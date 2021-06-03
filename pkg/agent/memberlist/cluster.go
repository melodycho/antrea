// Copyright 2021 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package memberlist

import (
	"fmt"
	"sync"
	"time"

	"github.com/golang/groupcache/consistenthash"
	"github.com/hashicorp/memberlist"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/util/k8s"
)

const defaultClusterHealthzAskInterval = 40 * time.Second

type ClusterInterface interface {
	Run(stopCh <-chan struct{})
	ShouldSelect(name string) bool
	AddEventHandler(handler clusterNodeEventHandler)
}

type clusterNodeEventHandler func(ip string, added bool)

type Cluster struct {
	bindPort                         int
	NodeConfig                       *config.NodeConfig
	nodeInformer                     coreinformers.NodeInformer
	memberList                       *memberlist.Memberlist
	memberRWLock                     sync.RWMutex
	existingMembers                  []string
	defaultClusterHealthzAskInterval time.Duration
	conHash                          *consistenthash.Map
	nodeEventsCh                     chan memberlist.NodeEvent
	ClusterNodeEventHandlers         []clusterNodeEventHandler
}

func NewCluster(clusterBindPort int, nodeInformer coreinformers.NodeInformer, nodeConfig *config.NodeConfig) (*Cluster, error) {
	// The Node join/leave events will be notified via it.
	nodeEventCh := make(chan memberlist.NodeEvent, 1024)
	s := &Cluster{
		bindPort:                         clusterBindPort,
		nodeInformer:                     nodeInformer,
		NodeConfig:                       nodeConfig,
		defaultClusterHealthzAskInterval: defaultClusterHealthzAskInterval,
		nodeEventsCh:                     nodeEventCh,
	}
	s.conHash = newNodeConsistentHashMap()

	bindPort := s.bindPort
	hostIP := s.NodeConfig.NodeIPAddr.IP

	nodeMember := fmt.Sprintf("%s:%d", hostIP.String(), bindPort)

	klog.V(2).Infof("Add new node: %s", nodeMember)

	conf := memberlist.DefaultLocalConfig()
	conf.Name = s.NodeConfig.Name

	conf.BindPort = bindPort
	conf.AdvertisePort = bindPort
	conf.Events = &memberlist.ChannelEventDelegate{Ch: nodeEventCh}

	klog.V(1).Infof("Memberlist cluster configs: %+v", conf)

	list, err := memberlist.Create(conf)
	if err != nil {
		return nil, fmt.Errorf("failed to create memberlist: %v", err.Error())
	}

	s.memberList = list
	s.existingMembers = []string{nodeMember}

	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    s.addNodeMemberHandler,
		UpdateFunc: nil,
		DeleteFunc: nil,
	})

	return s, nil
}

func newNodeConsistentHashMap() *consistenthash.Map {
	return consistenthash.New(3, nil)
}

func (gc *Cluster) convertListNodesToMemberlist() (clusterNodes []string) {
	nodes, err := gc.nodeInformer.Lister().List(labels.Everything())
	if err != nil {
		klog.Errorf("error when listing Nodes: %v", err)
		return
	}
	klog.V(3).Infof("List %d nodes", len(nodes))

	for _, node := range nodes {
		klog.V(4).Infof("Node %s: %#v", node.Name, node.Status.Addresses)
		nodeAddr, err := k8s.GetNodeAddr(node)
		if err != nil {
			klog.Errorf("Failed to obtain local IP address from K8s node: %w", err)
			continue
		}
		member := fmt.Sprintf("%s:%d", nodeAddr, gc.bindPort)
		clusterNodes = append(clusterNodes, member)
	}
	return
}

func (gc *Cluster) addNodeMemberHandler(obj interface{}) {
	node, ok := obj.(*corev1.Node)
	if !ok {
		klog.Errorf("Add node callback error, unexpected object type: %v", obj)
		return
	}
	gc.addMember(node)
}

func (gc *Cluster) memberNum() int {
	gc.memberRWLock.RLock()
	defer gc.memberRWLock.RUnlock()

	return len(gc.existingMembers)
}

func (gc *Cluster) addMember(node *corev1.Node) {
	gc.memberRWLock.Lock()
	defer gc.memberRWLock.Unlock()
	nodeAddr, err := k8s.GetNodeAddr(node)
	if err != nil {
		klog.Errorf("Failed to obtain local IP address from K8s node: %w", err)
		return
	}
	member := fmt.Sprintf("%s:%d", nodeAddr, gc.bindPort)
	gc.existingMembers = append(gc.existingMembers, member)
	gc.joinMembers(gc.existingMembers)
}

func (gc *Cluster) joinMembers(clusterNodes []string) {
	n, err := gc.memberList.Join(clusterNodes)
	if err != nil {
		klog.Errorf("Failed to join cluster: %v, cluster nodes: %#v", err, clusterNodes)
		return
	}
	klog.V(2).Infof("Join cluster: %v, cluster nodes: %+v", n, clusterNodes)
}

func (gc *Cluster) Run(stopCh <-chan struct{}) {
	newClusterMembers := gc.convertListNodesToMemberlist()
	expectNodeNum := len(newClusterMembers)

	actualMemberNum := gc.memberList.NumMembers()
	klog.V(3).Infof("Nodes num: %d, actual member num: %d", expectNodeNum, actualMemberNum)
	if actualMemberNum < expectNodeNum {
		gc.joinMembers(newClusterMembers)
	}

	gc.askClusterMemberHealthz()

	// Memberlist will maintain membership information in the background.
	timeTicker := time.NewTicker(gc.defaultClusterHealthzAskInterval)
	defer func() {
		timeTicker.Stop()
		close(gc.nodeEventsCh)
	}()
	for {
		select {
		case <-stopCh:
			return
		case nodeEvent := <-gc.nodeEventsCh:
			gc.updateNodeConsistenHash(&nodeEvent)
		case <-timeTicker.C:
			gc.askClusterMemberHealthz()
		}
	}
}

func (gc *Cluster) askClusterMemberHealthz() {
	for i, member := range gc.memberList.Members() {
		klog.V(0).Infof("Cluster member %d: %s, Address: %s, State: %#v",
			i, member.Name, member.Addr, member.State)
	}
}

func (gc *Cluster) updateNodeConsistenHash(nodeEvent *memberlist.NodeEvent) {
	gc.memberRWLock.Lock()
	defer gc.memberRWLock.Unlock()
	switch node, event := nodeEvent.Node, nodeEvent.Event; event {
	case memberlist.NodeJoin:
		klog.V(0).Infof("Node event: join node (%s)", node.String())
		gc.conHash.Add(node.Name)
		gc.notify(node.Name, true)
	case memberlist.NodeLeave:
		klog.V(0).Infof("Node event: leave node (%s)", node.String())
		gc.conHash = newNodeConsistentHashMap()
		gc.conHash.Add(gc.nodesList()...)
		gc.notify(node.Name, false)
	default:
		klog.V(0).Infof("Node event: update node (%s)", node.String())
	}
}

func (gc *Cluster) nodesList() []string {
	aliveMembers := gc.memberList.Members()
	nodes := make([]string, len(aliveMembers))
	for i, node := range aliveMembers {
		nodes[i] = node.Name
	}
	return nodes
}

func (gc *Cluster) ShouldSelect(name string) bool {
	myNode := gc.NodeConfig.Name
	hitted := hitNodeByConsistentHash(gc.conHash, name, myNode)
	klog.V(0).Infof("Assign egress (%s) owner node for local node (%s): %t", name, myNode, hitted)
	return hitted
}

func hitNodeByConsistentHash(conHash *consistenthash.Map, name, myNode string) bool {
	return conHash.Get(name) == myNode
}

func (gc *Cluster) notify(nodeName string, join bool) {
	for _, handler := range gc.ClusterNodeEventHandlers {
		handler(nodeName, join)
	}
}

func (gc *Cluster) AddEventHandler(handler clusterNodeEventHandler) {
	gc.ClusterNodeEventHandlers = append(gc.ClusterNodeEventHandlers, handler)
}
