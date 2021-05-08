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
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/memberlist"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
)

const defaultInterval = 30 * time.Second

type Server struct {
	bindPort        int
	nodeConfig      *config.NodeConfig
	nodeInformer    coreinformers.NodeInformer
	memberList      *memberlist.Memberlist
	memberRWLock    sync.RWMutex
	existingMembers *[]string
	defaultInterval time.Duration
}

func NewMemberlistServer(p int, nodeInformer coreinformers.NodeInformer, nodeConfig *config.NodeConfig) (*Server, error) {
	klog.Infof("Node config: %#v", nodeConfig)

	s := &Server{
		bindPort:        p,
		nodeInformer:    nodeInformer,
		nodeConfig:      nodeConfig,
		defaultInterval: defaultInterval,
	}

	hostname := s.nodeConfig.Name
	bindPort := s.bindPort
	hostIP := s.nodeConfig.NodeIPAddr.IP

	nodeMember := fmt.Sprintf("%s:%d", hostIP.String(), bindPort)

	klog.Infof("Add new node: %s", nodeMember)

	conf := memberlist.DefaultLocalConfig()
	conf.Name = hostname + "-" + strconv.Itoa(bindPort)

	conf.BindPort = bindPort
	conf.AdvertisePort = bindPort

	klog.Infof("Configs: %+v\n", conf)

	list, err := memberlist.Create(conf)
	if err != nil {
		return nil, fmt.Errorf("failed to create memberlist: %s", err.Error())
	}

	s.memberList = list
	s.existingMembers = &[]string{nodeMember}

	// Join an existing cluster by specifying at least one known member.
	s.joinMembers(*s.existingMembers)

	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    s.addNodeMemberHandler,
		UpdateFunc: nil,
		DeleteFunc: nil,
	})

	return s, nil
}

func (ms *Server) convertListNodesToMemberlist() []string {
	nodes, err := ms.nodeInformer.Lister().List(labels.Everything())
	if err != nil {
		klog.Errorf("error when listing Nodes: %v", err)
	}
	klog.Infof("List %d nodes", len(nodes))

	clusterNodes := make([]string, len(nodes))

	for i, node := range nodes {
		klog.Infof("Node %s: %#v", node.Name, node.Status.Addresses)
		address := node.Status.Addresses
		for _, add := range address {
			if add.Type == corev1.NodeInternalIP {
				member := fmt.Sprintf("%s:%d", add.Address, ms.bindPort)
				clusterNodes[i] = member
				klog.Infof("Cluster memberlist: %s", member)
			}
		}
	}
	return clusterNodes
}

func (ms *Server) addNodeMemberHandler(obj interface{}) {
	node, ok := obj.(*corev1.Node)
	if !ok {
		klog.Errorf("Add node callback error, unexpected object type: %v", obj)
		return
	}
	ms.addMember(node)
}

func (ms *Server) memberNum() int {
	ms.memberRWLock.RLock()
	defer ms.memberRWLock.RUnlock()

	num := len(*ms.existingMembers)
	return num
}

func (ms *Server) addMember(node *corev1.Node) {
	ms.memberRWLock.Lock()
	defer ms.memberRWLock.Unlock()
	var member string
	for _, add := range node.Status.Addresses {
		if add.Type == corev1.NodeInternalIP {
			member = fmt.Sprintf("%s:%d", add.Address, ms.bindPort)
		}
	}
	if member != "" {
		*ms.existingMembers = append(*ms.existingMembers, member)
		ms.joinMembers(*ms.existingMembers)
	}
}

func (ms *Server) joinMembers(clusterNodes []string) {
	n, err := ms.memberList.Join(clusterNodes)
	if err != nil {
		klog.Errorf("Failed to join cluster: %s, cluster nodes: %#v", err.Error(), clusterNodes)
	}
	klog.Infof("Join cluster: %v, cluster nodes: %+v", n, clusterNodes)
}

func (ms *Server) Run(stopCh <-chan struct{}) {
	newClusterMembers := ms.convertListNodesToMemberlist()
	expectNodeNum := len(newClusterMembers)
	klog.Infof("List %d nodes: %#v", expectNodeNum, newClusterMembers)

	actualMemberNum := ms.memberList.NumMembers()
	klog.Infof("Nodes num: %d, member num: %d", expectNodeNum, actualMemberNum)
	if actualMemberNum < expectNodeNum {
		ms.joinMembers(newClusterMembers)
	}

	// Ask for members of the cluster
	for i, member := range ms.memberList.Members() {
		klog.Infof("Member %d: %s, Address: %s, State: %#v", i, member.Name, member.Addr, member.State)
	}

	// Memberlist will maintain membership information in the background.
	// Delegates can be used for receiving events when members join or leave.
	timeTicker := time.NewTicker(ms.defaultInterval)
	for {
		select {
		case <-stopCh:
			return
		case <-timeTicker.C:
			for i, member := range ms.memberList.Members() {
				klog.Infof("Member %d: %s, Address: %s, State: %#v", i, member.Name, member.Addr, member.State)
			}
		}
	}
}
