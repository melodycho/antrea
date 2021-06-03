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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"

	"bou.ke/monkey"
	"github.com/golang/groupcache/consistenthash"
	"github.com/hashicorp/memberlist"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/apis"
)

const testDefaultInterval = 1 * time.Second

func hitNode(nodes []string, name, myNode string) bool {
	if len(nodes) == 0 {
		return false
	}
	minNode := sha256.Sum256([]byte(nodes[0] + "#" + name))
	hitNode := nodes[0]
	for i := 1; i < len(nodes); i++ {
		hi := sha256.Sum256([]byte(nodes[i] + "#" + name))
		if bytes.Compare(hi[:], minNode[:]) < 0 {
			minNode = hi
			hitNode = nodes[i]
		}
	}
	return hitNode == myNode
}

func TestMemberlistServer_Run(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stopCh := make(chan struct{})
	defer close(stopCh)

	port := apis.AntreaAgentClusterPort + 1
	nodeName := "test_memberlist_node"
	nodeConfig := &config.NodeConfig{
		Name: nodeName,
		NodeIPAddr: &net.IPNet{
			IP:   net.IPv4(127, 0, 0, 1),
			Mask: net.IPv4Mask(255, 255, 255, 255),
		},
	}

	clientset := fake.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactory(clientset, 0)

	nodeInformer := informerFactory.Core().V1().Nodes()

	node0 := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "test_node0"},
		Status: v1.NodeStatus{
			Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "192.169.0.11"}}}}
	_, err := clientset.CoreV1().Nodes().Create(context.TODO(), node0, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Add node error: %v", err)
	}

	s, err := NewCluster(port, nodeInformer, nodeConfig)
	if err != nil {
		t.Fatalf("New memberlist server error: %v", err)
	}
	s.defaultClusterHealthzAskInterval = testDefaultInterval

	// Make sure informers are running.
	informerFactory.Start(ctx.Done())

	cache.WaitForCacheSync(ctx.Done(), nodeInformer.Informer().HasSynced)

	s.AddEventHandler(func(ip string, added bool) {
		t.Logf("notified node %s added (%t) node event handler", nodeName, added)
	})

	go s.Run(stopCh)

	assert.Equal(t, 2, s.memberNum(), "expected node member num is 2")
	assert.Equal(t, 1, s.memberList.NumMembers(), "expected alive node num is 1")

	node1 := &v1.Node{Status: v1.NodeStatus{
		Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "192.169.0.12"}}}}

	_, err = clientset.CoreV1().Nodes().Create(context.TODO(), node1, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Add node error: %v", err)
	}

	time.Sleep(testDefaultInterval)

	assert.Equal(t, 3, s.memberNum(), "expected node member num is 3")
	assert.Equal(t, 1, s.memberList.NumMembers(), "expected alive node num is 1")

	s.nodeEventsCh <- memberlist.NodeEvent{
		Node:  &memberlist.Node{Name: "testleaveNodeName"},
		Event: memberlist.NodeLeave,
	}

	s.nodeEventsCh <- memberlist.NodeEvent{
		Node:  &memberlist.Node{Name: "testleaveNodeName", State: 0},
		Event: memberlist.NodeUpdate,
	}

	time.Sleep(100 * time.Millisecond)

	assert.Equal(t, 3, s.memberNum(), "expected node member num is 3")
	assert.Equal(t, 1, s.memberList.NumMembers(), "expected alive node num is 1")
}

func TestCluster_ShouldSelectNodeFailedOrAddedBySortHash(t *testing.T) {
	const egressNum = 100
	expectEgressSeqSum := func(n int) int {
		count := 0
		for i := 0; i < n; i++ {
			count += i
		}
		return count
	}(egressNum)

	genNodes := func(n int) []string {
		nodes := make([]string, n)
		for i := 0; i < n; i++ {
			nodes[i] = fmt.Sprintf("node-%d", i)
		}
		return nodes
	}

	nodes := genNodes(12)
	testCases := []struct {
		name  string
		nodes []string
	}{
		{
			fmt.Sprintf("assign owner node for %d egress", egressNum),
			nodes[:10],
		},
		{
			// failover, when node failed, egress should move to available node
			"a node fail then egress should move",
			nodes[1:10],
		},
		{
			// egress should move when node added in cluster? how to move?
			"add new node then egress should move",
			nodes[:11],
		},
		{
			fmt.Sprintf("recover to %d nodes", 10),
			nodes[:10],
		},
	}
	for _, testC := range testCases {
		t.Run(testC.name, func(t *testing.T) {
			nodes := testC.nodes
			nodeEgress := make(map[string][]string, len(nodes))
			hitCount := 0
			seqSum := 0
			for i := 0; i < egressNum; i++ {
				egressName := fmt.Sprintf("%d", i)
				for j := range nodes {
					myNode := nodes[j]
					if hitNode(nodes, egressName, myNode) {
						nodeEgress[myNode] = append(nodeEgress[myNode], egressName)
						hitCount++
						seqSum += i
					}
				}
			}
			assert.Equal(t, expectEgressSeqSum, seqSum, "egress seq")
			for _, node := range nodes {
				t.Logf("Node (%s) egress: %#v", node, nodeEgress[node])
			}
			assert.Equal(t, egressNum, hitCount, "hitNode egress total num should be 30")

		})
	}
}

func TestCluster_ShouldSelectNodeFailedOrAddedByConsistentHash(t *testing.T) {
	const egressNum = 100
	expectEgressSeqSum := func(n int) int {
		count := 0
		for i := 0; i < n; i++ {
			count += i
		}
		return count
	}(egressNum)

	genNodes := func(n int) []string {
		nodes := make([]string, n)
		for i := 0; i < n; i++ {
			nodes[i] = fmt.Sprintf("node-%d", i)
		}
		return nodes
	}

	nodes := genNodes(12)
	testCases := []struct {
		name    string
		nodes   []string
		conHash *consistenthash.Map
	}{
		{
			fmt.Sprintf("assign owner node for %d egress", egressNum),
			nodes[:10],
			consistenthash.New(5, nil),
		},
		{
			// failover, when node failed, egress should move to available node
			"a node fail then egress should move",
			nodes[1:10],
			consistenthash.New(5, nil),
		},
		{
			// egress should move when node added in cluster? how to move?
			"add new node then egress should move",
			nodes[:11],
			consistenthash.New(5, nil),
		},
		{
			fmt.Sprintf("recover to %d nodes", 10),
			nodes[:10],
			consistenthash.New(5, nil),
		},
	}
	for _, testC := range testCases {
		t.Run(testC.name, func(t *testing.T) {
			nodes := testC.nodes
			testC.conHash.Add(nodes...)
			nodeEgress := make(map[string][]string, len(nodes))
			hitCount := 0
			seqSum := 0
			for i := 0; i < egressNum; i++ {
				egressName := fmt.Sprintf("%d", i)
				for j := range nodes {
					myNode := nodes[j]
					if hitNodeByConsistentHash(testC.conHash, egressName, myNode) {
						nodeEgress[myNode] = append(nodeEgress[myNode], egressName)
						hitCount++
						seqSum += i
					}
				}
			}
			assert.Equal(t, expectEgressSeqSum, seqSum, "egress seq")
			for _, node := range nodes {
				t.Logf("Node (%s) egress: %#v", node, nodeEgress[node])
			}
			assert.Equal(t, egressNum, hitCount, "hitNode egress total num should be 30")
		})
	}
}

func TestCluster_ShouldSelectByConstentHash(t *testing.T) {
	nodes := []string{"node1", "node2", "node3"}
	conHash := consistenthash.New(1, nil)

	conHash.Add(nodes...)

	checkNum := func(count int, myNode string) int {
		totalNum := 0
		for i := 0; i < count; i++ {
			egressName := fmt.Sprintf("egress-%d", i)
			if hitNodeByConsistentHash(conHash, egressName, myNode) {
				totalNum++
			}
		}
		return totalNum
	}

	checkSum := func(egressNum int) int {
		count := 0
		for _, node := range nodes {
			num := checkNum(egressNum, node)
			count += num
		}
		return count
	}

	testCases := []struct {
		name      string
		egressNum int
	}{
		{
			name:      "select node from alive nodes",
			egressNum: 3,
		},
		{
			name:      "select node from alive nodes",
			egressNum: 100,
		},
		{
			name:      "select node from alive nodes",
			egressNum: 100,
		},
		{
			name:      "select node from alive nodes",
			egressNum: 1000,
		},
		{
			name:      "select node from alive nodes",
			egressNum: 10000,
		},
	}
	for _, tCase := range testCases {
		t.Run(tCase.name, func(t *testing.T) {
			assert.Equal(t, tCase.egressNum, checkSum(tCase.egressNum))
		})
	}
}

//BenchmarkCluster_ShouldSelect
//BenchmarkCluster_ShouldSelect/select_node_from_1000_alive_nodes
//BenchmarkCluster_ShouldSelect/select_node_from_1000_alive_nodes-16         	    4860	    244613 ns/op
//BenchmarkCluster_ShouldSelect/select_node_from_100_alive_nodes
//BenchmarkCluster_ShouldSelect/select_node_from_100_alive_nodes-16          	   52707	     22412 ns/op
//BenchmarkCluster_ShouldSelect/select_node_from_10_alive_nodes
//BenchmarkCluster_ShouldSelect/select_node_from_10_alive_nodes-16           	  538476	      2273 ns/op
//PASS
//BenchmarkCluster_ShouldSelectHitNodeByConsistentHash
//BenchmarkCluster_ShouldSelect/select_node_from_1000_alive_nodes
//BenchmarkCluster_ShouldSelect/select_node_from_1000_alive_nodes-16         	12263878	        95.5 ns/op
//BenchmarkCluster_ShouldSelect/select_node_from_100_alive_nodes
//BenchmarkCluster_ShouldSelect/select_node_from_100_alive_nodes-16          	13036746	       103 ns/op
//BenchmarkCluster_ShouldSelect/select_node_from_10_alive_nodes
//BenchmarkCluster_ShouldSelect/select_node_from_10_alive_nodes-16           	14923483	        77.5 ns/op
//PASS
func BenchmarkCluster_ShouldSelect(b *testing.B) {
	genNodes := func(n int) []string {
		nodes := make([]string, n)
		for i := 0; i < n; i++ {
			nodes[i] = fmt.Sprintf("node-%d", i)
		}
		return nodes
	}

	benchmarkCases := []struct {
		name       string
		nodes      []string
		egressName string
		myNode     string
	}{
		{
			name:       "select node from 10000 alive nodes",
			nodes:      genNodes(10000),
			egressName: "egress-10",
			myNode:     "node-10",
		},
		{
			name:       "select node from 1000 alive nodes",
			nodes:      genNodes(1024),
			egressName: "egress-10",
			myNode:     "node-10",
		},
		{
			name:       "select node from 100 alive nodes",
			nodes:      genNodes(128),
			egressName: "egress-10",
			myNode:     "node-10",
		},
		{
			name:       "select node from 10 alive nodes",
			nodes:      genNodes(8),
			egressName: "egress-10",
			myNode:     "node-10",
		},
	}

	for i := range benchmarkCases {
		bc := benchmarkCases[i]
		b.Run(fmt.Sprintf("%s-hitNodeByConsistentHash", bc.name), func(b *testing.B) {
			b.ResetTimer()
			conHash := consistenthash.New(1, nil)
			conHash.Add(bc.nodes...)
			for i := 0; i < b.N; i++ {
				hitNodeByConsistentHash(conHash, bc.egressName, bc.myNode)
			}
		})
		b.Run(fmt.Sprintf("%s-hitNodeBySortHash", bc.name), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				hitNode(bc.nodes, bc.egressName, bc.myNode)
			}
		})
	}
}

func genRandomStr(num int) string {
	buf := make([]byte, num)
	_, err := rand.Read(buf)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%016x", buf)
}

func TestCluster_ShouldSelect(t *testing.T) {
	nodes := []string{"node1", "node2", "node3"}

	genLocalNodeCluster := func(nodeNme string) *Cluster {
		cluster := &Cluster{
			memberList: &memberlist.Memberlist{},
			NodeConfig: &config.NodeConfig{
				Name: nodeNme,
			},
			conHash: consistenthash.New(1, nil),
		}
		return cluster
	}

	node1Cluster := genLocalNodeCluster("node1")

	monkey.PatchInstanceMethod(reflect.TypeOf(node1Cluster.memberList), "Members", func(_ *memberlist.Memberlist) []*memberlist.Node {
		memberNodes := make([]*memberlist.Node, len(nodes))
		for i := range nodes {
			memberNode := memberlist.Node{}
			memberNode.Name = nodes[i]
			memberNodes[i] = &memberNode
		}

		return memberNodes
	})
	defer monkey.UnpatchAll()

	hitCount := 0
	for i := 0; i < 4; i++ {
		egressName := fmt.Sprintf("%s-%d", genRandomStr(10), i)
		if node1Cluster.ShouldSelect(egressName) {
			hitCount++
		}
	}
}
