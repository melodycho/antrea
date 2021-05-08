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
	"context"
	"net"
	"testing"
	"time"

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

func TestMemberlistServer_Run(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stopCh := make(chan struct{})
	defer close(stopCh)

	port := apis.AntreaAgentMemberlistPort + 1
	nodeConfig := &config.NodeConfig{Name: "test_memberlist_node",
		NodeIPAddr: &net.IPNet{IP: net.IPv4(127, 0, 0, 1),
			Mask: net.IPv4Mask(255, 255, 255, 255)}}

	clientset := fake.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactory(clientset, 0)

	nodeInformer := informerFactory.Core().V1().Nodes()

	node0 := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "test_node0"},
		Status: v1.NodeStatus{
			Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "fake_ip_node0"}}}}
	_, err := clientset.CoreV1().Nodes().Create(context.TODO(), node0, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("add node error: %s", err.Error())
	}

	s, err := NewMemberlistServer(port, nodeInformer, nodeConfig)
	if err != nil {
		t.Fatalf("new memberlist server error: %s", err.Error())
	}
	s.defaultInterval = testDefaultInterval

	// Make sure informers are running.
	informerFactory.Start(ctx.Done())

	cache.WaitForCacheSync(ctx.Done(), nodeInformer.Informer().HasSynced)

	go s.Run(stopCh)

	assert.Equal(t, 2, s.memberNum(), "expected node member num is 2")
	assert.Equal(t, 1, s.memberList.NumMembers(), "expected alive node num is 1")

	node1 := &v1.Node{Status: v1.NodeStatus{
		Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "fake_ip_node1"}}}}

	_, err = clientset.CoreV1().Nodes().Create(context.TODO(), node1, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("add node error: %s", err.Error())
	}

	time.Sleep(testDefaultInterval)

	assert.Equal(t, 3, s.memberNum(), "expected node member num is 3")
	assert.Equal(t, 1, s.memberList.NumMembers(), "expected alive node num is 1")
}
