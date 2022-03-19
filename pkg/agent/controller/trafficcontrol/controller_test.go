// Copyright 2022 Antrea Authors
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

package trafficcontrol

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/pkg/agent/interfacestore"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	ovsconfigtest "antrea.io/antrea/pkg/ovs/ovsconfig/testing"
	"antrea.io/antrea/pkg/util/k8s"
)

type fakeController struct {
	*Controller
	mockController      *gomock.Controller
	mockOFClient        *openflowtest.MockClient
	mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient
	crdClient           *fakeversioned.Clientset
	crdInformerFactory  crdinformers.SharedInformerFactory
	client              *fake.Clientset
	informerFactory     informers.SharedInformerFactory
	localPodInformer    cache.SharedIndexInformer
}

func newFakeController(t *testing.T, objects []runtime.Object, initObjects []runtime.Object) *fakeController {
	controller := gomock.NewController(t)

	mockOFClient := openflowtest.NewMockClient(controller)

	mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)

	client := fake.NewSimpleClientset(objects...)
	crdClient := fakeversioned.NewSimpleClientset(initObjects...)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
	informerFactory := informers.NewSharedInformerFactory(client, 0)
	tcInformer := crdInformerFactory.Crd().V1alpha2().TrafficControls()
	nsInformer := informerFactory.Core().V1().Namespaces()

	addPodInterface := func(ifaceStore interfacestore.InterfaceStore, podNamespace, podName string, ofPort int32) {
		containerName := k8s.NamespacedName(podNamespace, podName)
		ifaceStore.AddInterface(&interfacestore.InterfaceConfig{
			InterfaceName:            util.GenerateContainerInterfaceName(podName, podNamespace, containerName),
			ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: podName, PodNamespace: podNamespace, ContainerID: containerName},
			OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: ofPort},
		})
	}

	ifaceStore := interfacestore.NewInterfaceStore()
	addPodInterface(ifaceStore, "ns1", "pod1", 1)
	addPodInterface(ifaceStore, "ns2", "pod2", 2)

	ifaceStore.AddInterface(&interfacestore.InterfaceConfig{
		InterfaceName:            "test-device",
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "podName", PodNamespace: "podNamespace", ContainerID: "containerName"},
		OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 3},
		TunnelInterfaceConfig: &interfacestore.TunnelInterfaceConfig{
			Type:     "",
			NodeName: "",
			LocalIP:  nil,
			RemoteIP: nil,
			PSK:      "",
			Csum:     false,
		},
	})

	listOptions := func(options *metav1.ListOptions) {
		options.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", "fakeNode1").String()
	}
	localPodInformer := coreinformers.NewFilteredPodInformer(
		client,
		metav1.NamespaceAll,
		0,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		listOptions,
	)

	tcController := NewTrafficControlController(mockOFClient, ifaceStore, mockOVSBridgeClient, tcInformer, localPodInformer, nsInformer)
	return &fakeController{
		Controller:          tcController,
		mockController:      controller,
		mockOFClient:        mockOFClient,
		mockOVSBridgeClient: mockOVSBridgeClient,
		crdClient:           crdClient,
		crdInformerFactory:  crdInformerFactory,
		client:              client,
		informerFactory:     informerFactory,
		localPodInformer:    localPodInformer,
	}
}

func newPod(ns, name, nodeName string, labels map[string]string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
			Labels:    labels,
		},
		Spec: v1.PodSpec{
			NodeName: nodeName,
		},
	}

}

func TestSyncTrafficControl(t *testing.T) {
	defaultGENEVEdstPort := defaultGENEVETunnelDestinationPort
	testcases := []struct {
		name          string
		tc            *v1alpha2.TrafficControl
		localPods     []*v1.Pod
		expectedCalls func(mockOFClient *openflowtest.MockClient, mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient)
	}{
		{
			name: "create trafficControl",
			tc: &v1alpha2.TrafficControl{
				ObjectMeta: metav1.ObjectMeta{Name: "trafficControl1", UID: "tc-uid"},
				Spec: v1alpha2.TrafficControlSpec{
					AppliedTo: v1alpha2.AppliedTo{
						PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}},
					Direction:  v1alpha2.DirectionIngress,
					Action:     v1alpha2.ActionMirror,
					TargetPort: v1alpha2.TrafficControlPort{OVSInternal: &v1alpha2.OVSInternalPort{Name: "test-device"}},
				}},
			localPods: []*v1.Pod{
				newPod("ns1", "pod1", "fakeNode", map[string]string{"app": "foo"}),
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient) {
				mockOVSBridgeClient.EXPECT().GetOFPort("test-device", false).Return(int32(0), ovsconfig.NewTransactionError(fmt.Errorf("failed to get OVS port"), true)).Times(1)
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows("trafficControl1", []uint32{1}, uint32(0), v1alpha2.DirectionIngress, v1alpha2.ActionMirror)
				mockOVSBridgeClient.EXPECT().CreateInternalPort("test-device", int32(0),
					map[string]interface{}{interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaUnset})
				mockOVSBridgeClient.EXPECT().GetOFPort("test-device", false).Times(1)
			},
		},
		{
			name: "sync trafficControl pod selector",
			tc: &v1alpha2.TrafficControl{
				ObjectMeta: metav1.ObjectMeta{Name: "trafficControl1", UID: "tc-uid"},
				Spec: v1alpha2.TrafficControlSpec{
					AppliedTo: v1alpha2.AppliedTo{
						PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}},
					Direction:  v1alpha2.DirectionIngress,
					Action:     v1alpha2.ActionMirror,
					TargetPort: v1alpha2.TrafficControlPort{Device: &v1alpha2.NetworkDevice{Name: "test-device"}},
				}},
			localPods: []*v1.Pod{
				newPod("ns1", "pod1", "fakeNode", map[string]string{"app": "foo"}),
				newPod("ns2", "pod2", "fakeNode", map[string]string{"app": "foo1"}),
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows("trafficControl1", []uint32{1}, uint32(3), v1alpha2.DirectionIngress, v1alpha2.ActionMirror)
			},
		},
		{
			name: "sync trafficControl with nil AppliedTo",
			tc: &v1alpha2.TrafficControl{
				ObjectMeta: metav1.ObjectMeta{Name: "trafficControl1", UID: "tc-uid"},
				Spec: v1alpha2.TrafficControlSpec{
					Direction:  v1alpha2.DirectionIngress,
					Action:     v1alpha2.ActionRedirect,
					ReturnPort: &v1alpha2.TrafficControlPort{Device: &v1alpha2.NetworkDevice{Name: "test-device"}},
					TargetPort: v1alpha2.TrafficControlPort{Device: &v1alpha2.NetworkDevice{Name: "test-device"}},
				}},
			localPods: []*v1.Pod{
				newPod("ns1", "pod1", "fakeNode", map[string]string{"app": "foo"}),
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows("trafficControl1", []uint32{1}, uint32(3), v1alpha2.DirectionIngress, v1alpha2.ActionRedirect)
				mockOFClient.EXPECT().InstallTrafficControlReturnPortFlow(uint32(3))
			},
		},
		{
			name: "sync trafficControl with nil pod selector",
			tc: &v1alpha2.TrafficControl{
				ObjectMeta: metav1.ObjectMeta{Name: "trafficControl1", UID: "tc-uid"},
				Spec: v1alpha2.TrafficControlSpec{
					AppliedTo:  v1alpha2.AppliedTo{},
					Direction:  v1alpha2.DirectionIngress,
					Action:     v1alpha2.ActionRedirect,
					ReturnPort: &v1alpha2.TrafficControlPort{Device: &v1alpha2.NetworkDevice{Name: "test-device"}},
					TargetPort: v1alpha2.TrafficControlPort{Device: &v1alpha2.NetworkDevice{Name: "test-device"}},
				}},
			localPods: []*v1.Pod{
				newPod("ns1", "pod1", "fakeNode", map[string]string{"app": "foo"}),
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows("trafficControl1", []uint32{1}, uint32(3), v1alpha2.DirectionIngress, v1alpha2.ActionRedirect)
				mockOFClient.EXPECT().InstallTrafficControlReturnPortFlow(uint32(3))
			},
		},
		{
			name: "sync trafficControl with internal OVSPort type",
			tc: &v1alpha2.TrafficControl{
				ObjectMeta: metav1.ObjectMeta{Name: "trafficControl1", UID: "tc-uid"},
				Spec: v1alpha2.TrafficControlSpec{
					AppliedTo:  v1alpha2.AppliedTo{},
					Direction:  v1alpha2.DirectionIngress,
					Action:     v1alpha2.ActionMirror,
					TargetPort: v1alpha2.TrafficControlPort{OVSInternal: &v1alpha2.OVSInternalPort{Name: "fake-internal-device"}},
				}},
			localPods: []*v1.Pod{
				newPod("ns1", "pod1", "fakeNode", map[string]string{"app": "foo"}),
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows("trafficControl1", []uint32{1}, uint32(0), v1alpha2.DirectionIngress, v1alpha2.ActionMirror)
				mockOVSBridgeClient.EXPECT().GetOFPort("fake-internal-device", false).Return(int32(0), ovsconfig.NewTransactionError(fmt.Errorf("failed to get OVS port"), true)).Times(1)
				mockOVSBridgeClient.EXPECT().CreateInternalPort("fake-internal-device", int32(0),
					map[string]interface{}{interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaUnset})
				mockOVSBridgeClient.EXPECT().GetOFPort("fake-internal-device", false).Times(1)
			},
		},
		{
			name: "sync trafficControl with device OVSPort type",
			tc: &v1alpha2.TrafficControl{
				ObjectMeta: metav1.ObjectMeta{Name: "trafficControl1", UID: "tc-uid"},
				Spec: v1alpha2.TrafficControlSpec{
					AppliedTo:  v1alpha2.AppliedTo{},
					Direction:  v1alpha2.DirectionIngress,
					Action:     v1alpha2.ActionMirror,
					TargetPort: v1alpha2.TrafficControlPort{Device: &v1alpha2.NetworkDevice{Name: "fake-device"}},
				}},
			localPods: []*v1.Pod{newPod("ns1", "pod1", "fakeNode", map[string]string{"app": "foo"})},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows("trafficControl1", []uint32{1}, uint32(0), v1alpha2.DirectionIngress, v1alpha2.ActionMirror)
				mockOVSBridgeClient.EXPECT().CreatePort("fake-device", "fake-device",
					map[string]interface{}{interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaUnset})
				mockOVSBridgeClient.EXPECT().GetOFPort("fake-device", false)
			},
		},
		{
			name: "sync trafficControl with GRE OVSPort type",
			tc: &v1alpha2.TrafficControl{
				ObjectMeta: metav1.ObjectMeta{Name: "trafficControl1", UID: "tc-uid"},
				Spec: v1alpha2.TrafficControlSpec{
					AppliedTo: v1alpha2.AppliedTo{},
					Direction: v1alpha2.DirectionIngress,
					Action:    v1alpha2.ActionMirror,
					TargetPort: v1alpha2.TrafficControlPort{GRE: &v1alpha2.GRETunnel{
						RemoteIP: "1.1.1.1",
						Key:      nil,
					}},
				}},
			localPods: []*v1.Pod{newPod("ns1", "pod1", "fakeNode", map[string]string{"app": "foo"})},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows("trafficControl1", []uint32{1}, uint32(0), v1alpha2.DirectionIngress, v1alpha2.ActionMirror)
				mockOVSBridgeClient.EXPECT().CreateTunnelPortExt("gre-27a193", ovsconfig.TunnelType(ovsconfig.GRETunnel), int32(0), false, "", "1.1.1.1", "",
					map[string]interface{}{interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaTunnel})
				mockOVSBridgeClient.EXPECT().GetOFPort("gre-27a193", false).Times(1)
			},
		},
		{
			name: "sync trafficControl with VXLAN OVSPort type",
			tc: &v1alpha2.TrafficControl{
				ObjectMeta: metav1.ObjectMeta{Name: "trafficControl1", UID: "tc-uid"},
				Spec: v1alpha2.TrafficControlSpec{
					AppliedTo: v1alpha2.AppliedTo{},
					Direction: v1alpha2.DirectionIngress,
					Action:    v1alpha2.ActionMirror,
					TargetPort: v1alpha2.TrafficControlPort{VXLAN: &v1alpha2.UDPTunnel{
						RemoteIP:        "1.1.1.1",
						VNI:             nil,
						DestinationPort: nil,
					}},
				}},
			localPods: []*v1.Pod{newPod("ns1", "pod1", "fakeNode", map[string]string{"app": "foo"})},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows("trafficControl1", []uint32{1}, uint32(0), v1alpha2.DirectionIngress, v1alpha2.ActionMirror)
				mockOVSBridgeClient.EXPECT().CreateTunnelPortExt("vxlan-0ec8dd", ovsconfig.TunnelType(ovsconfig.VXLANTunnel), int32(0), false, "", "1.1.1.1", "",
					map[string]interface{}{interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaTunnel, "dst_port": strconv.Itoa(int(defaultVXLANTunnelDestinationPort))})
				mockOVSBridgeClient.EXPECT().GetOFPort("vxlan-0ec8dd", false).Times(1)
			},
		},
		{
			name: "sync trafficControl with GENEVE OVSPort type",
			tc: &v1alpha2.TrafficControl{
				ObjectMeta: metav1.ObjectMeta{Name: "trafficControl-GENEVE", UID: "tc-uid"},
				Spec: v1alpha2.TrafficControlSpec{
					AppliedTo: v1alpha2.AppliedTo{},
					Direction: v1alpha2.DirectionIngress,
					Action:    v1alpha2.ActionMirror,
					TargetPort: v1alpha2.TrafficControlPort{GENEVE: &v1alpha2.UDPTunnel{
						RemoteIP:        "1.1.1.1",
						VNI:             nil,
						DestinationPort: &defaultGENEVEdstPort,
					}},
				}},
			localPods: []*v1.Pod{newPod("ns1", "pod1", "fakeNode", map[string]string{"app": "foo"})},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows("trafficControl-GENEVE", []uint32{1}, uint32(0), v1alpha2.DirectionIngress, v1alpha2.ActionMirror)
				mockOVSBridgeClient.EXPECT().CreateTunnelPortExt("geneve-ecd278", ovsconfig.TunnelType(ovsconfig.GeneveTunnel), int32(0), false, "", "1.1.1.1", "",
					map[string]interface{}{interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaTunnel, "dst_port": strconv.Itoa(int(defaultGENEVEdstPort))})
				mockOVSBridgeClient.EXPECT().GetOFPort("geneve-ecd278", false).Times(1)
			},
		},
		{
			name: "sync trafficControl with GENEVE OVSPort type, compare default and nil dstPort config",
			tc: &v1alpha2.TrafficControl{
				ObjectMeta: metav1.ObjectMeta{Name: "trafficControl-GENEVE", UID: "tc-uid"},
				Spec: v1alpha2.TrafficControlSpec{
					AppliedTo: v1alpha2.AppliedTo{},
					Direction: v1alpha2.DirectionIngress,
					Action:    v1alpha2.ActionMirror,
					TargetPort: v1alpha2.TrafficControlPort{GENEVE: &v1alpha2.UDPTunnel{
						RemoteIP: "1.1.1.1",
						VNI:      nil,
					}},
				}},
			localPods: []*v1.Pod{newPod("ns1", "pod1", "fakeNode", map[string]string{"app": "foo"})},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows("trafficControl-GENEVE", []uint32{1}, uint32(0), v1alpha2.DirectionIngress, v1alpha2.ActionMirror)
				mockOVSBridgeClient.EXPECT().CreateTunnelPortExt("geneve-ecd278", ovsconfig.TunnelType(ovsconfig.GeneveTunnel), int32(0), false, "", "1.1.1.1", "",
					map[string]interface{}{interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaTunnel, "dst_port": strconv.Itoa(int(defaultGENEVEdstPort))})
				mockOVSBridgeClient.EXPECT().GetOFPort("geneve-ecd278", false).Times(1)
			},
		},
		{
			name: "sync trafficControl with ERSPAN OVSPort type",
			tc: &v1alpha2.TrafficControl{
				ObjectMeta: metav1.ObjectMeta{Name: "trafficControl1", UID: "tc-uid"},
				Spec: v1alpha2.TrafficControlSpec{
					AppliedTo: v1alpha2.AppliedTo{},
					Direction: v1alpha2.DirectionIngress,
					Action:    v1alpha2.ActionMirror,
					TargetPort: v1alpha2.TrafficControlPort{
						ERSPAN: &v1alpha2.ERSPANTunnel{
							Version:    1,
							Dir:        nil,
							HardwareID: nil,
						}},
				}},
			localPods: []*v1.Pod{newPod("ns1", "pod1", "fakeNode", map[string]string{"app": "foo"})},
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows("trafficControl1", []uint32{1}, uint32(0), v1alpha2.DirectionIngress, v1alpha2.ActionMirror)
				mockOVSBridgeClient.EXPECT().CreateTunnelPortExt("erspan-da39a3", ovsconfig.TunnelType(ovsconfig.ERSpanTunnel), int32(0), false, "", "", "",
					map[string]interface{}{
						interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaUnset,
						"erspan_ver":                          strconv.Itoa(1),
						"key":                                 strconv.Itoa(1),
					})
				mockOVSBridgeClient.EXPECT().GetOFPort("erspan-da39a3", false).Times(1)
			},
		},
	}
	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			var objects []runtime.Object
			for _, pod := range tt.localPods {
				objects = append(objects, pod)
			}
			c := newFakeController(t, objects, []runtime.Object{tt.tc})
			defer c.mockController.Finish()

			stopCh := make(chan struct{})
			defer close(stopCh)

			go c.localPodInformer.Run(stopCh)

			c.crdInformerFactory.Start(stopCh)
			c.crdInformerFactory.WaitForCacheSync(stopCh)

			c.informerFactory.Start(stopCh)
			c.informerFactory.WaitForCacheSync(stopCh)

			tt.expectedCalls(c.mockOFClient, c.mockOVSBridgeClient)

			assert.NoError(t, c.syncTrafficControl(tt.tc.Name))
		})
	}
}

func TestTrafficControlControllerPodUpdate(t *testing.T) {
	defaultContext := context.TODO()
	tc := v1alpha2.TrafficControl{
		ObjectMeta: metav1.ObjectMeta{Name: "tc-mirror", UID: "tc-uid"},
		Spec: v1alpha2.TrafficControlSpec{
			AppliedTo: v1alpha2.AppliedTo{
				PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}},
			Direction:  v1alpha2.DirectionIngress,
			Action:     v1alpha2.ActionMirror,
			TargetPort: v1alpha2.TrafficControlPort{Device: &v1alpha2.NetworkDevice{Name: "test-device"}},
		}}
	c := newFakeController(t, nil, nil)
	defer c.mockController.Finish()

	stopCh := make(chan struct{})
	defer close(stopCh)

	go c.localPodInformer.Run(stopCh)

	c.crdInformerFactory.Start(stopCh)
	c.crdInformerFactory.WaitForCacheSync(stopCh)

	c.informerFactory.Start(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)

	go c.Controller.Run(stopCh)

	_, err := c.crdClient.CrdV1alpha2().TrafficControls().Create(defaultContext, &tc, metav1.CreateOptions{})
	require.NoError(t, err)

	pod1 := newPod("ns1", "pod1", "fakeNode", map[string]string{"app": "foo"})
	_, err = c.client.CoreV1().Pods("ns1").Create(defaultContext, pod1, metav1.CreateOptions{})
	require.NoError(t, err)

	c.mockOFClient.EXPECT().InstallTrafficControlMarkFlows("tc-mirror", []uint32{1}, uint32(3), v1alpha2.DirectionIngress, v1alpha2.ActionMirror)

	assert.NoError(t, wait.Poll(100*time.Millisecond, time.Second, func() (done bool, err error) {
		return c.Controller.tcStates != nil, nil
	}), "wait TCState update")
	state, ok := c.getTcState("tc-mirror")
	assert.Equal(t, true, ok)
	assert.Equal(t, tcState{
		ofPorts:    sets.Int32{},
		pods:       sets.String{"ns1/pod1": sets.Empty{}},
		targetPort: uint32(3),
		returnPort: 0,
		appliedTo:  tc.Spec.AppliedTo,
	}, *state)
}
