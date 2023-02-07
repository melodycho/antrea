// Copyright 2023 Antrea Authors
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

package app

import (
	"antrea.io/antrea/pkg/agent"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/controller/networkpolicy"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/memberlist"
	memberlisttest "antrea.io/antrea/pkg/agent/memberlist/testing"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/proxy/types"
	"antrea.io/antrea/pkg/agent/route"
	testing2 "antrea.io/antrea/pkg/agent/testing"
	"antrea.io/antrea/pkg/apis"
	"antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha2"
	"antrea.io/antrea/pkg/ovs/ovsctl"
	"antrea.io/antrea/pkg/util/channel"
	"antrea.io/antrea/pkg/util/env"
	"context"
	"github.com/golang/mock/gomock"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"net"
	"os"
	"reflect"
	"runtime"
	"testing"
	"time"

	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/ovsdb"
	apiextensionclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	fakeapiextensionclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"
	clientset "k8s.io/client-go/kubernetes"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	componentbaseconfig "k8s.io/component-base/config"
	aggregatorclientset "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	fakeaggregatorclientset "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/fake"

	"antrea.io/antrea/cmd/antrea-agent/app/options"
	mcclientset "antrea.io/antrea/multicluster/pkg/client/clientset/versioned"
	mcfake "antrea.io/antrea/multicluster/pkg/client/clientset/versioned/fake"
	crdclientset "antrea.io/antrea/pkg/client/clientset/versioned"
	crdfake "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/signals"
)

func TestRunAgentController(t *testing.T) {
	goExec = func(function func(stopCh <-chan struct{}), stopCh <-chan struct{}) {
		pc := reflect.ValueOf(function).Pointer()
		funcName := runtime.FuncForPC(pc).Name()
		t.Logf("fake function %s running", funcName)
	}
	apiServerRun = func(function func(stopCh <-chan struct{}) error, stopCh <-chan struct{}) {
		t.Log("fake APIServer running")
	}
	goExecWithCtx = func(function func(ctx context.Context), ctx context.Context) {
		t.Log("fake APIServer running")
	}
	createK8sClient = func(config componentbaseconfig.ClientConnectionConfiguration, kubeAPIServerOverride string) (
		clientset.Interface, aggregatorclientset.Interface, crdclientset.Interface, apiextensionclientset.Interface, mcclientset.Interface, error) {
		aggregatorClientset := fakeaggregatorclientset.NewSimpleClientset()
		apiExtensionClient := fakeapiextensionclientset.NewSimpleClientset()
		return fakeclientset.NewSimpleClientset(), aggregatorClientset, crdfake.NewSimpleClientset(), apiExtensionClient, mcfake.NewSimpleClientset(), nil
	}

	ctl := gomock.NewController(t)
	defer ctl.Finish()
	mockAgentInit := testing2.NewMockAgentInitialierI(ctl)
	mockAgentInit.EXPECT().Initialize().Return(nil)

	podCIDRStr := "172.16.10.0/24"
	_, podCIDR, _ := net.ParseCIDR(podCIDRStr)

	fakeGatewayIPv4, _, _ := net.ParseCIDR("10.10.0.1/24")
	fakeGatewayIPv6, _, _ := net.ParseCIDR("fec0:10:10::1/80")
	fakeGatewayMAC, _ := net.ParseMAC("0a:00:00:00:00:01")
	fakeGatewayConfig := &config.GatewayConfig{
		IPv4:   fakeGatewayIPv4,
		IPv6:   fakeGatewayIPv6,
		MAC:    fakeGatewayMAC,
		OFPort: uint32(2),
	}

	_, nodeIPNet, _ := net.ParseCIDR("192.168.10.10/24")
	nodeConfig := &config.NodeConfig{
		Name:                  "node-test",
		Type:                  config.K8sNode,
		OVSBridge:             "br-int",
		PodIPv4CIDR:           podCIDR,
		NodeMTU:               1450,
		GatewayConfig:         fakeGatewayConfig,
		TunnelOFPort:          uint32(1),
		NodeTransportIPv4Addr: nodeIPNet,
		NodeIPv4Addr:          nodeIPNet,
	}
	mockAgentInit.EXPECT().GetNodeConfig().Return(nodeConfig)

	mockAgentInit.EXPECT().GetWireGuardClient().Return(nil)
	mockAgentInit.EXPECT().FlowRestoreComplete().Return(nil)
	// mockAgentInit.EXPECT().

	newAgentInitializerFunc = func(k8sClient clientset.Interface, crdClient crdclientset.Interface, ovsBridgeClient ovsconfig.OVSBridgeClient, ovsCtlClient ovsctl.OVSCtlClient, ofClient openflow.Client, routeClient route.Interface, ifaceStore interfacestore.InterfaceStore, ovsBridge string, hostGateway string, mtu int, networkConfig *config.NetworkConfig, wireGuardConfig *config.WireGuardConfig, egressConfig *config.EgressConfig, serviceConfig *config.ServiceConfig, networkReadyCh chan<- struct{}, stopCh <-chan struct{}, nodeType config.NodeType, externalNodeNamespace string, enableProxy bool, proxyAll bool, connectUplinkToBridge bool, enableL7NetworkPolicy bool) agent.AgentInitialierI {
		return mockAgentInit
	}

	newNetworkPolicyController = func(antreaClientGetter agent.AntreaClientProvider, ofClient openflow.Client, ifaceStore interfacestore.InterfaceStore, nodeName string, podUpdateSubscriber channel.Subscriber, externalEntityUpdateSubscriber channel.Subscriber, groupCounters []types.GroupCounter, groupIDUpdates <-chan string, antreaPolicyEnabled bool, l7NetworkPolicyEnabled bool, antreaProxyEnabled bool, statusManagerEnabled bool, multicastEnabled bool, loggingEnabled bool, asyncRuleDeleteInterval time.Duration, dnsServerOverride string, nodeType config.NodeType, v4Enabled bool, v6Enabled bool, gwPort, tunPort uint32) (*networkpolicy.Controller, error) {
		// clientset := &fakeclientset.Clientset{}
		// podUpdateChannel := channel.NewSubscribableChannel("PodUpdate", 100)
		// ch := make(chan string, 100)
		// groupIDAllocator := openflow.NewGroupAllocator(false)
		// groupCounters := []proxytypes.GroupCounter{proxytypes.NewGroupCounter(groupIDAllocator, ch2)}
		// controller, _ := networkpolicy.NewNetworkPolicyController(nil, nil, nil, "node1", podUpdateChannel, nil, nil, ch, true, true, true, true, false, true, 1, "8.8.8.8:53", config.K8sNode, true, false, config.HostGatewayOFPort, config.DefaultTunOFPort)
		return nil, nil
	}

	mockMemberlist := memberlisttest.NewMockMemberlist(ctl)
	// clientset := fakeclientset.NewSimpleClientset(objs...)
	// informerFactory := informers.NewSharedInformerFactory(clientset, 0)

	// nodeInformer := informerFactory.Core().V1().Nodes()
	crdClient := fakeversioned.NewSimpleClientset()
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
	ipPoolInformer := crdInformerFactory.Crd().V1alpha2().ExternalIPPools()

	newMemberlistCluster = func(nodeIP net.IP, clusterBindPort int, nodeName string, nodeInformer coreinformers.NodeInformer, externalIPPoolInformer v1alpha2.ExternalIPPoolInformer, ml memberlist.Memberlist) (*memberlist.Cluster, error) {
		cluster, _ := memberlist.NewCluster(nodeConfig.NodeIPv4Addr.IP, apis.AntreaAgentClusterMembershipPort, nodeConfig.Name, nodeInformer, ipPoolInformer, mockMemberlist)
		return cluster, nil
	}

	opts := options.NewOptions()
	if err := opts.Complete(); err != nil {
		t.Errorf("Complete antrea controller config error: %v", err)
	}

	_ = os.Setenv(env.NodeNameEnvKey, "name")

	newOVSDBConnection = func(address string) (*ovsdb.OVSDB, ovsconfig.Error) {

		return &ovsdb.OVSDB{}, nil
	}

	go func() {
		time.Sleep(time.Second)
		signals.GenerateStopSignal()
	}()
	if err := Run(opts); err != nil {
		t.Errorf("Run antrea controller error: %v", err)
	}
}
