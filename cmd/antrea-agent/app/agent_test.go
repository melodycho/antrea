package app

import (
	"antrea.io/antrea/pkg/agent"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/route"
	testing2 "antrea.io/antrea/pkg/agent/testing"
	"antrea.io/antrea/pkg/ovs/ovsctl"
	"antrea.io/antrea/pkg/util/env"
	"context"
	"github.com/golang/mock/gomock"
	"os"
	"reflect"
	"runtime"
	"testing"
	"time"

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
	newAgentInitializerFunc = func(k8sClient clientset.Interface, crdClient crdclientset.Interface, ovsBridgeClient ovsconfig.OVSBridgeClient, ovsCtlClient ovsctl.OVSCtlClient, ofClient openflow.Client, routeClient route.Interface, ifaceStore interfacestore.InterfaceStore, ovsBridge string, hostGateway string, mtu int, networkConfig *config.NetworkConfig, wireGuardConfig *config.WireGuardConfig, egressConfig *config.EgressConfig, serviceConfig *config.ServiceConfig, networkReadyCh chan<- struct{}, stopCh <-chan struct{}, nodeType config.NodeType, externalNodeNamespace string, enableProxy bool, proxyAll bool, connectUplinkToBridge bool, enableL7NetworkPolicy bool) agent.AgentInitialierI {
		ctl := gomock.NewController(t)
		defer ctl.Finish()
		mockAgentInit := testing2.NewMockAgentInitialierI(ctl)
		return mockAgentInit
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
