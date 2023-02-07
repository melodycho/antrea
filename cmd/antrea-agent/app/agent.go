// Copyright 2019 Antrea Authors
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
	crdclientset "antrea.io/antrea/pkg/client/clientset/versioned"
	"context"
	"fmt"
	"net"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apiserver/pkg/server/options"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	agentoptions "antrea.io/antrea/cmd/antrea-agent/app/options"
	"antrea.io/antrea/cmd/antrea-agent/app/util"
	"antrea.io/antrea/pkg/agent"
	"antrea.io/antrea/pkg/agent/apiserver"
	"antrea.io/antrea/pkg/agent/cniserver"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/controller/egress"
	"antrea.io/antrea/pkg/agent/controller/ipseccertificate"
	"antrea.io/antrea/pkg/agent/controller/networkpolicy"
	"antrea.io/antrea/pkg/agent/controller/noderoute"
	"antrea.io/antrea/pkg/agent/externalnode"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/memberlist"
	"antrea.io/antrea/pkg/agent/metrics"
	"antrea.io/antrea/pkg/agent/multicast"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/proxy"
	proxytypes "antrea.io/antrea/pkg/agent/proxy/types"
	"antrea.io/antrea/pkg/agent/querier"
	"antrea.io/antrea/pkg/agent/route"
	"antrea.io/antrea/pkg/agent/secondarynetwork/cnipodcache"
	"antrea.io/antrea/pkg/agent/secondarynetwork/podwatch"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	crdv1alpha1informers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/log"
	ofconfig "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/ovs/ovsctl"
	"antrea.io/antrea/pkg/signals"
	"antrea.io/antrea/pkg/util/channel"
	"antrea.io/antrea/pkg/util/k8s"
	"antrea.io/antrea/pkg/version"
)

// informerDefaultResync is the default resync period if a handler doesn't specify one.
// Use the same default value as kube-controller-manager:
// https://github.com/kubernetes/kubernetes/blob/release-1.17/pkg/controller/apis/config/v1alpha1/defaults.go#L120
const informerDefaultResync = 12 * time.Hour

// resyncPeriodDisabled is 0 to disable resyncing.
// UpdateFunc event handler will be called only when the object is actually updated.
const resyncPeriodDisabled = 0 * time.Minute

// The devices that should be excluded from NodePort.
var excludeNodePortDevices = []string{"antrea-egress0", "antrea-ingress0", "kube-ipvs0"}

var ipv4Localhost = net.ParseIP("127.0.0.1")

var networkConfig *config.NetworkConfig

var (
	createK8sClient            = k8s.CreateClients
	newOVSDBConnection         = ovsconfig.NewOVSDBConnectionUDS
	newAgentInitializerFunc    = agent.NewInitializer
	newNetworkPolicyController = networkpolicy.NewNetworkPolicyController
	newMemberlistCluster       = memberlist.NewCluster
)

var goExec = func(function func(stopCh <-chan struct{}), stopCh <-chan struct{}) {
	go function(stopCh)
}

var goExecWithCtx = func(function func(ctx context.Context), ctx context.Context) {
	go function(ctx)
}

var apiServerRun = func(function func(stopCh <-chan struct{}) error, stopCh <-chan struct{}) {
	go func() {
		err := function(stopCh)
		if err != nil {
			klog.ErrorS(err, "start APIServer error")
		}
	}()
}

type agentContext struct {
	options    *agentoptions.Options
	nodeConfig *config.NodeConfig

	k8sClient clientset.Interface
	crdClient crdclientset.Interface

	informerFactory  informers.SharedInformerFactory
	localPodInformer cache.SharedIndexInformer

	ifaceStore interfacestore.InterfaceStore

	proxier proxy.Proxier

	ofClient        openflow.Client
	ovsBridgeClient ovsconfig.OVSBridgeClient

	connectUplinkToBridge bool
	v4Enabled             bool
	v6Enabled             bool
	serviceCIDRNet        *net.IPNet
	serviceCIDRNetv6      *net.IPNet
	ovsDatapathType       ovsconfig.OVSDatapathType

	v4GroupIDAllocator openflow.GroupAllocator

	podUpdateChannel *channel.SubscribableChannel

	multicastEnabled bool

	antreaPolicyEnabled bool

	enableAntreaIPAM bool

	enableNodePortLocal bool

	enableBridgingMode bool

	egressEnabled bool

	npController         *networkpolicy.Controller
	noderouteController  *noderoute.Controller
	mcastController      *multicast.Controller
	agentQuerier         querier.AgentQuerier
	antreaClientProvider agent.AntreaClientProvider
}

var agentCtx agentContext

// Run starts Antrea agent with the given options and waits for termination signal.
func Run(o *agentoptions.Options) error {
	klog.Infof("Starting Antrea agent (version %s)", version.GetFullVersion())

	// Create K8s Clientset, CRD Clientset, Multicluster CRD Clientset and SharedInformerFactory for the given config.
	k8sClient, _, crdClient, _, mcClient, err := createK8sClient(o.Config.ClientConnection, o.Config.KubeAPIServerOverride)
	if err != nil {
		return fmt.Errorf("error creating K8s clients: %v", err)
	}

	informerFactory := informers.NewSharedInformerFactory(k8sClient, informerDefaultResync)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, informerDefaultResync)
	traceflowInformer := crdInformerFactory.Crd().V1alpha1().Traceflows()
	egressInformer := crdInformerFactory.Crd().V1alpha2().Egresses()
	externalIPPoolInformer := crdInformerFactory.Crd().V1alpha2().ExternalIPPools()
	trafficControlInformer := crdInformerFactory.Crd().V1alpha2().TrafficControls()
	nodeInformer := informerFactory.Core().V1().Nodes()
	serviceInformer := informerFactory.Core().V1().Services()
	endpointsInformer := informerFactory.Core().V1().Endpoints()
	namespaceInformer := informerFactory.Core().V1().Namespaces()

	agentCtx.informerFactory = informerFactory

	// Create Antrea Clientset for the given config.
	antreaClientProvider := agent.NewAntreaClientProvider(o.Config.AntreaClientConnection, k8sClient)
	agentCtx.antreaClientProvider = antreaClientProvider

	// Register Antrea Agent metrics if EnablePrometheusMetrics is set
	if *o.Config.EnablePrometheusMetrics {
		metrics.InitializePrometheusMetrics()
	}

	// Create ovsdb and openflow clients.
	ovsdbAddress := ovsconfig.GetConnAddress(o.Config.OVSRunDir)
	ovsdbConnection, err := newOVSDBConnection(ovsdbAddress)
	if err != nil {
		// TODO: ovsconfig.NewOVSDBConnectionUDS might return timeout in the future, need to add retry
		return fmt.Errorf("error connecting OVSDB: %v", err)
	}
	// defer ovsdbConnection.Close()

	agentCtx.egressEnabled = features.DefaultFeatureGate.Enabled(features.Egress)
	enableAntreaIPAM := features.DefaultFeatureGate.Enabled(features.AntreaIPAM)
	enableBridgingMode := enableAntreaIPAM && o.Config.EnableBridgingMode
	enableNodePortLocal := features.DefaultFeatureGate.Enabled(features.NodePortLocal) && o.Config.NodePortLocal.Enable
	l7NetworkPolicyEnabled := features.DefaultFeatureGate.Enabled(features.L7NetworkPolicy)
	enableMulticlusterGW := features.DefaultFeatureGate.Enabled(features.Multicluster) && o.Config.Multicluster.EnableGateway
	enableMulticlusterNP := features.DefaultFeatureGate.Enabled(features.Multicluster) && o.Config.Multicluster.EnableStretchedNetworkPolicy

	// Bridging mode will connect the uplink interface to the OVS bridge.
	connectUplinkToBridge := enableBridgingMode
	agentCtx.connectUplinkToBridge = connectUplinkToBridge
	agentCtx.options = o

	ovsDatapathType := ovsconfig.OVSDatapathType(o.Config.OVSDatapathType)
	agentCtx.ovsDatapathType = ovsDatapathType

	ovsBridgeClient := ovsconfig.NewOVSBridge(o.Config.OVSBridge, ovsDatapathType, ovsdbConnection)
	ovsCtlClient := ovsctl.NewClient(o.Config.OVSBridge)
	ovsBridgeMgmtAddr := ofconfig.GetMgmtAddress(o.Config.OVSRunDir, o.Config.OVSBridge)
	multicastEnabled := features.DefaultFeatureGate.Enabled(features.Multicast)
	agentCtx.multicastEnabled = multicastEnabled
	ofClient := openflow.NewClient(o.Config.OVSBridge, ovsBridgeMgmtAddr,
		features.DefaultFeatureGate.Enabled(features.AntreaProxy),
		features.DefaultFeatureGate.Enabled(features.AntreaPolicy),
		l7NetworkPolicyEnabled,
		agentCtx.egressEnabled,
		features.DefaultFeatureGate.Enabled(features.FlowExporter),
		o.Config.AntreaProxy.ProxyAll,
		connectUplinkToBridge,
		multicastEnabled,
		features.DefaultFeatureGate.Enabled(features.TrafficControl),
		enableMulticlusterGW,
	)
	agentCtx.ovsBridgeClient = ovsBridgeClient
	agentCtx.ofClient = ofClient

	var serviceCIDRNet *net.IPNet
	if o.NodeType == config.K8sNode {
		_, serviceCIDRNet, _ = net.ParseCIDR(o.Config.ServiceCIDR)
	}
	agentCtx.serviceCIDRNet = serviceCIDRNet
	var serviceCIDRNetv6 *net.IPNet
	if o.Config.ServiceCIDRv6 != "" {
		_, serviceCIDRNetv6, _ = net.ParseCIDR(o.Config.ServiceCIDRv6)
	}
	agentCtx.serviceCIDRNetv6 = serviceCIDRNetv6

	_, encapMode := config.GetTrafficEncapModeFromStr(o.Config.TrafficEncapMode)
	_, encryptionMode := config.GetTrafficEncryptionModeFromStr(o.Config.TrafficEncryptionMode)
	if o.Config.EnableIPSecTunnel {
		klog.InfoS("enableIPSecTunnel is deprecated, use trafficEncryptionMode instead.")
		encryptionMode = config.TrafficEncryptionModeIPSec
	}
	_, ipsecAuthenticationMode := config.GetIPsecAuthenticationModeFromStr(o.Config.IPsec.AuthenticationMode)
	networkConfig = &config.NetworkConfig{
		TunnelType:            ovsconfig.TunnelType(o.Config.TunnelType),
		TunnelPort:            o.Config.TunnelPort,
		TunnelCsum:            o.Config.TunnelCsum,
		TrafficEncapMode:      encapMode,
		TrafficEncryptionMode: encryptionMode,
		TransportIface:        o.Config.TransportInterface,
		TransportIfaceCIDRs:   o.Config.TransportInterfaceCIDRs,
		IPsecConfig: config.IPsecConfig{
			AuthenticationMode: ipsecAuthenticationMode,
		},
	}

	wireguardConfig := &config.WireGuardConfig{
		Port: o.Config.WireGuard.Port,
	}
	var exceptCIDRs []net.IPNet
	for _, cidr := range o.Config.Egress.ExceptCIDRs {
		_, exceptCIDR, _ := net.ParseCIDR(cidr)
		exceptCIDRs = append(exceptCIDRs, *exceptCIDR)
	}
	egressConfig := &config.EgressConfig{
		ExceptCIDRs: exceptCIDRs,
	}
	routeClient, err := route.NewClient(networkConfig, o.Config.NoSNAT, o.Config.AntreaProxy.ProxyAll, connectUplinkToBridge, multicastEnabled)
	if err != nil {
		return fmt.Errorf("error creating route client: %v", err)
	}

	// Create an ifaceStore that caches network interfaces managed by this node.
	ifaceStore := interfacestore.NewInterfaceStore()
	agentCtx.ifaceStore = ifaceStore

	// networkReadyCh is used to notify that the Node's network is ready.
	// Functions that rely on the Node's network should wait for the channel to close.
	networkReadyCh := make(chan struct{})
	// set up signal capture: the first SIGTERM / SIGINT signal is handled gracefully and will
	// cause the stopCh channel to be closed; if another signal is received before the program
	// exits, we will force exit.
	stopCh := signals.RegisterSignalHandlers()
	// Generate a context for functions which require one (instead of stopCh).
	// We cancel the context when the function returns, which in the normal case will be when
	// stopCh is closed.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Get all available NodePort addresses.
	var nodePortAddressesIPv4, nodePortAddressesIPv6 []net.IP
	if o.Config.AntreaProxy.ProxyAll {
		nodePortAddressesIPv4, nodePortAddressesIPv6, err = util.GetAvailableNodePortAddresses(o.Config.AntreaProxy.NodePortAddresses, append(excludeNodePortDevices, o.Config.HostGateway))
		if err != nil {
			return fmt.Errorf("getting available NodePort IP addresses failed: %v", err)
		}
	}
	serviceConfig := &config.ServiceConfig{
		ServiceCIDR:           serviceCIDRNet,
		ServiceCIDRv6:         serviceCIDRNetv6,
		NodePortAddressesIPv4: nodePortAddressesIPv4,
		NodePortAddressesIPv6: nodePortAddressesIPv6,
	}

	// Initialize agent and node network.
	agentInitializer := newAgentInitializerFunc(
		k8sClient,
		crdClient,
		ovsBridgeClient,
		ovsCtlClient,
		ofClient,
		routeClient,
		ifaceStore,
		o.Config.OVSBridge,
		o.Config.HostGateway,
		o.Config.DefaultMTU,
		networkConfig,
		wireguardConfig,
		egressConfig,
		serviceConfig,
		networkReadyCh,
		stopCh,
		o.NodeType,
		o.Config.ExternalNode.ExternalNodeNamespace,
		features.DefaultFeatureGate.Enabled(features.AntreaProxy),
		o.Config.AntreaProxy.ProxyAll,
		connectUplinkToBridge,
		l7NetworkPolicyEnabled)
	err = agentInitializer.Initialize()
	if err != nil {
		return fmt.Errorf("error initializing agent: %v", err)
	}
	nodeConfig := agentInitializer.GetNodeConfig()
	agentCtx.nodeConfig = nodeConfig

	var ipsecCertController *ipseccertificate.Controller

	if networkConfig.TrafficEncryptionMode == config.TrafficEncryptionModeIPSec &&
		networkConfig.IPsecConfig.AuthenticationMode == config.IPsecAuthenticationModeCert {
		ipsecCertController = ipseccertificate.NewIPSecCertificateController(k8sClient, ovsBridgeClient, nodeConfig.Name)
	}

	var nodeRouteController *noderoute.Controller
	if o.NodeType == config.K8sNode {
		nodeRouteController = noderoute.NewNodeRouteController(
			k8sClient,
			informerFactory,
			ofClient,
			ovsBridgeClient,
			routeClient,
			ifaceStore,
			networkConfig,
			nodeConfig,
			agentInitializer.GetWireGuardClient(),
			o.Config.AntreaProxy.ProxyAll,
			ipsecCertController,
		)
	}
	agentCtx.noderouteController = nodeRouteController

	// podUpdateChannel is a channel for receiving Pod updates from CNIServer and
	// notifying NetworkPolicyController, StretchedNetworkPolicyController and
	// EgressController to reconcile rules related to the updated Pods.
	var podUpdateChannel *channel.SubscribableChannel
	// externalEntityUpdateChannel is a channel for receiving ExternalEntity updates from ExternalNodeController and
	// notifying NetworkPolicyController to reconcile rules related to the updated ExternalEntities.
	var externalEntityUpdateChannel *channel.SubscribableChannel
	if o.NodeType == config.K8sNode {
		podUpdateChannel = channel.NewSubscribableChannel("PodUpdate", 100)
	} else {
		externalEntityUpdateChannel = channel.NewSubscribableChannel("ExternalEntityUpdate", 100)
	}
	agentCtx.podUpdateChannel = podUpdateChannel

	// Initialize localPodInformer for NPLAgent, AntreaIPAMController,
	// StretchedNetworkPolicyController, and secondary network controller.
	var localPodInformer cache.SharedIndexInformer
	if enableNodePortLocal || enableBridgingMode || enableMulticlusterNP ||
		features.DefaultFeatureGate.Enabled(features.SecondaryNetwork) ||
		features.DefaultFeatureGate.Enabled(features.TrafficControl) {
		listOptions := func(options *metav1.ListOptions) {
			options.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", nodeConfig.Name).String()
		}
		localPodInformer = coreinformers.NewFilteredPodInformer(
			k8sClient,
			metav1.NamespaceAll,
			resyncPeriodDisabled,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, // NamespaceIndex is used in NPLController.
			listOptions,
		)
	}
	agentCtx.localPodInformer = localPodInformer

	var groupCounters []proxytypes.GroupCounter
	groupIDUpdates := make(chan string, 100)
	v4GroupIDAllocator := openflow.NewGroupAllocator(false)
	v4GroupCounter := proxytypes.NewGroupCounter(v4GroupIDAllocator, groupIDUpdates)
	v6GroupIDAllocator := openflow.NewGroupAllocator(true)
	v6GroupCounter := proxytypes.NewGroupCounter(v6GroupIDAllocator, groupIDUpdates)

	agentCtx.v4GroupIDAllocator = v4GroupIDAllocator

	// We set flow poll interval as the time interval for rule deletion in the async
	// rule cache, which is implemented as part of the idAllocator. This is to preserve
	// the rule info for populating NetworkPolicy fields in the Flow Exporter even
	// after rule deletion.
	asyncRuleDeleteInterval := o.PollInterval
	antreaPolicyEnabled := features.DefaultFeatureGate.Enabled(features.AntreaPolicy)
	agentCtx.antreaPolicyEnabled = antreaPolicyEnabled
	antreaProxyEnabled := features.DefaultFeatureGate.Enabled(features.AntreaProxy)
	// In Antrea agent, status manager and audit logging will automatically be enabled
	// if AntreaPolicy feature is enabled.
	statusManagerEnabled := antreaPolicyEnabled
	loggingEnabled := antreaPolicyEnabled

	var gwPort, tunPort uint32
	if o.NodeType == config.K8sNode {
		gwPort = nodeConfig.GatewayConfig.OFPort
		tunPort = nodeConfig.TunnelOFPort
	}

	nodeKey := nodeConfig.Name
	if o.NodeType == config.ExternalNode {
		nodeKey = k8s.NamespacedName(o.Config.ExternalNode.ExternalNodeNamespace, nodeKey)
	}
	networkPolicyController, err := newNetworkPolicyController(
		antreaClientProvider,
		ofClient,
		ifaceStore,
		nodeKey,
		podUpdateChannel,
		externalEntityUpdateChannel,
		groupCounters,
		groupIDUpdates,
		antreaPolicyEnabled,
		l7NetworkPolicyEnabled,
		antreaProxyEnabled,
		statusManagerEnabled,
		multicastEnabled,
		loggingEnabled,
		asyncRuleDeleteInterval,
		o.DnsServerOverride,
		o.NodeType,
		v4Enabled,
		v6Enabled,
		gwPort,
		tunPort,
	)
	if err != nil {
		return fmt.Errorf("error creating new NetworkPolicy controller: %v", err)
	}
	agentCtx.npController = networkPolicyController

	var egressController *egress.EgressController

	if agentCtx.egressEnabled {
		egressController, err = egress.NewEgressController(
			ofClient, antreaClientProvider, crdClient, ifaceStore, routeClient, nodeConfig.Name, nodeConfig.NodeTransportInterfaceName,
			memberlistCluster, egressInformer, podUpdateChannel,
		)
		if err != nil {
			return fmt.Errorf("error creating new Egress controller: %v", err)
		}
	}

	var cniServer *cniserver.CNIServer
	var cniPodInfoStore cnipodcache.CNIPodInfoStore
	var externalNodeController *externalnode.ExternalNodeController
	var localExternalNodeInformer cache.SharedIndexInformer
	if o.NodeType == config.K8sNode {
		isChaining := false
		if networkConfig.TrafficEncapMode.IsNetworkPolicyOnly() {
			isChaining = true
		}
		cniServer = cniserver.New(
			o.Config.CNISocket,
			o.Config.HostProcPathPrefix,
			nodeConfig,
			k8sClient,
			routeClient,
			isChaining,
			enableBridgingMode,
			enableAntreaIPAM,
			o.Config.DisableTXChecksumOffload,
			networkReadyCh)

		if features.DefaultFeatureGate.Enabled(features.SecondaryNetwork) {
			cniPodInfoStore = cnipodcache.NewCNIPodInfoStore()
			err = cniServer.Initialize(ovsBridgeClient, ofClient, ifaceStore, podUpdateChannel, cniPodInfoStore)
			if err != nil {
				return fmt.Errorf("error initializing CNI server with cniPodInfoStore cache: %v", err)
			}
		} else {
			err = cniServer.Initialize(ovsBridgeClient, ofClient, ifaceStore, podUpdateChannel, nil)
			if err != nil {
				return fmt.Errorf("error initializing CNI server: %v", err)
			}
		}
	} else {
		listOptions := func(options *metav1.ListOptions) {
			options.FieldSelector = fields.OneTermEqualSelector("metadata.name", nodeConfig.Name).String()
		}
		localExternalNodeInformer = crdv1alpha1informers.NewFilteredExternalNodeInformer(
			crdClient,
			o.Config.ExternalNode.ExternalNodeNamespace,
			resyncPeriodDisabled,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			listOptions,
		)
		externalNodeController, err = externalnode.NewExternalNodeController(ovsBridgeClient, ofClient, localExternalNodeInformer,
			ifaceStore, externalEntityUpdateChannel, o.Config.ExternalNode.ExternalNodeNamespace, o.Config.ExternalNode.PolicyBypassRules)
		if err != nil {
			return fmt.Errorf("error creating ExternalNode controller: %v", err)
		}
	}

	// TODO: we should call this after installing flows for initial node routes
	//  and initial NetworkPolicies so that no packets will be mishandled.
	if err := agentInitializer.FlowRestoreComplete(); err != nil {
		return err
	}
	// ConnectUplinkToOVSBridge must be run immediately after FlowRestoreComplete
	if connectUplinkToBridge {
		// Restore network config before shutdown. ovsdbConnection must be alive when restore.
		defer agentInitializer.RestoreOVSBridge()
		if err := agentInitializer.ConnectUplinkToOVSBridge(); err != nil {
			return fmt.Errorf("failed to connect uplink to OVS bridge: %w", err)
		}
	}

	if err := antreaClientProvider.RunOnce(); err != nil {
		return err
	}

	log.StartLogFileNumberMonitor(stopCh)

	if o.NodeType == config.K8sNode {
		// go routeClient.Run(stopCh)
		// go podUpdateChannel.Run(stopCh)
		// go cniServer.Run(stopCh)
		// go nodeRouteController.Run(stopCh)
		// goExec(routeClient.Run, stopCh)
		goExec(podUpdateChannel.Run, stopCh)
		goExec(cniServer.Run, stopCh)
		goExec(nodeRouteController.Run, stopCh)
	} else {
		// go externalEntityUpdateChannel.Run(stopCh)
		// go localExternalNodeInformer.Run(stopCh)
		// go externalNodeController.Run(stopCh)
		goExec(externalEntityUpdateChannel.Run, stopCh)
		goExec(localExternalNodeInformer.Run, stopCh)
		goExec(externalNodeController.Run, stopCh)
	}

	if networkConfig.TrafficEncryptionMode == config.TrafficEncryptionModeIPSec &&
		networkConfig.IPsecConfig.AuthenticationMode == config.IPsecAuthenticationModeCert {
		// go ipsecCertController.Run(stopCh)
		goExec(ipsecCertController.Run, stopCh)
	}

	// go antreaClientProvider.Run(ctx)
	goExecWithCtx(antreaClientProvider.Run, ctx)

	if networkConfig.TrafficEncryptionMode == config.TrafficEncryptionModeIPSec &&
		networkConfig.IPsecConfig.AuthenticationMode == config.IPsecAuthenticationModeCert {
		// go ipsecCertController.Run(stopCh)
		goExec(ipsecCertController.Run, stopCh)
	}

	// go networkPolicyController.Run(stopCh)
	goExec(networkPolicyController.Run, stopCh)
	// Initialize the NPL agent.
	startNodePortLocalController(agentCtx, stopCh)

	// Antrea IPAM is needed by bridging mode and secondary network IPAM.
	startIPAM(agentCtx, stopCh)

	if features.DefaultFeatureGate.Enabled(features.SecondaryNetwork) {
		// Create the NetworkAttachmentDefinition client, which handles access to secondary network object definition from the API Server.
		netAttachDefClient, err := k8s.CreateNetworkAttachDefClient(o.Config.ClientConnection, o.Config.KubeAPIServerOverride)
		if err != nil {
			return fmt.Errorf("NetworkAttachmentDefinition client creation failed. %v", err)
		}
		// Create podController to handle secondary network configuration for Pods with k8s.v1.cni.cncf.io/networks Annotation defined.
		podWatchController := podwatch.NewPodController(
			k8sClient,
			netAttachDefClient,
			localPodInformer,
			nodeConfig.Name,
			cniPodInfoStore,
			// safe to call given that cniServer.Initialize has been called already.
			cniServer.GetPodConfigurator())
		// go podWatchController.Run(stopCh)
		goExec(podWatchController.Run, stopCh)
	}

	startTrafficControl(agentCtx, stopCh)

	//  Start the localPodInformer
	if localPodInformer != nil {
		// go localPodInformer.Run(stopCh)
		goExec(localPodInformer.Run, stopCh)
	}

	informerFactory.Start(stopCh)
	crdInformerFactory.Start(stopCh)

	if agentCtx.egressEnabled || features.DefaultFeatureGate.Enabled(features.ServiceExternalIP) {
		// go externalIPPoolController.Run(stopCh)
		// go memberlistCluster.Run(stopCh)
		goExec(externalIPPoolController.Run, stopCh)
		goExec(memberlistCluster.Run, stopCh)
	}

	if agentCtx.egressEnabled {
		// go egressController.Run(stopCh)
		goExec(egressController.Run, stopCh)
	}

	startExternalIPController()

	startTraceflowController(agentCtx, stopCh)

	startAntreaProxy(agentCtx, stopCh)

	startMulticastController(agentCtx, stopCh)

	startMultiClusterRouteController(agentCtx, stopCh)

	// statsCollector collects stats and reports to the antrea-controller periodically. For now, it's only used for
	// NetworkPolicy stats and Multicast stats.
	startStatsCollector(agentCtx, stopCh)

	agentQuerier := querier.NewAgentQuerier(
		nodeConfig,
		networkConfig,
		ifaceStore,
		k8sClient,
		ofClient,
		ovsBridgeClient,
		proxier,
		networkPolicyController,
		o.Config.APIPort,
		o.Config.NodePortLocal.PortRange,
	)
	agentCtx.agentQuerier = agentQuerier

	startAgentMonitor(agentCtx, stopCh)

	startSupportBundleCollection(agentCtx, stopCh)

	bindAddress := net.IPv4zero
	if o.NodeType == config.ExternalNode {
		bindAddress = ipv4Localhost
	}
	secureServing := options.NewSecureServingOptions().WithLoopback()
	secureServing.BindAddress = bindAddress
	secureServing.BindPort = o.Config.APIPort
	secureServing.CipherSuites = o.TlsCipherSuites
	secureServing.MinTLSVersion = o.Config.TLSMinVersion
	authentication := options.NewDelegatingAuthenticationOptions()
	authorization := options.NewDelegatingAuthorizationOptions().WithAlwaysAllowPaths("/healthz", "/livez", "/readyz")
	apiServer, err := apiserver.New(
		agentQuerier,
		networkPolicyController,
		mcastController,
		externalIPController,
		secureServing,
		authentication,
		authorization,
		*o.Config.EnablePrometheusMetrics,
		o.Config.ClientConnection.Kubeconfig,
		v4Enabled,
		v6Enabled)
	if err != nil {
		return fmt.Errorf("error when creating agent API server: %v", err)
	}
	// go apiServer.Run(stopCh)
	apiServerRun(apiServer.Run, stopCh)
	// goExec(apiServer.Run, stopCh)

	// Start PacketIn
	// go ofClient.StartPacketInHandler(stopCh)
	goExec(ofClient.StartPacketInHandler, stopCh)

	// Start the goroutine to periodically export IPFIX flow records.
	startFlowExporter(agentCtx, stopCh)

	<-stopCh
	klog.Info("Stopping Antrea agent")
	return nil
}
