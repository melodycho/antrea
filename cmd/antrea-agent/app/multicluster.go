package app

import (
	mcinformers "antrea.io/antrea/multicluster/pkg/client/informers/externalversions"
	mcroute "antrea.io/antrea/pkg/agent/multicluster"
	"antrea.io/antrea/pkg/util/env"
)

func startMultiClusterRouteController(agentContext agentContext, stopCh <-chan struct{}) error {
	var mcRouteController *mcroute.MCRouteController
	var mcStrechedNetworkPolicyController *mcroute.StretchedNetworkPolicyController
	var mcInformerFactory mcinformers.SharedInformerFactory
	if enableMulticlusterGW {
		mcNamespace := env.GetPodNamespace()
		if o.Config.Multicluster.Namespace != "" {
			mcNamespace = o.Config.Multicluster.Namespace
		}
		mcInformerFactory = mcinformers.NewSharedInformerFactory(mcClient, informerDefaultResync)
		gwInformer := mcInformerFactory.Multicluster().V1alpha1().Gateways()
		ciImportInformer := mcInformerFactory.Multicluster().V1alpha1().ClusterInfoImports()
		mcRouteController = mcroute.NewMCRouteController(
			mcClient,
			gwInformer,
			ciImportInformer,
			ofClient,
			ovsBridgeClient,
			ifaceStore,
			nodeConfig,
			mcNamespace,
			o.Config.Multicluster.EnableStretchedNetworkPolicy,
		)
	}
	if enableMulticlusterNP {
		labelIDInformer := mcInformerFactory.Multicluster().V1alpha1().LabelIdentities()
		mcStrechedNetworkPolicyController = mcroute.NewMCAgentStretchedNetworkPolicyController(
			ofClient,
			ifaceStore,
			localPodInformer,
			informerFactory.Core().V1().Namespaces(),
			labelIDInformer,
			podUpdateChannel,
		)
	}

	if enableMulticlusterGW {
		mcInformerFactory.Start(stopCh)
		// go mcRouteController.Run(stopCh)
		goExec(mcRouteController.Run, stopCh)
	}
	if enableMulticlusterNP {
		// go mcStrechedNetworkPolicyController.Run(stopCh)
		goExec(mcStrechedNetworkPolicyController.Run, stopCh)
	}

}
