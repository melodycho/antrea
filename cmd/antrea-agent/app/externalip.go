package app

import (
	"antrea.io/antrea/pkg/features"
	"fmt"
)

func startExternalIPController(agentContext agentContext, stopCh <-chan struct{}) error {
	var externalIPController *serviceexternalip.ServiceExternalIPController

	if features.DefaultFeatureGate.Enabled(features.ServiceExternalIP) {
		externalIPController, err = serviceexternalip.NewServiceExternalIPController(
			nodeConfig.Name,
			nodeConfig.NodeTransportInterfaceName,
			k8sClient,
			memberlistCluster,
			serviceInformer,
			endpointsInformer,
		)
		if err != nil {
			return fmt.Errorf("error creating new ServiceExternalIP controller: %v", err)
		}
	}

	if features.DefaultFeatureGate.Enabled(features.ServiceExternalIP) {
		// go externalIPController.Run(stopCh)
		goExec(externalIPController.Run, stopCh)
	}

}
