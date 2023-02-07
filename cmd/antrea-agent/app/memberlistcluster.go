package app

import (
	"antrea.io/antrea/pkg/agent/memberlist"
	"antrea.io/antrea/pkg/controller/externalippool"
	"antrea.io/antrea/pkg/features"
	"fmt"
	"net"
)

func startMemberlist() {
	var externalIPPoolController *externalippool.ExternalIPPoolController

	var memberlistCluster *memberlist.Cluster

	if agentCtx.egressEnabled || features.DefaultFeatureGate.Enabled(features.ServiceExternalIP) {
		externalIPPoolController = externalippool.NewExternalIPPoolController(
			crdClient, externalIPPoolInformer,
		)
		var nodeTransportIP net.IP
		if nodeConfig.NodeTransportIPv4Addr != nil {
			nodeTransportIP = nodeConfig.NodeTransportIPv4Addr.IP
		} else if nodeConfig.NodeTransportIPv6Addr != nil {
			nodeTransportIP = nodeConfig.NodeTransportIPv6Addr.IP
		} else {
			return fmt.Errorf("invalid Node Transport IPAddr in Node config: %v", nodeConfig)
		}
		memberlistCluster, err = newMemberlistCluster(nodeTransportIP, o.Config.ClusterMembershipPort,
			nodeConfig.Name, nodeInformer, externalIPPoolInformer, nil,
		)
		if err != nil {
			return fmt.Errorf("error creating new memberlist cluster: %v", err)
		}
	}
}
