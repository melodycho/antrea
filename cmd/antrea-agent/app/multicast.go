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
	"fmt"

	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/pkg/agent/multicast"
	agenttypes "antrea.io/antrea/pkg/agent/types"
)

func startMulticastController(agentContext agentContext, stopCh <-chan struct{}) error {
	var mcastController *multicast.Controller
	if agentContext.multicastEnabled {
		multicastSocket, err := multicast.CreateMulticastSocket()
		if err != nil {
			return fmt.Errorf("failed to create multicast socket")
		}
		var validator agenttypes.McastNetworkPolicyController
		if agentContext.antreaPolicyEnabled {
			validator = agentContext.npController
		}
		mcastController = multicast.NewMulticastController(
			agentContext.ofClient,
			agentContext.v4GroupIDAllocator,
			agentContext.nodeConfig,
			agentContext.ifaceStore,
			multicastSocket,
			sets.NewString(append(agentContext.options.Config.Multicast.MulticastInterfaces, agentContext.nodeConfig.NodeTransportInterfaceName)...),
			agentContext.ovsBridgeClient,
			agentContext.podUpdateChannel,
			agentContext.options.IgmpQueryInterval,
			validator,
			networkConfig.TrafficEncapMode.SupportsEncap(),
			agentContext.informerFactory)
		if err := mcastController.Initialize(); err != nil {
			return err
		}
		go mcastController.Run(stopCh)
	}
	agentCtx.mcastController = mcastController
	return nil
}
