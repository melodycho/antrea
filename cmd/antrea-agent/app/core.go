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
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/controller/noderoute"
	"antrea.io/antrea/pkg/agent/querier"
	"antrea.io/antrea/pkg/monitor"
)

func startAgentMonitor(agentContext agentContext, stopCh <-chan struct{}) error {
	agentQuerier := querier.NewAgentQuerier(
		agentContext.nodeConfig,
		networkConfig,
		agentContext.ifaceStore,
		agentContext.k8sClient,
		agentContext.ofClient,
		agentContext.ovsBridgeClient,
		agentContext.proxier,
		agentContext.npController,
		agentContext.options.Config.APIPort,
		agentContext.options.Config.NodePortLocal.PortRange,
	)
	agentCtx.agentQuerier = agentQuerier

	agentMonitor := monitor.NewAgentMonitor(agentContext.crdClient, agentQuerier)

	go agentMonitor.Run(stopCh)
	return nil
}

func startNodeRouteController(agentContext agentContext, stopCh <-chan struct{}) error {
	var nodeRouteController *noderoute.Controller
	if agentContext.options.NodeType == config.K8sNode {
		nodeRouteController = noderoute.NewNodeRouteController(
			agentContext.k8sClient,
			agentContext.informerFactory,
			agentContext.ofClient,
			agentContext.ovsBridgeClient,
			agentContext.routeClient,
			agentContext.ifaceStore,
			networkConfig,
			agentContext.nodeConfig,
			agentContext.agentInitializer.GetWireGuardClient(),
			agentContext.options.Config.AntreaProxy.ProxyAll,
			agentContext.ipsecCertController,
		)
	}
	agentCtx.noderouteController = nodeRouteController
	return nil
}
