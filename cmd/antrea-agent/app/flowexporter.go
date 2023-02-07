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

	"antrea.io/antrea/pkg/agent/flowexporter"
	"antrea.io/antrea/pkg/agent/flowexporter/exporter"
	"antrea.io/antrea/pkg/features"
)

func startFlowExporter(agentContext agentContext, stopCh <-chan struct{}) error {
	var flowExporter *exporter.FlowExporter
	if features.DefaultFeatureGate.Enabled(features.FlowExporter) {
		flowExporterOptions := &flowexporter.FlowExporterOptions{
			FlowCollectorAddr:      agentContext.options.FlowCollectorAddr,
			FlowCollectorProto:     agentContext.options.FlowCollectorProto,
			ActiveFlowTimeout:      agentContext.options.ActiveFlowTimeout,
			IdleFlowTimeout:        agentContext.options.IdleFlowTimeout,
			StaleConnectionTimeout: agentContext.options.StaleConnectionTimeout,
			PollInterval:           agentContext.options.PollInterval,
			ConnectUplinkToBridge:  agentContext.connectUplinkToBridge}
		flowExporter, err := exporter.NewFlowExporter(
			agentContext.ifaceStore,
			agentContext.proxier,
			agentContext.k8sClient,
			agentContext.noderouteController,
			networkConfig.TrafficEncapMode,
			agentContext.nodeConfig,
			agentContext.v4Enabled,
			agentContext.v6Enabled,
			agentContext.serviceCIDRNet,
			agentContext.serviceCIDRNetv6,
			agentContext.ovsDatapathType,
			features.DefaultFeatureGate.Enabled(features.AntreaProxy),
			agentCtx.npController,
			flowExporterOptions)
		if err != nil {
			return fmt.Errorf("error when creating IPFIX flow exporter: %v", err)
		}
		agentCtx.npController.SetDenyConnStore(flowExporter.GetDenyConnStore())
	}
	go flowExporter.Run(stopCh)
	return nil
}
