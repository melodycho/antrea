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
	"antrea.io/antrea/pkg/agent/config"
	support "antrea.io/antrea/pkg/agent/supportbundlecollection"
	"antrea.io/antrea/pkg/apis/controlplane"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/ovs/ovsctl"
)

func startSupportBundleCollection(agentContext agentContext, stopCh <-chan struct{}) error {
	if features.DefaultFeatureGate.Enabled(features.SupportBundleCollection) {
		nodeNamespace := ""
		nodeType := controlplane.SupportBundleCollectionNodeTypeNode
		if agentContext.options.NodeType == config.ExternalNode {
			nodeNamespace = agentContext.options.Config.ExternalNode.ExternalNodeNamespace
			nodeType = controlplane.SupportBundleCollectionNodeTypeExternalNode
		}
		supportBundleController := support.NewSupportBundleController(agentContext.nodeConfig.Name, nodeType, nodeNamespace, agentContext.antreaClientProvider,
			ovsctl.NewClient(agentContext.options.Config.OVSBridge), agentContext.agentQuerier, agentContext.npController, agentContext.v4Enabled, agentContext.v6Enabled)
		go supportBundleController.Run(stopCh)
	}
	return nil
}
