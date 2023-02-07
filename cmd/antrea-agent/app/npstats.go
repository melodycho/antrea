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
	"antrea.io/antrea/pkg/agent/stats"
	"antrea.io/antrea/pkg/features"
)

func startStatsCollector(agentContext agentContext, stopCh <-chan struct{}) error {
	if features.DefaultFeatureGate.Enabled(features.NetworkPolicyStats) {
		statsCollector := stats.NewCollector(agentContext.antreaClientProvider, agentContext.ofClient, agentContext.npController, agentContext.mcastController)
		go statsCollector.Run(stopCh)
	}
	return nil
}
