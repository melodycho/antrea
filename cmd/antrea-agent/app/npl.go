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
	npl "antrea.io/antrea/pkg/agent/nodeportlocal"
	"fmt"
)

func startNodePortLocalController(agentContext agentContext, stopCh <-chan struct{}) error {
	if agentContext.enableNodePortLocal {
		nplController, err := npl.InitializeNPLAgent(
			agentContext.k8sClient,
			agentContext.informerFactory,
			agentContext.options.NplStartPort,
			agentContext.options.NplEndPort,
			agentContext.nodeConfig.Name,
			agentContext.localPodInformer)
		if err != nil {
			return fmt.Errorf("failed to start NPL agent: %v", err)
		}
		go nplController.Run(stopCh)
	}
	return nil
}
