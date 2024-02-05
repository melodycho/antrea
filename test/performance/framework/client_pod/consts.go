// Copyright 2023 Antrea Authors.
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

package client_pod

import (
	"fmt"

	"github.com/google/uuid"
	"k8s.io/klog/v2"
)

func init() {
	suffix := uuid.New().String()
	ScaleTestNamespaceBase = fmt.Sprintf("%s-%s", ScaleTestNamespacePrefix, suffix[:6])
	klog.InfoS("Scale up namespace", "ScaleTestNamespaceBase", ScaleTestNamespaceBase)
}

var (
	ScaleTestNamespacePrefix = "antrea-scale-ns"
	ScaleTestNamespaceBase   = "antrea-scale-ns-xxxx"
	ClientPodsNamespace      = ScaleTestNamespacePrefix + "-scale-client"
)

const (
	AppLabelKey   = "app"
	AppLabelValue = "antrea-scale-test-workload"

	SimulatorNodeLabelKey   = "antrea/instance"
	SimulatorNodeLabelValue = "simulator"

	SimulatorTaintKey   = "simulator"
	SimulatorTaintValue = "true"

	ScaleTestClientDaemonSet          = "antrea-scale-test-client-daemonset"
	ScaleClientContainerName          = "antrea-scale-test-client"
	ScaleAgentProbeContainerName      = "antrea-scale-test-agent-probe"
	ScaleControllerProbeContainerName = "antrea-scale-test-controller-probe"
	ScaleClientPodTemplateName        = "antrea-scale-test-client"

	ScaleTestControllerProbeDaemonSet = "antrea-scale-test-controller-probe-daemonset"
	ScaleTestAgentProbeDaemonSet      = "antrea-scale-test-agent-probe-daemonset"
)
