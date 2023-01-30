//go:build windows
// +build windows

// Copyright 2020 Antrea Authors
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

package options

import (
	"fmt"
	"strings"

	"k8s.io/component-base/featuregate"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
)

func (o *Options) checkUnsupportedFeatures() error {
	var unsupported []string

	// First check feature gates.
	for f, enabled := range o.Config.FeatureGates {
		if enabled && !features.SupportedOnWindows(featuregate.Feature(f)) {
			unsupported = append(unsupported, f)
		}
	}

	if o.Config.OVSDatapathType != string(ovsconfig.OVSDatapathSystem) {
		unsupported = append(unsupported, "OVSDatapathType: "+o.Config.OVSDatapathType)
	}
	_, encapMode := config.GetTrafficEncapModeFromStr(o.Config.TrafficEncapMode)
	if encapMode == config.TrafficEncapModeNetworkPolicyOnly {
		unsupported = append(unsupported, "TrafficEncapMode: "+encapMode.String())
	}
	if o.Config.TunnelType == ovsconfig.GRETunnel {
		unsupported = append(unsupported, "TunnelType: "+o.Config.TunnelType)
	}
	_, encryptionMode := config.GetTrafficEncryptionModeFromStr(o.Config.TrafficEncryptionMode)
	if encryptionMode != config.TrafficEncryptionModeNone {
		unsupported = append(unsupported, "TrafficEncryptionMode: "+encryptionMode.String())
	}
	if o.Config.EnableBridgingMode {
		unsupported = append(unsupported, "EnableBridgingMode")
	}
	if unsupported != nil {
		return fmt.Errorf("unsupported features on Windows: {%s}", strings.Join(unsupported, ", "))
	}

	if !features.DefaultFeatureGate.Enabled(features.AntreaProxy) {
		klog.Warning("AntreaProxy is not enabled. NetworkPolicies might not be enforced correctly for Service traffic!")
	}
	return nil
}