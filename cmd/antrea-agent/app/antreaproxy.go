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
	"antrea.io/antrea/pkg/agent/proxy"
	"antrea.io/antrea/pkg/features"
	"fmt"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
	"time"
)

func startAntreaProxy(agentContext agentContext, stopCh <-chan struct{}) error {
	v4Enabled := networkConfig.IPv4Enabled
	v6Enabled := networkConfig.IPv6Enabled
	var proxier proxy.Proxier
	if features.DefaultFeatureGate.Enabled(features.AntreaProxy) {
		proxyAll := o.Config.AntreaProxy.ProxyAll
		skipServices := o.Config.AntreaProxy.SkipServices
		proxyLoadBalancerIPs := *o.Config.AntreaProxy.ProxyLoadBalancerIPs

		switch {
		case v4Enabled && v6Enabled:
			proxier = proxy.NewDualStackProxier(nodeConfig.Name, informerFactory, ofClient, routeClient, nodePortAddressesIPv4, nodePortAddressesIPv6, proxyAll, skipServices, proxyLoadBalancerIPs, v4GroupCounter, v6GroupCounter)
			groupCounters = append(groupCounters, v4GroupCounter, v6GroupCounter)
		case v4Enabled:
			proxier = proxy.NewProxier(nodeConfig.Name, informerFactory, ofClient, false, routeClient, nodePortAddressesIPv4, proxyAll, skipServices, proxyLoadBalancerIPs, v4GroupCounter)
			groupCounters = append(groupCounters, v4GroupCounter)
		case v6Enabled:
			proxier = proxy.NewProxier(nodeConfig.Name, informerFactory, ofClient, true, routeClient, nodePortAddressesIPv6, proxyAll, skipServices, proxyLoadBalancerIPs, v6GroupCounter)
			groupCounters = append(groupCounters, v6GroupCounter)
		default:
			return fmt.Errorf("at least one of IPv4 or IPv6 should be enabled")
		}
	}
	agentCtx.proxier = proxier
	agentCtx.v4Enabled = v4Enabled
	agentCtx.v6Enabled = v6Enabled

	if features.DefaultFeatureGate.Enabled(features.AntreaProxy) {
		go agentContext.proxier.GetProxyProvider().Run(stopCh)

		// If AntreaProxy is configured to proxy all Service traffic, we need to wait for it to sync at least once
		// before moving forward. Components that rely on Service availability should run after it, otherwise accessing
		// Service would fail.
		if agentContext.options.Config.AntreaProxy.ProxyAll {
			klog.InfoS("Waiting for AntreaProxy to be ready")
			if err := wait.PollUntil(time.Second, func() (bool, error) {
				klog.V(2).InfoS("Checking if AntreaProxy is ready")
				return agentContext.proxier.GetProxyProvider().SyncedOnce(), nil
			}, stopCh); err != nil {
				return fmt.Errorf("error when waiting for AntreaProxy to be ready: %v", err)
			}
			klog.InfoS("AntreaProxy is ready")
		}
	}
	return nil
}
