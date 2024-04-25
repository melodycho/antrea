// Copyright 2024 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by informer-gen. DO NOT EDIT.

package v1beta1

import (
	internalinterfaces "antrea.io/antrea/pkg/client/informers/externalversions/internalinterfaces"
)

// Interface provides access to all the informers in this group version.
type Interface interface {
	// AntreaAgentInfos returns a AntreaAgentInfoInformer.
	AntreaAgentInfos() AntreaAgentInfoInformer
	// AntreaControllerInfos returns a AntreaControllerInfoInformer.
	AntreaControllerInfos() AntreaControllerInfoInformer
	// ClusterGroups returns a ClusterGroupInformer.
	ClusterGroups() ClusterGroupInformer
	// ClusterNetworkPolicies returns a ClusterNetworkPolicyInformer.
	ClusterNetworkPolicies() ClusterNetworkPolicyInformer
	// Egresses returns a EgressInformer.
	Egresses() EgressInformer
	// ExternalIPPools returns a ExternalIPPoolInformer.
	ExternalIPPools() ExternalIPPoolInformer
	// Groups returns a GroupInformer.
	Groups() GroupInformer
	// IPPools returns a IPPoolInformer.
	IPPools() IPPoolInformer
	// NetworkPolicies returns a NetworkPolicyInformer.
	NetworkPolicies() NetworkPolicyInformer
	// Tiers returns a TierInformer.
	Tiers() TierInformer
	// Traceflows returns a TraceflowInformer.
	Traceflows() TraceflowInformer
}

type version struct {
	factory          internalinterfaces.SharedInformerFactory
	namespace        string
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// New returns a new Interface.
func New(f internalinterfaces.SharedInformerFactory, namespace string, tweakListOptions internalinterfaces.TweakListOptionsFunc) Interface {
	return &version{factory: f, namespace: namespace, tweakListOptions: tweakListOptions}
}

// AntreaAgentInfos returns a AntreaAgentInfoInformer.
func (v *version) AntreaAgentInfos() AntreaAgentInfoInformer {
	return &antreaAgentInfoInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// AntreaControllerInfos returns a AntreaControllerInfoInformer.
func (v *version) AntreaControllerInfos() AntreaControllerInfoInformer {
	return &antreaControllerInfoInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// ClusterGroups returns a ClusterGroupInformer.
func (v *version) ClusterGroups() ClusterGroupInformer {
	return &clusterGroupInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// ClusterNetworkPolicies returns a ClusterNetworkPolicyInformer.
func (v *version) ClusterNetworkPolicies() ClusterNetworkPolicyInformer {
	return &clusterNetworkPolicyInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// Egresses returns a EgressInformer.
func (v *version) Egresses() EgressInformer {
	return &egressInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// ExternalIPPools returns a ExternalIPPoolInformer.
func (v *version) ExternalIPPools() ExternalIPPoolInformer {
	return &externalIPPoolInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// Groups returns a GroupInformer.
func (v *version) Groups() GroupInformer {
	return &groupInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// IPPools returns a IPPoolInformer.
func (v *version) IPPools() IPPoolInformer {
	return &iPPoolInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// NetworkPolicies returns a NetworkPolicyInformer.
func (v *version) NetworkPolicies() NetworkPolicyInformer {
	return &networkPolicyInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// Tiers returns a TierInformer.
func (v *version) Tiers() TierInformer {
	return &tierInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// Traceflows returns a TraceflowInformer.
func (v *version) Traceflows() TraceflowInformer {
	return &traceflowInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}
