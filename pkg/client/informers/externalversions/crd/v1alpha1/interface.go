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

package v1alpha1

import (
	internalinterfaces "antrea.io/antrea/pkg/client/informers/externalversions/internalinterfaces"
)

// Interface provides access to all the informers in this group version.
type Interface interface {
	// ExternalNodes returns a ExternalNodeInformer.
	ExternalNodes() ExternalNodeInformer
	// NodeLatencyMonitors returns a NodeLatencyMonitorInformer.
	NodeLatencyMonitors() NodeLatencyMonitorInformer
	// SupportBundleCollections returns a SupportBundleCollectionInformer.
	SupportBundleCollections() SupportBundleCollectionInformer
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

// ExternalNodes returns a ExternalNodeInformer.
func (v *version) ExternalNodes() ExternalNodeInformer {
	return &externalNodeInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// NodeLatencyMonitors returns a NodeLatencyMonitorInformer.
func (v *version) NodeLatencyMonitors() NodeLatencyMonitorInformer {
	return &nodeLatencyMonitorInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// SupportBundleCollections returns a SupportBundleCollectionInformer.
func (v *version) SupportBundleCollections() SupportBundleCollectionInformer {
	return &supportBundleCollectionInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}
