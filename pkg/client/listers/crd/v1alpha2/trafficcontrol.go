// Copyright 2022 Antrea Authors
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

// Code generated by lister-gen. DO NOT EDIT.

package v1alpha2

import (
	v1alpha2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// TrafficControlLister helps list TrafficControls.
// All objects returned here must be treated as read-only.
type TrafficControlLister interface {
	// List lists all TrafficControls in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha2.TrafficControl, err error)
	// Get retrieves the TrafficControl from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1alpha2.TrafficControl, error)
	TrafficControlListerExpansion
}

// trafficControlLister implements the TrafficControlLister interface.
type trafficControlLister struct {
	indexer cache.Indexer
}

// NewTrafficControlLister returns a new TrafficControlLister.
func NewTrafficControlLister(indexer cache.Indexer) TrafficControlLister {
	return &trafficControlLister{indexer: indexer}
}

// List lists all TrafficControls in the indexer.
func (s *trafficControlLister) List(selector labels.Selector) (ret []*v1alpha2.TrafficControl, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha2.TrafficControl))
	})
	return ret, err
}

// Get retrieves the TrafficControl from the index for a given name.
func (s *trafficControlLister) Get(name string) (*v1alpha2.TrafficControl, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1alpha2.Resource("trafficcontrol"), name)
	}
	return obj.(*v1alpha2.TrafficControl), nil
}
