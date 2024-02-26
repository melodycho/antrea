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
//

// Code generated by MockGen. DO NOT EDIT.
// Source: antrea.io/antrea/pkg/controller/networkpolicy (interfaces: EndpointQuerier)
//
// Generated by this command:
//
//	mockgen -copyright_file hack/boilerplate/license_header.raw.txt -destination pkg/controller/networkpolicy/testing/mock_networkpolicy.go -package testing antrea.io/antrea/pkg/controller/networkpolicy EndpointQuerier
//
// Package testing is a generated GoMock package.
package testing

import (
	reflect "reflect"

	types "antrea.io/antrea/pkg/controller/types"
	gomock "go.uber.org/mock/gomock"
)

// MockEndpointQuerier is a mock of EndpointQuerier interface.
type MockEndpointQuerier struct {
	ctrl     *gomock.Controller
	recorder *MockEndpointQuerierMockRecorder
}

// MockEndpointQuerierMockRecorder is the mock recorder for MockEndpointQuerier.
type MockEndpointQuerierMockRecorder struct {
	mock *MockEndpointQuerier
}

// NewMockEndpointQuerier creates a new mock instance.
func NewMockEndpointQuerier(ctrl *gomock.Controller) *MockEndpointQuerier {
	mock := &MockEndpointQuerier{ctrl: ctrl}
	mock.recorder = &MockEndpointQuerierMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockEndpointQuerier) EXPECT() *MockEndpointQuerierMockRecorder {
	return m.recorder
}

// QueryNetworkPolicyRules mocks base method.
func (m *MockEndpointQuerier) QueryNetworkPolicyRules(arg0, arg1 string) (*types.EndpointNetworkPolicyRules, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "QueryNetworkPolicyRules", arg0, arg1)
	ret0, _ := ret[0].(*types.EndpointNetworkPolicyRules)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// QueryNetworkPolicyRules indicates an expected call of QueryNetworkPolicyRules.
func (mr *MockEndpointQuerierMockRecorder) QueryNetworkPolicyRules(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "QueryNetworkPolicyRules", reflect.TypeOf((*MockEndpointQuerier)(nil).QueryNetworkPolicyRules), arg0, arg1)
}
