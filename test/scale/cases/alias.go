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

package cases

import (
	"context"
	"fmt"
	"net/url"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"

	"antrea.io/antrea/test/scale/types"
)

type (
	Context  = context.Context
	TestData = types.TestData
	TestCase = types.TestCase
	RunFunc  = types.RunFunc
)

var (
	chain  = func(name string, testCases ...TestCase) TestCase { return types.NewChain(name).Includes(testCases...) }
	repeat = func(name string, times int, testCase TestCase) TestCase {
		return types.NewRepeat(name, times).Includes(testCase)
	}
	fan = func(name string, testCases ...TestCase) TestCase { return types.NewFan(name).Includes(testCases...) }
	do  = func(name string, runFunc RunFunc) TestCase { return types.NewUnary(name, false, runFunc) }
)

func execURL(clientPod *corev1.Pod, kClient kubernetes.Interface, peerIP string) *url.URL {
	return kClient.CoreV1().RESTClient().Post().
		Namespace(clientPod.Namespace).
		Resource("pods").
		Name(clientPod.Name).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Command: []string{"/bin/sh", "-c", fmt.Sprintf("nc -vz -w 1 %s 80", peerIP)},
			Stdin:   false,
			Stdout:  true,
			Stderr:  true,
			TTY:     false,
		}, scheme.ParameterCodec).URL()
}
