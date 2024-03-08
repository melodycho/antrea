// Copyright 2021 Antrea Authors
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

package framework

import (
	"context"
	"fmt"
	"time"

	"k8s.io/klog/v2"

	"antrea.io/antrea/test/performance/framework/networkpolicy"
)

func init() {
	RegisterFunc("ScaleNetworkPolicy", ScaleNetworkPolicy)
}

func ScaleNetworkPolicy(ctx context.Context, ch chan time.Duration, data *ScaleData) (res ScaleResult) {
	checkCount, err := networkpolicy.ScaleUp(ctx, data.kubernetesClientSet, data.namespaces,
		data.Specification.NpNumPerNs, ch)
	if err != nil {
		res.err = fmt.Errorf("scale up NetworkPolicies error: %v", err)
		return
	}
	res.scaleNum = len(data.namespaces) * data.Specification.NpNumPerNs
	res.actualCheckNum = checkCount

	defer func() {
		for {
			if len(ch) >= res.actualCheckNum {
				break
			}
			klog.InfoS("Waiting the check goroutine finish", "actualCheckNum", res.actualCheckNum, "channel length", len(ch))
			time.Sleep(time.Second)
		}
		if err := networkpolicy.ScaleDown(ctx, data.namespaces, data.kubernetesClientSet); err != nil {
			klog.ErrorS(err, "Scale down NetworkPolicies failed")
		}
	}()

	res.actualCheckNum = checkCount
	return
}
