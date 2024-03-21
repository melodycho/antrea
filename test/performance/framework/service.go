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

//goland:noinspection ALL
import (
	"context"
	"fmt"
	"time"

	"k8s.io/klog/v2"

	"antrea.io/antrea/test/performance/framework/service"
)

func init() {
	RegisterFunc("ScaleService", ScaleService)
}

func ScaleService(ctx context.Context, ch chan time.Duration, data *ScaleData) (res ScaleResult) {
	var err error

	var svcs []service.ServiceInfo
	svcs, err = service.ScaleUp(ctx, data.provider, data.controlPlaneNodes[0], data.kubernetesClientSet, data.namespaces, data.Specification.SvcNumPerNs, data.Specification.IPv6, ch)
	if err != nil {
		res.err = fmt.Errorf("scale up services error: %v", err)
		return
	}
	res.scaleNum = len(svcs)

	defer func() {
		res.err = err
		for {
			if len(ch) == res.scaleNum {
				break
			}
			klog.InfoS("Waiting the check goroutine finish")
			time.Sleep(time.Second)
		}
		if err = service.ScaleDown(ctx, svcs, data.kubernetesClientSet); err != nil {
			klog.ErrorS(err, "Scale down Services failed")
		}
	}()

	return
}
