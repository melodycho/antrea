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
	"antrea.io/antrea/test/performance/framework/client_pod"
	"context"
	"fmt"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	"antrea.io/antrea/test/performance/framework/service"
)

func init() {
	RegisterFunc("ScaleService", ScaleService)
	RegisterFunc("ScaleServiceDemo", ScaleServiceDemo)
}

func ScaleService(ctx context.Context, ch chan time.Duration, data *ScaleData) (res ScaleResult) {
	var err error

	clientPods, err := data.kubernetesClientSet.CoreV1().Pods(client_pod.ClientPodsNamespace).List(ctx, metav1.ListOptions{LabelSelector: client_pod.ScaleClientPodTemplateName})
	if err != nil {
		res.err = fmt.Errorf("list client Pod error: %+v", err)
		return
	}

	klog.InfoS("client Pods", "Pod num", len(clientPods.Items))

	maxSvcCheckedCount := data.nodesNum
	svcs, actualCheckNum, err := service.ScaleUp(ctx, data.kubeconfig, data.kubernetesClientSet, data.namespaces, data.Specification.SvcNumPerNs, data.Specification.IPv6, maxSvcCheckedCount, ch, clientPods.Items)
	if err != nil {
		err = fmt.Errorf("scale up services error: %v", err)
		return
	}
	res.scaleNum = len(svcs)

	defer func() {
		res.err = err
		for {
			if len(ch) == res.actualCheckNum {
				break
			}
			klog.InfoS("Waiting the check goroutine finish")
			time.Sleep(time.Second)
		}
		if err = service.ScaleDown(ctx, svcs, data.kubernetesClientSet); err != nil {
			klog.ErrorS(err, "Scale down Services failed")
		}
	}()

	// start := time.Now()
	// actualCheckNum := 0
	// for i := range svcs {
	// 	svcCheckStart := time.Now()
	// 	if utils.CheckTimeout(start, data.checkTimeout) || i > maxSvcCheckedCount {
	// 		klog.InfoS("Services check deadline exceeded", "count", i)
	// 		break
	// 	}
	// 	k := int(utils.GenRandInt()) % len(data.clientPods)
	// 	clientPod := data.clientPods[k]
	// 	svc := svcs[i]
	// 	if err = utils.PingIP(ctx, data.kubeconfig, data.kubernetesClientSet, clientPod.Namespace, clientPod.Name, svc.IP); err != nil {
	// 		klog.ErrorS(err, "Check readiness of service error", "ClientPodName", clientPod.Name, "svc", svc)
	// 		return
	// 	}
	// 	ch <- time.Since(svcCheckStart)
	// 	actualCheckNum++
	// 	klog.V(2).InfoS("Check service", "svc", svc, "Pod", clientPod.Name)
	// }
	res.actualCheckNum = actualCheckNum
	return
}

func ScaleServiceDemo(ctx context.Context, ch chan time.Duration, data *ScaleData) (res ScaleResult) {
	var err error
	defer func() {
		res.err = err
	}()
	start := time.Now()
	var nss *v1.NamespaceList
	nss, err = data.kubernetesClientSet.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return
	}
	klog.InfoS("List all test namespace", "namespacesNum", len(nss.Items))
	klog.V(2).InfoS("level 2 log")
	klog.V(1).InfoS("level 1 log")
	for i := 0; i < data.maxCheckNum; i++ {
		ch <- time.Since(start)
	}
	res.actualCheckNum = data.maxCheckNum
	return
}
