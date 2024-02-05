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
	"antrea.io/antrea/test/performance/framework/client_pod"
	"context"
	"fmt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"time"

	"k8s.io/klog/v2"

	"antrea.io/antrea/test/performance/framework/networkpolicy"
)

func init() {
	RegisterFunc("ScaleNetworkPolicy", ScaleNetworkPolicy)
}

func ScaleNetworkPolicy(ctx context.Context, ch chan time.Duration, data *ScaleData) (res ScaleResult) {
	clientPods, err := data.kubernetesClientSet.CoreV1().Pods(client_pod.ClientPodsNamespace).List(ctx, metav1.ListOptions{LabelSelector: client_pod.ScaleClientPodTemplateName})
	if err != nil {
		res.err = fmt.Errorf("list client Pod error: %+v", err)
		return
	}
	checkCount, scaleNum, err := networkpolicy.ScaleUp(ctx, data.kubeconfig, data.kubernetesClientSet, data.namespaces,
		data.Specification.NpNumPerNs, clientPods.Items, data.Specification.IPv6, data.maxCheckNum, ch)
	if err != nil {
		res.err = fmt.Errorf("scale up NetworkPolicies error: %v", err)
		return
	}
	res.scaleNum = scaleNum

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

	// maxNPCheckedCount := data.nodesNum
	//
	// start := time.Now()
	// for i, np := range nps {
	// 	if utils.CheckTimeout(start, data.checkTimeout) || i > maxNPCheckedCount {
	// 		klog.InfoS("NetworkPolicies check deadline exceeded", "count", i)
	// 		break
	// 	}
	//
	// 	// Check connection of Pods in NetworkPolicies, workload Pods
	// 	fromPod, ip, err := networkpolicy.SelectConnectPod(ctx, data.kubernetesClientSet, np.Namespace, &nps[i])
	// 	if err != nil || fromPod == nil || ip == "" {
	// 		continue
	// 	}
	// 	if err := PingIP(ctx, ch, data.kubeconfig, data.kubernetesClientSet, fromPod.Namespace, fromPod.Name, ip); err != nil {
	// 		return fmt.Errorf("the connection should be success, NetworkPolicyName: %s, FromPod: %s, ToPod: %s",
	// 			np.Name, fromPod.Name, ip)
	// 	}
	//
	// 	// Check isolation of Pods in NetworkPolicies, client Pods to workload Pods
	// 	fromPod, ip, err = networkpolicy.SelectIsoPod(ctx, data.kubernetesClientSet, np.Namespace, np, data.clientPods)
	// 	if err != nil || fromPod == nil || ip == "" {
	// 		continue
	// 	}
	// 	if err := PingIP(ctx, ch, data.kubeconfig, data.kubernetesClientSet, fromPod.Namespace, fromPod.Name, ip); err == nil {
	// 		return fmt.Errorf("the connection should not be success, NetworkPolicyName: %s, FromPod: %s, ToPodIP: %s", np.Name, fromPod.Name, ip)
	// 	}
	// 	klog.InfoS("Checked networkPolicy", "Name", np.Name, "Namespace", np.Namespace, "count", i, "maxNum", maxNPCheckedCount)
	// }
	res.actualCheckNum = checkCount
	return
}
