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
	v1 "k8s.io/api/core/v1"
	"time"

	appv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	antreaapis "antrea.io/antrea/pkg/apis"
	"antrea.io/antrea/test/performance/config"
	"antrea.io/antrea/test/performance/framework/client_pod"
	"antrea.io/antrea/test/performance/utils"
)

func init() {
	RegisterFunc("ScaleRestartAgent", ScaleRestartAgent)
	RegisterFunc("RestartController", RestartController)
	RegisterFunc("RestartOVSContainer", RestartOVSContainer)
}

func ScaleRestartAgent(ctx context.Context, ch chan time.Duration, data *ScaleData) (res ScaleResult) {
	var err error
	// start := time.Now()
	defer func() {
		// ch <- time.Since(start)
		res.err = err
	}()
	res.scaleNum = data.nodesNum

	prober := fmt.Sprintf("%s:%d", "", antreaapis.AntreaAgentAPIPort)

	expectPodNum := data.nodesNum - data.simulateNodesNum
	_, err = client_pod.Update(ctx, data.kubernetesClientSet, client_pod.ClientPodsNamespace, client_pod.ScaleTestClientDaemonSet, []string{prober}, client_pod.ScaleAgentProbeContainerName, expectPodNum)
	if err != nil {
		return
	}

	err = data.kubernetesClientSet.CoreV1().Pods(metav1.NamespaceSystem).
		DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: "app=antrea,component=antrea-agent"})
	if err != nil {
		return
	}

	err = wait.PollImmediateUntil(config.WaitInterval, func() (bool, error) {
		var ds *appv1.DaemonSet
		if err := utils.DefaultRetry(func() error {
			var err error
			ds, err = data.kubernetesClientSet.
				AppsV1().DaemonSets(metav1.NamespaceSystem).
				Get(ctx, "antrea-agent", metav1.GetOptions{})
			return err
		}); err != nil {
			return false, err
		}
		klog.V(2).InfoS("Check agent restart", "DesiredNumberScheduled", ds.Status.DesiredNumberScheduled,
			"NumberAvailable", ds.Status.NumberAvailable)
		return ds.Status.DesiredNumberScheduled == ds.Status.NumberAvailable, nil
	}, ctx.Done())

	startTime := time.Now().UnixNano()
	go func() {
		podList, err := data.kubernetesClientSet.CoreV1().Pods(client_pod.ClientPodsNamespace).List(ctx, metav1.ListOptions{LabelSelector: client_pod.ScaleClientPodTemplateName})
		if err != nil {
			err = fmt.Errorf("error when getting scale test client pods: %w", err)
			return
		}
		for _, pod := range podList.Items {
			key := "to up"
			if err := utils.FetchTimestampFromLog(ctx, data.kubernetesClientSet, pod.Namespace, pod.Name, client_pod.ScaleAgentProbeContainerName, ch, startTime, key); err != nil {
				klog.ErrorS(err, "Checking antrea agent restart time error", "ClientPodName", pod.Name)
			}
		}
	}()

	res.actualCheckNum = expectPodNum
	return
}

func getControllerPod(data *ScaleData, ctx context.Context) (*v1.Pod, error) {
	controllerPods, err := data.kubernetesClientSet.CoreV1().Pods(metav1.NamespaceSystem).List(ctx, metav1.ListOptions{LabelSelector: "app=antrea,component=antrea-controller"})
	if err != nil {
		return nil, err
	}
	if len(controllerPods.Items) < 1 {
		return nil, fmt.Errorf("no Antrea Controller Pods")
	}
	return &controllerPods.Items[0], nil
}

func RestartController(ctx context.Context, ch chan time.Duration, data *ScaleData) (res ScaleResult) {
	var err error
	res.scaleNum = 1
	defer func() {
		res.err = err
	}()

	prober := fmt.Sprintf("%s:%d", "", antreaapis.AntreaControllerAPIPort)

	expectPodNum := data.nodesNum - data.simulateNodesNum
	_, err = client_pod.Update(ctx, data.kubernetesClientSet, client_pod.ClientPodsNamespace, client_pod.ScaleTestClientDaemonSet, []string{prober}, client_pod.ScaleControllerProbeContainerName, expectPodNum)
	if err != nil {
		return
	}

	err = data.kubernetesClientSet.CoreV1().Pods(metav1.NamespaceSystem).
		DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: "app=antrea,component=antrea-controller"})
	if err != nil {
		return
	}
	startTime := time.Now().UnixNano()

	err = wait.PollImmediateUntil(config.WaitInterval, func() (bool, error) {
		var dp *appv1.Deployment
		if err := utils.DefaultRetry(func() error {
			var err error
			dp, err = data.kubernetesClientSet.AppsV1().Deployments(metav1.NamespaceSystem).Get(ctx, "antrea-controller", metav1.GetOptions{})
			return err
		}); err != nil {
			return false, err
		}
		return dp.Status.ObservedGeneration == dp.Generation && dp.Status.ReadyReplicas == *dp.Spec.Replicas, nil
	}, ctx.Done())

	go func() {
		controllerPod, err := getControllerPod(data, ctx)
		podList, err := data.kubernetesClientSet.CoreV1().Pods(client_pod.ClientPodsNamespace).List(ctx, metav1.ListOptions{LabelSelector: client_pod.ScaleClientPodTemplateName})
		if err != nil {
			err = fmt.Errorf("error when getting scale test client pods: %w", err)
			return
		}
		for _, pod := range podList.Items {
			if pod.Spec.NodeName == controllerPod.Spec.NodeName {
				key := "to up"
				if err := utils.FetchTimestampFromLog(ctx, data.kubernetesClientSet, pod.Namespace, pod.Name, client_pod.ScaleControllerProbeContainerName, ch, startTime, key); err != nil {
					klog.ErrorS(err, "Checking antrea controller restart time error", "ClientPodName", pod.Name)
				}
				break
			}
		}
	}()

	res.actualCheckNum = 1
	return
}

func RestartOVSContainer(ctx context.Context, ch chan time.Duration, data *ScaleData) ScaleResult {
	return ScaleRestartAgent(ctx, ch, data)
}
