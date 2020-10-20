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
	"bytes"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/klog"

	"antrea.io/antrea/test/scale/types"
	"antrea.io/antrea/test/scale/utils"
)

const (
	workloadPodLabelKey   = "antrea-scale-workload-pod"
	workloadPodLabelValue = ""
)

var (
	workloadPodContainer = corev1.Container{
		Name:            "busybox",
		Image:           "busybox",
		ImagePullPolicy: corev1.PullIfNotPresent,
		Command:         []string{"httpd", "-f"},
	}
)

func workloadPodTemplate(podName string, labels map[string]string, onRealNode bool) *corev1.Pod {
	var affinity *corev1.Affinity
	var tolerations []corev1.Toleration
	if onRealNode {
		affinity = &types.RealNodeAffinity
		tolerations = append(tolerations, types.MasterToleration)
	} else {
		affinity = &types.SimulateAffinity
		tolerations = append(tolerations, types.SimulateToleration)
	}
	labels[workloadPodLabelKey] = workloadPodLabelValue
	labels["name"] = podName
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: types.ScaleTestNamespace,
			Labels:    labels,
		},
		Spec: corev1.PodSpec{
			Affinity:      affinity,
			Containers:    []corev1.Container{workloadPodContainer},
			RestartPolicy: corev1.RestartPolicyNever,
			Tolerations:   tolerations,
		},
	}
}

func newWorkloadPod(podName string, onRealNode bool) *corev1.Pod {
	labels := map[string]string{
		types.AppLabelKey: types.AppLabelValue,
	}
	for len(labels) == 1 { // must generate at least one label.
		for _, l := range types.LabelCandidates {
			if genRandInt(math.MaxInt64)%10 < 8 {
				labels[l] = ""
			}
		}
	}
	if onRealNode {
		labels[types.PodOnRealNodeLabelKey] = ""
	}
	return workloadPodTemplate(podName, labels, onRealNode)
}

func TestCasePodCreation() TestCase {
	return chain("Creating workload Pods",
		do("Creating workload Pods", func(ctx Context, data TestData) error {
			for i := 0; i < data.PodNumber(); i++ {
				podName := fmt.Sprintf("antrea-scale-test-pod-%s", uuid.New().String())
				onRealNode := (i % data.NodeNumber()) >= data.SimulateNodeNumber()
				pod := newWorkloadPod(podName, onRealNode)
				if _, err := data.KubernetesClientSet().CoreV1().
					Pods(types.ScaleTestNamespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
					return err
				}
			}
			return nil
		}),
		chain("Checking workload Pods creation",
			do("Waiting scale workload Pods to be ready", func(ctx Context, data TestData) error {
				return wait.PollUntil(2*time.Second, func() (bool, error) {
					podsResult, err := data.KubernetesClientSet().
						CoreV1().Pods(types.ScaleTestNamespace).
						List(ctx, metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", types.AppLabelKey, types.AppLabelValue)})
					if err != nil {
						klog.Warningf("Error when listing Pods: %v", err)
					} else {
						var count int
						for _, pod := range podsResult.Items {
							if pod.Status.Phase == corev1.PodRunning && pod.Status.PodIP != "" {
								count += 1
							}
						}
						return count >= data.PodNumber(), nil
					}
					return false, nil
				}, ctx.Done())
			}),
			do("Checking if all pods can be accessed", func(ctx Context, data TestData) error {
				podList, err := data.KubernetesClientSet().CoreV1().Pods(types.ScaleTestNamespace).List(ctx, metav1.ListOptions{LabelSelector: fmt.Sprintf("%s", types.PodOnRealNodeLabelKey)})
				if err != nil {
					return err
				}
				gErr, _ := errgroup.WithContext(ctx)
				for i := range data.TestClientPods() {
					clientPod := data.TestClientPods()[i]
					gErr.Go(func() error {
						for _, pod := range podList.Items {
							exec, err := remotecommand.NewSPDYExecutor(data.Kubeconfig(), "POST", execURL(&clientPod, data.KubernetesClientSet(), pod.Status.PodIP))
							if err != nil {
								return fmt.Errorf("error when creating SPDY executor: %w", err)
							}
							var stdout, stderr bytes.Buffer
							if err := exec.Stream(remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}); err != nil {
								return fmt.Errorf("error when executing commands on service client Pod: %w, stdout: %s, stderr: %s", err, stdout.String(), stderr.String())
							}
						}
						return nil
					})
				}
				return nil
			}),
		),
	)
}

func TestCasePodChurn(podNumber int) TestCase {
	labelSelector := fmt.Sprintf("%s=%s", types.AppLabelKey, types.AppLabelValue)
	return chain("Deleting workload Pods",
		do("Deleting workload Pods", func(ctx Context, data TestData) error {
			return utils.DefaultRetry(func() error {
				return data.KubernetesClientSet().CoreV1().
					Pods(types.ScaleTestNamespace).
					DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: labelSelector})
			})
		}),
		do("Waiting scale workload Pods to be destroyed", func(ctx Context, data TestData) error {
			return wait.PollUntil(2*time.Second, func() (bool, error) {
				podsResult, err := data.KubernetesClientSet().
					CoreV1().Pods(types.ScaleTestNamespace).
					List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
				if err != nil {
					klog.Warningf("Error when listing Pods: %v", err)
					return false, err
				}
				return len(podsResult.Items) == 0, nil
			}, ctx.Done())
		}),
	)
}
