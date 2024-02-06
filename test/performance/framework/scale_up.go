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

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/antctl/runtime"
	"antrea.io/antrea/test/performance/config"
	"antrea.io/antrea/test/performance/framework/client_pod"
	"antrea.io/antrea/test/performance/framework/namespace"
	"antrea.io/antrea/test/performance/utils"
)

var (
	// RealNodeAffinity is used to make a Pod not to be scheduled to a simulated node.
	RealNodeAffinity = corev1.Affinity{
		NodeAffinity: &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{
					{
						MatchExpressions: []corev1.NodeSelectorRequirement{
							{
								Key:      client_pod.SimulatorNodeLabelKey,
								Operator: corev1.NodeSelectorOpNotIn,
								Values:   []string{client_pod.SimulatorNodeLabelValue},
							},
						},
					},
				},
			},
		},
	}

	// SimulateAffinity is used to make a Pod to be scheduled to a simulated node.
	SimulateAffinity = corev1.Affinity{
		NodeAffinity: &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{
					{
						MatchExpressions: []corev1.NodeSelectorRequirement{
							{
								Key:      client_pod.SimulatorNodeLabelKey,
								Operator: corev1.NodeSelectorOpIn,
								Values:   []string{client_pod.SimulatorNodeLabelValue},
							},
						},
					},
				},
			},
		},
	}

	// SimulateToleration marks a Pod able to run on a simulate node.
	SimulateToleration = corev1.Toleration{
		Key:      client_pod.SimulatorTaintKey,
		Operator: corev1.TolerationOpEqual,
		Value:    client_pod.SimulatorTaintValue,
		Effect:   corev1.TaintEffectNoExecute,
	}

	// MasterToleration marks a Pod able to run on the master node.
	MasterToleration = corev1.Toleration{
		Key:      "node-role.kubernetes.io/master",
		Operator: corev1.TolerationOpExists,
		Effect:   corev1.TaintEffectNoSchedule,
	}

	// clientPodTemplate is the PodTemplateSpec of a scale test client Pod.
	clientPodTemplate = corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{client_pod.ScaleClientPodTemplateName: ""}},
		Spec: corev1.PodSpec{
			Affinity:    &RealNodeAffinity,
			Tolerations: []corev1.Toleration{MasterToleration},
			Containers: []corev1.Container{
				{
					Name:            client_pod.ScaleClientContainerName,
					Image:           "busybox",
					Command:         []string{"nc", "-lk", "-p", "80"},
					ImagePullPolicy: corev1.PullIfNotPresent,
				},
			},
		},
	}
)

// ScaleData implemented the TestData interface and it provides clients for helping running
// scale test cases.
type ScaleData struct {
	kubernetesClientSet kubernetes.Interface
	kubeconfig          *rest.Config
	// clientPods          []corev1.Pod
	namespaces       []string
	Specification    *config.ScaleList
	nodesNum         int
	maxCheckNum      int
	simulateNodesNum int
	podsNumPerNs     int
	checkTimeout     time.Duration
}

func createTestPodClients(ctx context.Context, kClient kubernetes.Interface, ns string) error {
	if _, err := kClient.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{}); errors.IsNotFound(err) {
		if _, err := kClient.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, metav1.CreateOptions{}); err != nil {
			return err
		}
	}

	if err := utils.DefaultRetry(func() error {
		_, err := kClient.AppsV1().DaemonSets(ns).Create(ctx, &appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      client_pod.ScaleTestClientDaemonSet,
				Namespace: ns,
				Labels:    map[string]string{client_pod.ScaleClientPodTemplateName: ""},
			},
			Spec: appsv1.DaemonSetSpec{
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{client_pod.ScaleClientPodTemplateName: ""}},
				Template: clientPodTemplate,
			},
		}, metav1.CreateOptions{})
		return err
	}); err != nil {
		return err
	}
	if err := wait.PollImmediateUntil(config.WaitInterval, func() (bool, error) {
		ds, err := kClient.AppsV1().DaemonSets(ns).Get(ctx, client_pod.ScaleTestClientDaemonSet, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		return ds.Status.DesiredNumberScheduled == ds.Status.NumberReady, nil
	}, ctx.Done()); err != nil {
		return fmt.Errorf("error when waiting scale test clients to be ready: %w", err)
	}
	if err := wait.PollImmediateUntil(config.WaitInterval, func() (bool, error) {
		podList, err := kClient.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: client_pod.ScaleClientPodTemplateName})
		if err != nil {
			return false, nil
		}
		for _, pod := range podList.Items {
			if pod.Status.PodIP == "" {
				return false, nil
			}
		}
		return true, nil
	}, ctx.Done()); err != nil {
		return fmt.Errorf("error when waiting scale test clients to get IP: %w", err)
	}
	return nil
}

func checkNodeStatus(node corev1.Node) bool {
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func validScaleSpecification(c *config.ScaleConfiguration) error {
	if c.NpNumPerNs*2 > c.PodsNumPerNs {
		return fmt.Errorf("networkPolicy quantity is too larger than 1/2 workload Pods quantity, scale may fail")
	}
	if c.SvcNumPerNs*2 > c.PodsNumPerNs {
		return fmt.Errorf("service quantity is too larger than 1/2 workload Pods quantity, scale may fail")
	}
	return nil
}

func ScaleUp(ctx context.Context, kubeConfigPath, scaleConfigPath string) (*ScaleData, error) {
	var td ScaleData
	scaleConfig, err := config.ParseConfigs(scaleConfigPath)
	if err != nil {
		return nil, err
	}
	klog.InfoS("Scale config", "scaleConfig", scaleConfig)
	td.Specification = scaleConfig

	if err := validScaleSpecification(&scaleConfig.ScaleConfiguration); err != nil {
		return nil, err
	}

	kubeConfig, err := runtime.ResolveKubeconfig(kubeConfigPath)
	if err != nil {
		return nil, fmt.Errorf("error when retrieving incluster kubeconfig: %w", err)
	}
	td.kubeconfig = kubeConfig
	kClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("error when creating kubernetes client: %w", err)
	}

	controlPlaneNodes, err := kClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: "node-role.kubernetes.io/control-plane="})
	if err != nil {
		return nil, fmt.Errorf("error when getting Nodes in the cluster: %w", err)
	}
	masterNodes, err := kClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: "node-role.kubernetes.io/master="})
	if err != nil {
		return nil, fmt.Errorf("error when getting Nodes in the cluster: %w", err)
	}
	if len(masterNodes.Items) == 0 && len(controlPlaneNodes.Items) == 0 {
		return nil, fmt.Errorf("can not find a master/control-plane Node in the cluster")
	}

	td.kubernetesClientSet = kClient

	nodes, err := kClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("error when getting all Nodes: %w", err)
	}

	// Count simulate nodes.
	simulateNodesNum := 0
	for _, node := range nodes.Items {
		if v, ok := node.Labels[client_pod.SimulatorNodeLabelKey]; ok && v == client_pod.SimulatorNodeLabelValue {
			simulateNodesNum += 1
		}
		if !checkNodeStatus(node) {
			return nil, fmt.Errorf("check scale Node(%s) not Ready", node.Name)
		}
	}
	td.nodesNum = len(nodes.Items)
	td.podsNumPerNs = scaleConfig.PodsNumPerNs
	td.simulateNodesNum = simulateNodesNum
	td.checkTimeout = time.Duration(scaleConfig.CheckTimeout) * time.Minute

	expectNsNum := td.Specification.NamespaceNum
	klog.Infof("Preflight checks and clean up")
	if !scaleConfig.SkipDeployWorkload {
		if err := td.ScaleDown(ctx); err != nil {
			return nil, fmt.Errorf("deleting scale test namespaces error: %v", err)
		}

		nss, err := namespace.ScaleUp(ctx, td.kubernetesClientSet, client_pod.ScaleTestNamespaceBase, expectNsNum)
		if err != nil {
			return nil, fmt.Errorf("scale up namespaces error: %v", err)
		}
		td.namespaces = nss

		klog.Infof("Creating the scale test client DaemonSet")
		if err := createTestPodClients(ctx, kClient, client_pod.ClientPodsNamespace); err != nil {
			return nil, err
		}

	} else {
		td.namespaces, err = namespace.SelectNamespaces(ctx, kClient, client_pod.ScaleTestNamespacePrefix)
		if err != nil {
			return nil, err
		}
	}
	klog.Infof("Checking scale test client DaemonSet")
	expectClientNum := td.nodesNum - td.simulateNodesNum
	err = wait.PollImmediateUntil(config.WaitInterval, func() (bool, error) {
		podList, err := kClient.CoreV1().Pods(client_pod.ClientPodsNamespace).List(ctx, metav1.ListOptions{LabelSelector: client_pod.ScaleClientPodTemplateName})
		if err != nil {
			return false, fmt.Errorf("error when getting scale test client pods: %w", err)
		}
		if len(podList.Items) == expectClientNum {
			return true, nil
		}
		klog.InfoS("Waiting test client DaemonSet Pods ready", "podsNum", len(podList.Items),
			"expectClientNum", expectClientNum)
		return false, nil
	}, ctx.Done())
	if err != nil {
		return nil, err
	}

	return &td, nil
}
