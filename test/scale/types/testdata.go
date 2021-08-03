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

package types

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"strings"
	"time"

	promapi "github.com/prometheus/client_golang/api"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/antctl/runtime"
	"antrea.io/antrea/test/scale/utils"
)

const (
	// PodsPerNode defines average Pod number on each node (include simulate nodes).
	PodsPerNode = 1
	// ScaleTestNamespace is the Namespace of the scale test resources.
	ScaleTestNamespace = "antrea-scale-test-ns"

	AppLabelKey   = "app"
	AppLabelValue = "antrea-scale-test-workload"

	SimulatorNodeLabelKey   = "antrea/instance"
	SimulatorNodeLabelValue = "simulator"

	SimulatorTaintKey   = "simulator"
	SimulatorTaintValue = "true"

	PodOnRealNodeLabelKey = "realNode"

	ScaleClientContainerName   = "antrea-scale-test-client"
	ScaleClientPodTemplateName = "antrea-scale-test-client"
	ScaleTestClientDaemonSet   = "antrea-scale-test-client-daemonset"

	prometheusPort      = "8080"
	prometheusSvcName   = "prometheus-service"
	prometheusNamespace = "monitoring"

	ShortTimeWait = time.Minute
)

var (
	// LabelCandidates ...
	// label number:              1   2   3   4   5   6   7   8   9   10  11 12
	// pods cover percents:       80% 64% 51% 41% 32% 25% 20% 16% 13% 10% 8% 6%
	LabelCandidates = []string{"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"}

	// RealNodeAffinity is used to make a Pod not to be scheduled to a simulate node.
	RealNodeAffinity = corev1.Affinity{
		NodeAffinity: &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{
					{
						MatchExpressions: []corev1.NodeSelectorRequirement{
							{
								Key:      SimulatorNodeLabelKey,
								Operator: corev1.NodeSelectorOpNotIn,
								Values:   []string{SimulatorNodeLabelValue},
							},
						},
					},
				},
			},
		},
	}

	// SimulateAffinity is used to make a Pod to be scheduled to a simulate node.
	SimulateAffinity = corev1.Affinity{
		NodeAffinity: &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{
					{
						MatchExpressions: []corev1.NodeSelectorRequirement{
							{
								Key:      SimulatorNodeLabelKey,
								Operator: corev1.NodeSelectorOpIn,
								Values:   []string{SimulatorNodeLabelValue},
							},
						},
					},
				},
			},
		},
	}

	// SimulateToleration marks a Pod able to run on a simulate node.
	SimulateToleration = corev1.Toleration{
		Key:      SimulatorTaintKey,
		Operator: corev1.TolerationOpEqual,
		Value:    SimulatorTaintValue,
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
		ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{ScaleClientPodTemplateName: ""}},
		Spec: corev1.PodSpec{
			Affinity:    &RealNodeAffinity,
			Tolerations: []corev1.Toleration{MasterToleration},
			Containers: []corev1.Container{
				{
					Name:            ScaleClientContainerName,
					Image:           "busybox",
					Command:         []string{"nc", "-lk", "-p", "80"},
					ImagePullPolicy: corev1.PullIfNotPresent,
				},
			},
		},
	}
)

// PickLabels random select specific number of labels, if realNode is true, then no simulate node
// will be selected. By selecting different number of labels, we can control the size of the
// portion of the Pods we selected.
func PickLabels(num int, realNode bool) map[string]string {
	rand.Shuffle(len(LabelCandidates), func(i, j int) {
		LabelCandidates[i], LabelCandidates[j] = LabelCandidates[j], LabelCandidates[i]
	})
	result := make(map[string]string)
	for i := 0; i < num; i++ {
		result[LabelCandidates[i]] = ""
	}
	if len(result) == 0 { // re-pick if no labels is picked.
		return PickLabels(num, realNode)
	}
	if realNode {
		result[PodOnRealNodeLabelKey] = ""
	}
	return result
}

// testData implemented the TestData interface and it provides clients for helping running
// scale test cases.
type testData struct {
	prometheusClient    promapi.Client
	kubernetesClientSet kubernetes.Interface
	kubeconfig          *rest.Config
	clientPods          []corev1.Pod

	nodesNumber         int
	simulateNodesNumber int
}

func (t *testData) PrometheusClient() promapi.Client {
	return t.prometheusClient
}

func (t *testData) KubernetesClientSet() kubernetes.Interface {
	return t.kubernetesClientSet
}

func (t *testData) Kubeconfig() *rest.Config {
	return t.kubeconfig
}

func (t *testData) TestClientPods() []corev1.Pod {
	return t.clientPods
}

func (t *testData) PodNumber() int {
	return t.nodesNumber * PodsPerNode
}

func (t *testData) SimulateNodeNumber() int {
	return t.simulateNodesNumber
}

func (t *testData) NodeNumber() int {
	return t.nodesNumber
}

func createTestPodClients(ctx context.Context, kClient kubernetes.Interface) error {
	if err := utils.DefaultRetry(func() error {
		_, err := kClient.AppsV1().DaemonSets(ScaleTestNamespace).Create(ctx, &appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ScaleTestClientDaemonSet,
				Namespace: ScaleTestNamespace,
				Labels:    map[string]string{ScaleClientPodTemplateName: ""},
			},
			Spec: appsv1.DaemonSetSpec{
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{ScaleClientPodTemplateName: ""}},
				Template: clientPodTemplate,
			},
		}, metav1.CreateOptions{})
		return err
	}); err != nil {
		return err
	}
	if err := wait.PollImmediate(time.Second, ShortTimeWait, func() (bool, error) {
		ds, err := kClient.AppsV1().DaemonSets(ScaleTestNamespace).
			Get(ctx, ScaleTestClientDaemonSet, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		return ds.Status.DesiredNumberScheduled == ds.Status.NumberReady, nil
	}); err != nil {
		return fmt.Errorf("error when waiting scale test clients to be ready: %w", err)
	}
	if err := wait.PollImmediate(time.Second, ShortTimeWait, func() (bool, error) {
		podList, err := kClient.CoreV1().Pods(ScaleTestNamespace).
			List(ctx, metav1.ListOptions{LabelSelector: ScaleClientPodTemplateName})
		if err != nil {
			return false, nil
		}
		for _, pod := range podList.Items {
			if pod.Status.PodIP == "" {
				return false, nil
			}
		}
		return true, nil
	}); err != nil {
		return fmt.Errorf("error when waiting scale test clients to get IP: %w", err)
	}
	return nil
}

func NewTestData(ctx context.Context) (TestData, error) {
	var td testData
	kubeConfig, err := runtime.ResolveKubeconfig("")
	if err != nil {
		return nil, fmt.Errorf("error when retrieving incluster kubeconfig: %w", err)
	}
	td.kubeconfig = kubeConfig
	kClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("error when creating kubernetes client: %w", err)
	}
	masterNodes, err := kClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: `node-role.kubernetes.io/master`})
	if err != nil {
		return nil, fmt.Errorf("error when getting Nodes in the cluster: %w", err)
	}
	if len(masterNodes.Items) == 0 {
		return nil, fmt.Errorf("can not find a master Node in the cluster")
	}
	promSvc, err := kClient.CoreV1().Services(prometheusNamespace).Get(ctx, prometheusSvcName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error when retrieving prometheus service: %w", err)
	}
	ip := promSvc.Spec.ClusterIP
	if len(ip) == 0 {
		return nil, fmt.Errorf("error when getting prometheus service: ClusterIP is empty")
	}

	promURL := &url.URL{Scheme: "http", Host: net.JoinHostPort(ip, prometheusPort)}
	klog.Infof(".....................................................................")
	klog.InfoS("", "promURL", promURL)
	promClient, err := promapi.NewClient(promapi.Config{Address: promURL.String()})
	if err != nil {
		return nil, fmt.Errorf("error when creating prometheus client: %w", err)
	}
	td.kubernetesClientSet = kClient
	td.prometheusClient = promClient

	nodes, err := kClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("error when getting all Nodes: %w", err)
	}

	// Count simulate nodes.
	simulateNodesNumber := 0
	for _, node := range nodes.Items {
		if v, ok := node.Labels[SimulatorNodeLabelKey]; ok && v == SimulatorNodeLabelValue {
			simulateNodesNumber += 1
		}
	}
	td.nodesNumber = len(nodes.Items)
	td.simulateNodesNumber = simulateNodesNumber

	klog.Infof("Preflight checks and clean up")
	nsList, err := kClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, ns := range nsList.Items {
		if !strings.HasPrefix(ns.Name, "antrea-scale-test") {
			continue
		}
		if err := kClient.CoreV1().Namespaces().Delete(ctx, ns.Name, metav1.DeleteOptions{}); err != nil {
			return nil, err
		}
	}
	klog.Infof("Preflight checks and clean up: clean up exist scale test namespaces")
	err = wait.PollUntil(time.Second, func() (bool, error) {
		list, err := kClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, err
		}
		ok := true
		for _, np := range list.Items {
			if strings.HasPrefix(np.Name, "antrea-scale-test") {
				ok = false
			}
		}
		return ok, nil
	}, ctx.Done())
	if err != nil {
		return nil, err
	}

	// klog.Infof("Preflight checks and clean up: restart prometheus server")
	// if err := kClient.CoreV1().
	// 	Pods(prometheusNamespace).
	// 	DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: "app=prometheus-server"}); err != nil {
	// 	klog.Errorf("Error when stopping prometheus server: %v", err)
	// }
	func() {
		ctx, cancelFunc := context.WithTimeout(ctx, time.Minute)
		defer cancelFunc()
		if err := wait.PollImmediateUntil(time.Second, func() (bool, error) {
			list, _ := kClient.CoreV1().Pods(prometheusNamespace).
				List(ctx, metav1.ListOptions{})
			if len(list.Items) == 0 {
				return false, nil
			}
			// We expect that there is only one prometheus server.
			return list.Items[0].Status.Phase == corev1.PodRunning, nil
		}, ctx.Done()); err != nil {
			klog.Errorf("Timeout when waiting prometheus server to start")
		}
	}()
	// Sleep for 2 * 5 seconds (5s is the default scrape internal of prometheus) to make sure the prometheus server has metrics.
	time.Sleep(2 * 5 * time.Second)

	klog.Infof("Creating scale test namespaces")
	if _, err := kClient.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ScaleTestNamespace}}, metav1.CreateOptions{}); err != nil {
		return nil, err
	}

	klog.Infof("Creating the scale test client daemonset")
	if err := createTestPodClients(ctx, kClient); err != nil {
		return nil, err
	}
	err = wait.PollUntil(ShortTimeWait, func() (bool, error) {
		podList, err := kClient.CoreV1().Pods(ScaleTestNamespace).List(ctx, metav1.ListOptions{LabelSelector: ScaleClientPodTemplateName})
		if err != nil {
			return false, fmt.Errorf("error when getting scale test client pods: %w", err)
		}
		if len(podList.Items) == td.NodeNumber()-td.simulateNodesNumber {
			td.clientPods = podList.Items
			return true, nil
		}
		return false, nil
	}, ctx.Done())
	if err != nil {
		return nil, err
	}

	return &td, nil
}
