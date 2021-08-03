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
	"context"
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/google/uuid"
	promv1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/klog/v2"

	"antrea.io/antrea/test/scale/types"
	"antrea.io/antrea/test/scale/utils"
)

var (
	networkPolicyLabelKey = "antrea-scale-test-netpol"
)

var errPrometheusClient = fmt.Errorf("PrometheusClient is nil")

func genRandInt() int64 {
	b := new(big.Int).SetInt64(int64(math.MaxInt64))
	i, err := rand.Int(rand.Reader, b)
	if err != nil {
		return 0
	}
	return i.Int64()
}

func shuffle(s *[]corev1.Pod) {
	slice := *s
	n := len(slice)
	for i := range slice {
		j := int(genRandInt()) % n
		slice[i], slice[j] = slice[j], slice[i]
	}
	*s = slice
}

// Total NetworkPolicies number = 50% Pods number
//  5% NetworkPolicies cover 80% Pods = 2.5% Pods number
// 15% NetworkPolicies cover 13% Pods = 7.5% Pods number
// 80% NetworkPolicies cover 6% Pods  = 40%  Pods number
func generateNetpolTemplate(labelNum int, podName string, isIngress bool) *netv1.NetworkPolicy {
	name := uuid.New().String()
	protocol := corev1.ProtocolTCP
	port := intstr.FromInt(80)
	policyPorts := []netv1.NetworkPolicyPort{{Protocol: &protocol, Port: &port}}
	policyPeer := []netv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"name": podName}}}}
	netpol := &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: types.ScaleTestNamespace,
			Labels:    map[string]string{networkPolicyLabelKey: ""},
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: types.PickLabels(labelNum, false)},
		},
	}
	if isIngress {
		netpol.Spec.PolicyTypes = []netv1.PolicyType{netv1.PolicyTypeIngress}
		netpol.Spec.Ingress = []netv1.NetworkPolicyIngressRule{{Ports: policyPorts, From: policyPeer}}
	} else {
		netpol.Spec.PolicyTypes = []netv1.PolicyType{netv1.PolicyTypeEgress}
		netpol.Spec.Egress = []netv1.NetworkPolicyEgressRule{{Ports: policyPorts, To: policyPeer}}
	}
	return netpol
}

func generateP80NetworkPolicies(podName string, isIngress bool) *netv1.NetworkPolicy {
	return generateNetpolTemplate(1, podName, isIngress)
}
func generateP15NetworkPolicies(podName string, isIngress bool) *netv1.NetworkPolicy {
	return generateNetpolTemplate(7, podName, isIngress)
}
func generateP5NetworkPolicies(podName string, isIngress bool) *netv1.NetworkPolicy {
	return generateNetpolTemplate(10, podName, isIngress)
}

func generateNetworkPolicies(data TestData, isIngress bool) ([]*netv1.NetworkPolicy, error) {
	p5 := data.PodNumber() * 25 / 1000   // 2.5% number of Pods
	p15 := data.PodNumber() * 75 / 1000  // 7.5% number of Pods
	p80 := data.PodNumber() * 400 / 1000 // 40% number of Pods
	var result []*netv1.NetworkPolicy
	podList, err := data.KubernetesClientSet().
		CoreV1().Pods(types.ScaleTestNamespace).
		List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	shuffle(&podList.Items)

	items := podList.Items[:p5+p15+p80]
	for i := 0; i < p5; i++ {
		result = append(result, generateP80NetworkPolicies(items[i].Name, isIngress))
	}
	for i := 0; i < p15; i++ {
		result = append(result, generateP15NetworkPolicies(items[i].Name, isIngress))
	}
	for i := 0; i < p80; i++ {
		result = append(result, generateP5NetworkPolicies(items[i].Name, isIngress))
	}
	return result, nil
}

func TestCaseNetworkPolicyRealization() TestCase {
	var startProcessedNumber int
	var npNum int
	var nps []*netv1.NetworkPolicy

	retryWithRateLimiter := func(ctx context.Context, rateLimiter *rate.Limiter, f func() error) error {
		rateLimiter.Wait(ctx)
		return utils.DefaultRetry(f)
	}

	times := 0
	return repeat("Repeat", 1,
		chain("NetworkPolicy process test",
			do("Record number of processed NetworkPolicies in Antrea controller before running", func(ctx Context, data TestData) error {
				times += 1
				return wait.PollUntil(time.Second, func() (bool, error) {
					promAPI := promv1.NewAPI(data.PrometheusClient())
					if promAPI == nil {
						klog.ErrorS(errPrometheusClient, "PrometheusClient", data.PrometheusClient())
						return false, errPrometheusClient
					}
					err := utils.DefaultRetry(func() error {
						result, _, err := promAPI.Query(ctx, "antrea_controller_network_policy_processed", time.Now())
						if err != nil {
							klog.ErrorS(err, "Failed to retrieve antrea_controller_network_policy_processed")
							return err
						}
						samples := result.(model.Vector) // Expected that there should only be one instance.
						if len(samples) == 0 {
							return fmt.Errorf("can not retrieve valid metric data")
						}
						startProcessedNumber = int(samples[0].Value)
						return nil
					})
					if err != nil {
						return false, err
					}
					return true, nil
				}, ctx.Done())
			}),
			fan("Adding NetworkPolicies and wait them to be processed",
				do("Adding NetworkPolicies", func(ctx Context, data TestData) error {
					var err error
					nps, err = generateNetworkPolicies(data, times%2 == 0)
					if err != nil {
						return fmt.Errorf("error when generating network policies: %w", err)
					}
					klog.InfoS("Processing NetworkPolicies", "Num", len(nps))
					for _, netpol := range nps {
						if err := utils.DefaultRetry(func() error {
							_, err := data.KubernetesClientSet().
								NetworkingV1().
								NetworkPolicies(types.ScaleTestNamespace).
								Create(ctx, netpol, metav1.CreateOptions{})
							return err
						}); err != nil {
							return err
						}
					}
					return nil
				}),
				do("Waiting all NetworkPolicies to be processed", func(ctx Context, data TestData) error {
					promAPI := promv1.NewAPI(data.PrometheusClient())
					if promAPI == nil {
						klog.ErrorS(errPrometheusClient, "PrometheusClient", data.PrometheusClient())
						return errPrometheusClient
					}
					if err := utils.DefaultRetry(func() error {
						return wait.PollImmediateUntil(time.Second, func() (bool, error) {
							var processed int
							err := utils.DefaultRetry(func() error {
								result, _, err := promAPI.Query(ctx, "antrea_controller_network_policy_processed", time.Now())
								if err != nil {
									return err
								}
								samples := result.(model.Vector) // At current time, we expect that there is only one instance.
								processed = int(samples[0].Value)
								return nil
							})
							if err != nil {
								return false, err
							}
							return processed-startProcessedNumber >= npNum, nil
						}, ctx.Done())
					}); err != nil {
						return fmt.Errorf("error when waiting all NetworkPolicies to be processed, %w", err)
					}
					return nil
				}),
			),
			do("Check isolation of NetworkPolicies", func(ctx Context, data TestData) error {
				gErr, _ := errgroup.WithContext(context.Background())
				rateLimiter := rate.NewLimiter(rate.Limit(10*len(data.TestClientPods())), len(data.TestClientPods())*20)
				for _, np := range nps {
					// if genRandInt()%10 != 0 {
					// 	continue
					// }
					klog.InfoS("Checking isolation of the NetworkPolicy", "NetworkPolicyName", np.Name)
					podSelectors := make(map[string]string)
					for k, v := range np.Spec.PodSelector.MatchLabels {
						podSelectors[k] = v
					}
					podSelectors[types.PodOnRealNodeLabelKey] = ""
					podList, err := data.KubernetesClientSet().CoreV1().
						Pods(types.ScaleTestNamespace).
						List(ctx, metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(&np.Spec.PodSelector)})
					if err != nil {
						return fmt.Errorf("error when selecting networkpolicy applied to pods: %w", err)
					}
					if len(podList.Items) == 0 {
						klog.InfoS("No Pod is selected by the NetworkPolicy, skip", "NetworkPolicyName", np.Name)
						return nil
					}
					var fromPods []corev1.Pod
					var toPods []corev1.Pod
					if len(np.Spec.Ingress) > 0 {
						fromPods = data.TestClientPods()
						toPods = []corev1.Pod{podList.Items[int(genRandInt())%len(podList.Items)]}
					} else if len(np.Spec.Egress) > 0 {
						fromPods = []corev1.Pod{podList.Items[int(genRandInt())%len(podList.Items)]}
						toPods = data.TestClientPods()
					}
					for i, fromPod := range fromPods {
						for j, toPod := range toPods {
							// goroutines will use the last process in the slice
							tPod := &toPods[j]
							klog.InfoS("Checking isolation of the NetworkPolicy", "NetworkPolicyName", np.Name, "FromPod", fromPod.Name, "ToPod", toPod.Name)
							gErr.Go(func() error {
								return retryWithRateLimiter(ctx, rateLimiter, func() error {
									url := execURL(&fromPods[i], data.KubernetesClientSet(), tPod.Status.PodIP)
									exec, err := remotecommand.NewSPDYExecutor(data.Kubeconfig(), "POST", url)
									if err != nil {
										return fmt.Errorf("error when creating SPDY executor: %w", err)
									}
									var stdout, stderr bytes.Buffer
									if err := exec.Stream(remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}); err == nil {
										klog.InfoS("Check Pod connection ok", "FromPod", fromPod.Name, "toPod", toPod.Name, "output", stdout.String(), "outputErr", stderr.String())
										return fmt.Errorf("the connection should not be success")
									}
									return nil
								})
							})
						}
					}
				}
				return gErr.Wait()
			}),
			do("Check connectivity of NetworkPolicies", func(ctx Context, data TestData) error {
				for _, np := range nps {
					klog.InfoS("Checking connectivity of the NetworkPolicy", "NetworkPolicyName", np.Name)
					podSelector := make(map[string]string)
					for k, v := range np.Spec.PodSelector.MatchLabels {
						podSelector[k] = v
					}
					podSelector[types.PodOnRealNodeLabelKey] = ""
					// podList, err := data.KubernetesClientSet().CoreV1().
					// 	Pods(types.ScaleTestNamespace).
					// 	List(ctx, metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(&np.Spec.PodSelector)})
					np.Spec.PodSelector.MatchLabels = podSelector
					klog.InfoS("list PodSelector", "PodSelector", np.Spec.PodSelector)
					podList, err := data.KubernetesClientSet().CoreV1().
						Pods(types.ScaleTestNamespace).
						List(ctx, metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(&np.Spec.PodSelector)})
					if err != nil {
						return fmt.Errorf("error when selecting networkpolicy applied to pods: %w", err)
					}
					klog.InfoS("list Pod", "podNum", len(podList.Items))
					for _, pod := range podList.Items {
						klog.InfoS("Pod", pod.Name)
					}
					if len(podList.Items) == 0 {
						klog.InfoS("No Pod is selected by the NetworkPolicy, skip", "NetworkPolicyName", np.Name)
					}
					var fromPods []corev1.Pod
					var toPods []corev1.Pod
					if len(np.Spec.Ingress) > 0 {
						toPods = podList.Items
						if err := utils.DefaultRetry(func() error {
							fromPodsList, err := data.KubernetesClientSet().CoreV1().
								Pods(types.ScaleTestNamespace).
								List(ctx, metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(np.Spec.Ingress[0].From[0].PodSelector)})
							if err != nil {
								return err
							}
							fromPods = fromPodsList.Items
							return nil
						}); err != nil {
							return fmt.Errorf("error when retrieving Pods: %w", err)
						}
					} else if len(np.Spec.Egress) > 0 {
						fromPods = podList.Items
						if err := utils.DefaultRetry(func() error {
							toPodsList, err := data.KubernetesClientSet().CoreV1().
								Pods(types.ScaleTestNamespace).
								List(ctx, metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(np.Spec.Egress[0].To[0].PodSelector)})
							if err != nil {
								return err
							}
							toPods = toPodsList.Items
							return nil
						}); err != nil {
							return fmt.Errorf("error when retrieving Pods: %w", err)
						}
					}

					if len(toPods) == 0 || len(fromPods) == 0 {
						klog.InfoS("Skipping the check of the NetworkPolicy, since the label selector does not match any Pod", "NetworkPolicy", np.Name)
						continue
					}

					toPod := toPods[int(genRandInt())%len(toPods)]
					fromPod := fromPods[int(genRandInt())%len(fromPods)]
					rateLimiter := rate.NewLimiter(rate.Limit(10*len(data.TestClientPods())), len(data.TestClientPods())*20)
					if toPod.Status.PodIP == "" {
						klog.ErrorS(fmt.Errorf("nil Pod IP"), "Namespace", toPod.Namespace, "Name", toPod.Name)
						continue
					}
					if err := retryWithRateLimiter(ctx, rateLimiter, func() error {
						exec, err := remotecommand.NewSPDYExecutor(
							data.Kubeconfig(),
							"POST",
							execURL(&fromPod, data.KubernetesClientSet(), toPod.Status.PodIP),
						)
						if err != nil {
							return fmt.Errorf("error when creating SPDY executor: %w", err)
						}
						var stdout, stderr bytes.Buffer
						if err := exec.Stream(remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}); err != nil {
							klog.ErrorS(err, "Executing Stream and check connection error", "stdout", stdout.String(), "stderr", stderr.String(), "fromPod", fromPod.Name, "toPod", toPod.Name)
							return fmt.Errorf("the connection should be success, error: %w, fromPod: %s, toPod: %s", err, fromPod.Name, toPod.Name)
						}
						klog.InfoS("Executed Stream and check connection", "stdout", stdout.String(), "stderr", stderr.String())
						return nil
					}); err != nil {
						return err
					}
				}
				return nil
			}),
			do("Deleting all NetworkPolicies", func(ctx Context, data TestData) error {
				nps = nil
				return data.KubernetesClientSet().NetworkingV1().
					NetworkPolicies(types.ScaleTestNamespace).
					DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{})
			}),
		))
}
