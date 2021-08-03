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
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
	appv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/klog/v2"

	"antrea.io/antrea/test/scale/types"
	"antrea.io/antrea/test/scale/utils"
)

// serviceNum calculates the expected Service numbers based on the Node number.
func serviceNum(nodeNum int) int {
	return nodeNum * 1
}

func generateService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("antrea-scale-test-svc-%s", uuid.New().String()),
		},
		Spec: corev1.ServiceSpec{
			Selector: types.PickLabels(6, true), // each service select 25% pods on real nodes.
			Ports: []corev1.ServicePort{
				{
					Protocol: corev1.ProtocolTCP,
					Port:     80,
				},
			},
		},
	}
}

func TestCaseServiceChurns(isIPv6 bool) TestCase {
	var svcs []*corev1.Service
	agentDeletedCh := make(chan struct{})

	return repeat("Repeat", 1,
		chain("Service churn test",
			do("Create test services", func(ctx Context, data TestData) error {
				svcs = nil
				for i := 0; i < serviceNum(data.NodeNumber()); i++ {
					svc := generateService()
					if isIPv6 {
						ipFamily := corev1.IPv6Protocol
						svc.Spec.IPFamilies = []corev1.IPFamily{ipFamily}
					}
					if err := utils.DefaultRetry(func() error {
						newSvc, err := data.KubernetesClientSet().
							CoreV1().
							Services(types.ScaleTestNamespace).
							Create(ctx, svc, metav1.CreateOptions{})
						if err != nil {
							return err
						}
						if newSvc.Spec.ClusterIP == "" {
							panic("newSvc.Spec.ClusterIP is empty")
						}
						svcs = append(svcs, newSvc)
						return nil
					}); err != nil {
						return err
					}
				}
				return nil
			}),
			do("Check readiness of each test service", func(ctx Context, data TestData) error {
				time.Sleep(time.Minute)
				gErr, ctx := errgroup.WithContext(ctx)
				for i := range data.TestClientPods() {
					clientPod := data.TestClientPods()[i]
					klog.InfoS("Running client Pod", "PodName", clientPod.Name)
					gErr.Go(func() error {
						readySvcs := make(map[string]struct{})
						return utils.DefaultRetry(func() error {
							return wait.PollUntil(time.Second, func() (bool, error) {
								if len(readySvcs) == len(svcs) {
									return true, nil
								}
								for _, svc := range svcs {
									svcKey := fmt.Sprintf("%s_%s", svc.Namespace, svc.Name)
									if _, ok := readySvcs[svcKey]; ok { // Skip the service if it is verified.
										continue
									}
									executor, err := remotecommand.NewSPDYExecutor(data.Kubeconfig(), "POST", execURL(&clientPod, data.KubernetesClientSet(), svc.Spec.ClusterIP))
									if err != nil {
										return false, fmt.Errorf("error when creating SPDY executor: %w", err)
									}
									// Try to execute command with failure tolerant.
									if err = utils.DefaultRetry(func() error {
										var stdout, stderr bytes.Buffer
										if err := executor.Stream(remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}); err != nil {
											err := fmt.Errorf("executing commands on service client Pod error: %v", err)
											klog.ErrorS(err, "Check readiness of service", "ServiceName", svc.Name, "ClientPodName", clientPod.Name, "stdout", stdout.String(), "stderr", stderr.String())
											return fmt.Errorf("check readiness of service error: %v, stdout:`%s`, stderr:`%s`", err, stdout.String(), stderr.String())
										}
										klog.InfoS("Executed commands on service client Pod", "stdout", stdout.String(), "stderr", stderr.String())
										readySvcs[svcKey] = struct{}{}
										return nil
									}); err != nil {
										return false, err
									}
								}
								return len(readySvcs) == len(svcs), nil
							}, ctx.Done())
						})
					})
				}
				return gErr.Wait()
			}),
			fan("Restart antrea agents and wait them to be ready",
				do("Restart antrea agents", func(ctx Context, data TestData) error {
					err := data.KubernetesClientSet().CoreV1().Pods(metav1.NamespaceSystem).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: "app=antrea,component=antrea-agent"})
					if err != nil {
						return err
					}
					// Wait two seconds to ensure the deletion can really start.
					time.Sleep(2 * time.Second)
					select {
					case agentDeletedCh <- struct{}{}:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				}),
				do("Waiting antrea agents to be ready", func(ctx Context, data TestData) error {
					select {
					case <-agentDeletedCh:
					case <-ctx.Done():
						return ctx.Err()
					}
					return wait.PollImmediateUntil(time.Second, func() (bool, error) {
						var ds *appv1.DaemonSet
						if err := utils.DefaultRetry(func() error {
							var err error
							ds, err = data.KubernetesClientSet().
								AppsV1().DaemonSets(metav1.NamespaceSystem).
								Get(ctx, "antrea-agent", metav1.GetOptions{})
							return err
						}); err != nil {
							return false, err
						}
						return ds.Status.DesiredNumberScheduled == ds.Status.NumberAvailable, nil
					}, ctx.Done())
				}),
			),
			do("Check if all services can be stable access after agents restart", func(ctx Context, data TestData) error {
				// Wait two minutes to make sure all services to be realized.
				time.Sleep(2 * time.Minute)
				gErr, _ := errgroup.WithContext(ctx)
				for i := range data.TestClientPods() {
					clientPod := data.TestClientPods()[i]
					klog.InfoS("Running client Pod", "PodName", clientPod.Name)
					gErr.Go(func() error {
						for _, svc := range svcs {
							executor, err := remotecommand.NewSPDYExecutor(data.Kubeconfig(), "POST", execURL(&clientPod, data.KubernetesClientSet(), svc.Spec.ClusterIP))
							if err != nil {
								return fmt.Errorf("error when creating SPDY executor: %w", err)
							}
							var stdout, stderr bytes.Buffer
							if err := executor.Stream(remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}); err != nil {
								err = fmt.Errorf("executing commands on service client Pod error: %v", err)
								klog.ErrorS(err, "Check readiness of service", "ServiceName", svc.Name, "ClientPodName", clientPod.Name, "stdout", stdout.String(), "stderr", stderr.String())
								return fmt.Errorf("check readiness of service error: %v, stdout:`%s`, stderr:`%s`", err, stdout.String(), stderr.String())
							}
						}
						return nil
					})
				}
				return gErr.Wait()
			}),
			do("Clean up test services", func(ctx Context, data TestData) error {
				for _, svc := range svcs {
					err := data.KubernetesClientSet().
						CoreV1().
						Services(types.ScaleTestNamespace).Delete(ctx, svc.Name, metav1.DeleteOptions{})
					if err != nil {
						return err
					}
				}
				return nil
			}),
		),
	)
}
