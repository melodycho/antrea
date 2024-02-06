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

package service

import (
	"context"
	"fmt"
	"k8s.io/client-go/rest"
	"time"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"antrea.io/antrea/test/performance/utils"
)

func generateService(ns string, num int) (svcs []*corev1.Service) {
	for i := 0; i < num; i++ {
		labelNum := i/2 + 1
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name: fmt.Sprintf("antrea-scale-svc-%d-%s", i, uuid.New().String()),
			},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{
					fmt.Sprintf("%s%d", utils.SelectorLabelKeySuffix, labelNum): fmt.Sprintf("%s%d", utils.SelectorLabelValueSuffix, labelNum),
				},
				Ports: []corev1.ServicePort{
					{
						Protocol: corev1.ProtocolTCP,
						Port:     80,
					},
				},
			},
		}
		svcs = append(svcs, svc)
	}
	return
}

type ServiceInfo struct {
	Name      string
	IP        string
	NameSpace string
}

func ScaleUp(ctx context.Context, kubeConfig *rest.Config, cs kubernetes.Interface, nss []string, numPerNs int, ipv6 bool, maxCheckNum int, ch chan time.Duration, clientPods []corev1.Pod) (svcs []ServiceInfo, actualCheckNum int, err error) {
	start := time.Now()
	for _, ns := range nss {
		klog.InfoS("Scale up Services", "Namespace", ns)
		for _, svc := range generateService(ns, numPerNs) {
			if ipv6 {
				ipFamily := corev1.IPv6Protocol
				svc.Spec.IPFamilies = []corev1.IPFamily{ipFamily}
			}
			if err := utils.DefaultRetry(func() error {
				var newSvc *corev1.Service
				var err error
				newSvc, err = cs.CoreV1().Services(ns).Create(ctx, svc, metav1.CreateOptions{})
				if err != nil {
					if errors.IsAlreadyExists(err) {
						newSvc, _ = cs.CoreV1().Services(ns).Get(ctx, svc.Name, metav1.GetOptions{})
					} else {
						return err
					}
				}
				if newSvc.Spec.ClusterIP == "" {
					return fmt.Errorf("service %s Spec.ClusterIP is empty", svc.Name)
				}
				klog.InfoS("Create Service", "Name", newSvc.Name, "ClusterIP", newSvc.Spec.ClusterIP, "Namespace", ns)
				svcs = append(svcs, ServiceInfo{Name: newSvc.Name, IP: newSvc.Spec.ClusterIP, NameSpace: newSvc.Namespace})

				ip := newSvc.Spec.ClusterIP

				if actualCheckNum < maxCheckNum && actualCheckNum < cap(ch) {
					k := int(utils.GenRandInt()) % len(clientPods)
					clientPod := clientPods[k]
					klog.V(2).InfoS("Check service", "svc", svc, "Pod", clientPod.Name)
					actualCheckNum++
					go func() {
						if err := utils.WaitUntil(ctx, ch, kubeConfig, cs, clientPod.Namespace, clientPod.Name, ip, false); err != nil {
							klog.ErrorS(err, "Check readiness of service error", "ClientPodName", clientPod.Name, "svc", svc)
						}
					}()
				}

				return nil
			}); err != nil {
				return nil, 0, err
			}
			time.Sleep(time.Duration(utils.GenRandInt()%2000) * time.Millisecond)
		}
	}
	klog.InfoS("Scale up Services", "Duration", time.Since(start), "count", len(svcs))
	return
}
