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
	"strconv"
	"time"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"antrea.io/antrea/test/performance/framework/workload_pod"
	"antrea.io/antrea/test/performance/utils"
)

var startSvcCIDR = "10.100.100."

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

// func retrieveCIDRs(cmd string, reg string) ([]string, error) {
// 	res := make([]string, 2)
// 	rc, stdout, _, err := data.RunCommandOnNode(controlPlaneNodeName(), cmd)
// 	if err != nil || rc != 0 {
// 		return res, fmt.Errorf("error when running the following command `%s` on control-plane Node: %v, %s", cmd, err, stdout)
// 	}
// 	re := regexp.MustCompile(reg)
// 	matches := re.FindStringSubmatch(stdout)
// 	if len(matches) == 0 {
// 		return res, fmt.Errorf("cannot retrieve CIDR, unexpected kubectl output: %s", stdout)
// 	}
// 	cidrs := strings.Split(matches[1], ",")
// 	if len(cidrs) == 1 {
// 		_, cidr, err := net.ParseCIDR(cidrs[0])
// 		if err != nil {
// 			return res, fmt.Errorf("CIDR cannot be parsed: %s", cidrs[0])
// 		}
// 		if cidr.IP.To4() != nil {
// 			res[0] = cidrs[0]
// 		} else {
// 			res[1] = cidrs[0]
// 		}
// 	} else if len(cidrs) == 2 {
// 		_, cidr, err := net.ParseCIDR(cidrs[0])
// 		if err != nil {
// 			return res, fmt.Errorf("CIDR cannot be parsed: %s", cidrs[0])
// 		}
// 		if cidr.IP.To4() != nil {
// 			res[0] = cidrs[0]
// 			res[1] = cidrs[1]
// 		} else {
// 			res[0] = cidrs[1]
// 			res[1] = cidrs[0]
// 		}
// 	} else {
// 		return res, fmt.Errorf("unexpected cluster CIDR: %s", matches[1])
// 	}
// 	return res, nil
// }

func ScaleUp(ctx context.Context, kubeConfig *rest.Config, cs kubernetes.Interface, nss []string, numPerNs int, ipv6 bool, maxCheckNum int, ch chan time.Duration, clientPods []corev1.Pod) (svcs []ServiceInfo, actualCheckNum int, err error) {
	start := time.Now()

	// svcCIDRs, err := retrieveCIDRs("kubectl cluster-info dump | grep service-cluster-ip-range", `service-cluster-ip-range=([^"]+)`)
	// if err != nil {
	// 	// Retrieve service CIDRs for Rancher clusters.
	// 	svcCIDRs, err = retrieveCIDRs("ps aux | grep kube-controller | grep service-cluster-ip-range", `service-cluster-ip-range=([^\s]+)`)
	// 	if err != nil {
	// 		return err
	// 	}
	// }

	testPodIndex := 0
	for i, ns := range nss {

		klog.InfoS("Scale up Services", "Namespace", ns)
		for _, svc := range generateService(ns, numPerNs) {
			if ipv6 {
				ipFamily := corev1.IPv6Protocol
				svc.Spec.IPFamilies = []corev1.IPFamily{ipFamily}
			}
			if err := utils.DefaultRetry(func() error {
				clusterIP := startSvcCIDR + strconv.Itoa(i+1)

				var podList *corev1.PodList
				podList, err = cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("list test Pod error: %+v", err)
				}
				if testPodIndex < len(podList.Items) {
					fromPod := podList.Items[testPodIndex]
					testPodIndex++

					if err = workload_pod.Update(ctx, cs, fromPod.Namespace, fromPod.Name, []string{fmt.Sprintf("%s:%d", clusterIP, 80)}, workload_pod.ScaleClientPodProbeContainerName); err != nil {
						klog.ErrorS(err, "Update test Pod failed")
					}
					klog.InfoS("Update test Pod to check Service", "ClusterIP", clusterIP)
				}

				var newSvc *corev1.Service
				var err error
				svc.Spec.ClusterIP = clusterIP
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
