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
	utils2 "antrea.io/antrea/test/performance/framework/utils"
	"context"
	"fmt"
	"k8s.io/apimachinery/pkg/runtime"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/ipam/ipallocator"
	"antrea.io/antrea/test/e2e/providers"
	"antrea.io/antrea/test/performance/framework/workload_pod"
	"antrea.io/antrea/test/performance/utils"
)

func renderServices(service *corev1.Service, num int) (svcs []*corev1.Service) {
	for i := 0; i < num; i++ {
		labelNum := i/2 + 1
		svc := service
		svc.Name = fmt.Sprintf("antrea-scale-svc-%d-%s", i, uuid.New().String())
		svc.Spec.Selector = map[string]string{
			fmt.Sprintf("%s%d", utils.SelectorLabelKeySuffix, labelNum): fmt.Sprintf("%s%d", utils.SelectorLabelValueSuffix, labelNum),
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

func retrieveCIDRs(provider providers.ProviderInterface, controlPlaneNodeName string, cmd string, reg string) ([]string, error) {
	res := make([]string, 2)
	rc, stdout, _, err := provider.RunCommandOnNode(controlPlaneNodeName, cmd)
	if err != nil || rc != 0 {
		return res, fmt.Errorf("error when running the following command `%s` on control-plane Node: %v, %s", cmd, err, stdout)
	}
	re := regexp.MustCompile(reg)
	matches := re.FindStringSubmatch(stdout)
	if len(matches) == 0 {
		return res, fmt.Errorf("cannot retrieve CIDR, unexpected kubectl output: %s", stdout)
	}
	cidrs := strings.Split(matches[1], ",")
	if len(cidrs) == 1 {
		_, cidr, err := net.ParseCIDR(cidrs[0])
		if err != nil {
			return res, fmt.Errorf("CIDR cannot be parsed: %s", cidrs[0])
		}
		if cidr.IP.To4() != nil {
			res[0] = cidrs[0]
		} else {
			res[1] = cidrs[0]
		}
	} else if len(cidrs) == 2 {
		_, cidr, err := net.ParseCIDR(cidrs[0])
		if err != nil {
			return res, fmt.Errorf("CIDR cannot be parsed: %s", cidrs[0])
		}
		if cidr.IP.To4() != nil {
			res[0] = cidrs[0]
			res[1] = cidrs[1]
		} else {
			res[0] = cidrs[1]
			res[1] = cidrs[0]
		}
	} else {
		return res, fmt.Errorf("unexpected cluster CIDR: %s", matches[1])
	}
	return res, nil
}

func ScaleUp(ctx context.Context, provider providers.ProviderInterface, controlPlaneNodeName string, cs kubernetes.Interface, nss []string, numPerNs int, ipv6 bool, ch chan time.Duration) (svcs []ServiceInfo, err error) {
	start := time.Now()

	var svcCIDRs []string
	klog.InfoS("retrieving service CIDRs", "controlPlaneNodeName", controlPlaneNodeName)
	svcCIDRs, err = retrieveCIDRs(provider, controlPlaneNodeName, "kubectl cluster-info dump | grep service-cluster-ip-range", `service-cluster-ip-range=([^"]+)`)
	if err != nil {
		// Retrieve service CIDRs for Rancher clusters.
		svcCIDRs, err = retrieveCIDRs(provider, controlPlaneNodeName, "ps aux | grep kube-controller | grep service-cluster-ip-range", `service-cluster-ip-range=([^\s]+)`)
		if err != nil {
			klog.ErrorS(err, "retrieveCIDRs")
			return
		}
	}

	klog.InfoS("retrieveCIDRs", "svcCIDRs", svcCIDRs)
	svcCIDRIPv4 := svcCIDRs[0]
	_, ipNet, _ := net.ParseCIDR(svcCIDRIPv4)
	allocator, err := ipallocator.NewCIDRAllocator(ipNet, []net.IP{net.ParseIP("10.96.0.1"), net.ParseIP("10.96.0.10")})

	var obj runtime.Object
	obj, err = utils2.ReadYamlFile("service.yaml")
	if err != nil {
		err = fmt.Errorf("error reading Service template: %+v", err)
		return
	}

	service, ok := obj.(*corev1.Service)
	if !ok {
		err = fmt.Errorf("error converting to Unstructured: %+v", "the template file is nil")
		return
	}

	for _, ns := range nss {
		klog.InfoS("Scale up Services", "Namespace", ns)
		testPodIndex := 0
		var podList *corev1.PodList
		podList, err = cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return
		}
		for _, svc := range renderServices(service, numPerNs) {
			if ipv6 {
				ipFamily := corev1.IPv6Protocol
				svc.Spec.IPFamilies = []corev1.IPFamily{ipFamily}
			}
			if err := utils.DefaultRetry(func() error {
				var clusterIP net.IP
				clusterIP, err = allocator.AllocateNext()
				if err != nil {
					return fmt.Errorf("allocate IP from ServiceCIDR error: %+v", err)
				}

				var newSvc *corev1.Service
				var err error
				var clientPod *corev1.Pod
				svc.Spec.ClusterIP = clusterIP.String()
				klog.InfoS("go FetchTimestampFromLog", "cap(ch)", cap(ch))
				fromPod := &podList.Items[testPodIndex%len(podList.Items)]
				testPodIndex++
				clientPod, err = workload_pod.CreateClientPod(ctx, cs, fromPod.Namespace, fromPod.Name, []string{fmt.Sprintf("%s:%d", clusterIP, 80)}, workload_pod.ScaleTestPodProbeContainerName)
				if err != nil || clientPod == nil {
					klog.ErrorS(err, "Create client test Pod failed, can not verify the Service, will exist")
					return err
				}
				startTime0 := time.Now().UnixNano()
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
				go func() {
					startTimeStamp := time.Now().UnixNano()
					klog.InfoS("Service creating operate time", "Duration(ms)", (startTimeStamp-startTime0)/1000000)
					key := "down to up"
					if err := utils.FetchTimestampFromLog(ctx, cs, clientPod.Namespace, clientPod.Name, workload_pod.ScaleTestPodProbeContainerName, ch, startTimeStamp, key); err != nil {
						klog.ErrorS(err, "Check readiness of service error", "ClientPodName", clientPod.Name, "svc", svc)
					}
					klog.InfoS("Update test Pod to check Service", "ClusterIP", clusterIP)
				}()
				return nil
			}); err != nil {
				return nil, err
			}
			time.Sleep(time.Duration(utils.GenRandInt()%2000) * time.Millisecond)
		}
	}
	klog.InfoS("Scale up Services", "Duration", time.Since(start), "count", len(svcs))
	return
}
