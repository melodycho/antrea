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

package utils

import (
	"bytes"
	"context"
	"fmt"
	"k8s.io/klog/v2"
	"net/url"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"

	"antrea.io/antrea/test/performance/framework/client_pod"
)

const (
	defaultInterval = 1 * time.Second
	defaultTimeout  = 3 * time.Minute
)

func ExecURL(kClient kubernetes.Interface, clientPodNamespace, clientPodName, peerIP string) *url.URL {
	return kClient.CoreV1().RESTClient().Post().
		Namespace(clientPodNamespace).
		Resource("pods").Name(clientPodName).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Command:   []string{"/bin/sh", "-c", fmt.Sprintf("nc -vz -w 1 %s 80", peerIP)},
			Container: client_pod.ScaleClientContainerName,
			Stdin:     false,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, scheme.ParameterCodec).URL()
}

func WaitUntil(ctx context.Context, ch chan time.Duration, kubeConfig *rest.Config, kc kubernetes.Interface, podNs, podName, ip string, expectErr bool) error {
	var err error
	startTime := time.Now()
	defer func() {
		if err == nil {
			select {
			case ch <- time.Since(startTime):
				klog.InfoS("Successfully write in channel")
			default:
				klog.InfoS("Skipped writing to the channel. No receiver.")
			}
		}
	}()
	err = wait.Poll(defaultInterval, defaultTimeout, func() (bool, error) {
		err := PingIP(ctx, kubeConfig, kc, podNs, podName, ip)
		if (err != nil && !expectErr) || (err == nil && expectErr) {
			return false, fmt.Errorf("error when getting expected condition: %+v", err)
		}
		return true, nil
	})
	return err
}

func PingIP(ctx context.Context, kubeConfig *rest.Config, kc kubernetes.Interface, podNs, podName, ip string) error {
	executor, err := remotecommand.NewSPDYExecutor(kubeConfig, "POST", ExecURL(kc, podNs, podName, ip))
	if err != nil {
		return fmt.Errorf("error when creating SPDY executor: %w", err)
	}

	// Try to execute command with failure tolerant.
	if err = DefaultRetry(func() error {
		var stdout, stderr bytes.Buffer
		if err := executor.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}); err != nil {
			err := fmt.Errorf("executing commands on service client Pod error: %v", err)
			// klog.ErrorS(err, "Check readiness of service", "ServiceName", svc.Name, "ClientPodName", clientPod.Name, "stdout", stdout.String(), "stderr", stderr.String())
			return fmt.Errorf("ping ip %s error: %v, stdout:`%s`, stderr:`%s`, client pod: %s", ip, err, stdout.String(), stderr.String(), podName)
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}
