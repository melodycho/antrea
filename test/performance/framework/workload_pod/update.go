package workload_pod

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
)

const (
	ScaleClientPodProbeContainerName = "antrea-scale-test-client-pod-probe"
)

func Update(ctx context.Context, kClient kubernetes.Interface, namespace, podName string, probes []string, containerName string) error {
	var err error
	expectContainerNum := 0
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		pod, err := kClient.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		var containers []corev1.Container
		for _, probe := range probes {
			l := strings.Split(probe, ":")
			server, port := l[0], l[1]
			if server == "" {
				server = "$NODE_IP"
			}

			containers = append(containers, corev1.Container{
				Name:            containerName,
				Image:           "busybox",
				Command:         []string{"/bin/sh", "-c", fmt.Sprintf("server=%s; output_file=\"ping_log.txt\"; if [ ! -e \"$output_file\" ]; then touch \"$output_file\"; fi; last_status=\"unknown\"; last_change_time=$(date +%%s); while true; do status=$(nc -vz -w 1 \"$server\" %s > /dev/null && echo \"up\" || echo \"down\"); current_time=$(date +%%s); time_diff=$((current_time - last_change_time)); if [ \"$status\" != \"$last_status\" ]; then echo \"Status changed from $last_status to $status after ${time_diff} seconds\"; echo \"Status changed from $last_status to $status after ${time_diff} seconds\" >> \"$output_file\"; last_change_time=$current_time; last_status=$status; fi; sleep 0.3; done\n", server, port)},
				ImagePullPolicy: corev1.PullIfNotPresent,
				Env: []corev1.EnvVar{
					{
						Name: "NODE_IP",
						ValueFrom: &corev1.EnvVarSource{
							FieldRef: &corev1.ObjectFieldSelector{
								FieldPath: "status.hostIP",
							},
						},
					},
				},
			})
		}

		pod.Spec.Containers = append(pod.Spec.Containers, containers...)
		expectContainerNum = len(pod.Spec.Containers)

		err = kClient.CoreV1().Pods(namespace).Delete(ctx, podName, metav1.DeleteOptions{})
		if err != nil {
			return err
		}

		err = wait.PollImmediate(2*time.Second, 60*time.Second, func() (done bool, err error) {
			_, err = kClient.CoreV1().Pods(pod.Namespace).Get(context.TODO(), pod.Name, metav1.GetOptions{})
			return err != nil, nil
		})

		if err != nil {
			return fmt.Errorf("error waiting for Pod termination: %v", err)
		}
		newPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      pod.Name,
				Namespace: pod.Namespace,
			},
			Spec: pod.Spec,
		}

		_, err = kClient.CoreV1().Pods(namespace).Create(ctx, newPod, metav1.CreateOptions{})
		return err
	})
	if err != nil {
		return err
	}

	err = wait.PollImmediate(time.Second, 30, func() (bool, error) {
		pod, err := kClient.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		if expectContainerNum == len(pod.Spec.Containers) {
			return true, nil
		}

		return false, nil
	})
	if err != nil {
		return err
	}

	klog.InfoS("Container added successfully!")
	return nil
}
