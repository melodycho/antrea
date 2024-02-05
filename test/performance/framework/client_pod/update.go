package client_pod

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"

	"antrea.io/antrea/test/performance/config"
)

func Update(ctx context.Context, kClient kubernetes.Interface, ns, clientDaemonSetName string, probes []string, containerName string) (clientPods []corev1.Pod, err error) {
	err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		daemonSet, err := kClient.AppsV1().DaemonSets(ns).Get(context.TODO(), clientDaemonSetName, metav1.GetOptions{})
		if err != nil {
			klog.ErrorS(err, "Error getting DaemonSet", "Name", clientDaemonSetName)
			return err
		}
		for _, existedContainer := range daemonSet.Spec.Template.Spec.Containers {
			if existedContainer.Name == containerName {
				klog.InfoS("Container already existed", "ContainerName", containerName, "DaemonSet", clientDaemonSetName)
				return nil
			}
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
		daemonSet.Spec.Template.Spec.Containers = append(daemonSet.Spec.Template.Spec.Containers, containers...)

		_, err = kClient.AppsV1().DaemonSets(ns).Update(context.TODO(), daemonSet, metav1.UpdateOptions{})
		return err
	})

	if err != nil {
		klog.ErrorS(err, "Error updating DaemonSet", "Name", clientDaemonSetName)
		return
	}

	klog.InfoS("DaemonSet updated successfully!", "Name", clientDaemonSetName)

	if err := wait.PollImmediateUntil(config.WaitInterval, func() (bool, error) {
		ds, err := kClient.AppsV1().DaemonSets(ns).Get(ctx, clientDaemonSetName, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		if ds.Status.DesiredNumberScheduled != ds.Status.NumberReady {
			return false, nil
		}
		podList, err := kClient.CoreV1().Pods(ClientPodsNamespace).List(ctx, metav1.ListOptions{LabelSelector: ScaleClientPodTemplateName})
		if err != nil {
			return false, fmt.Errorf("error when getting scale test client pods: %w", err)
		}
		clientPods = podList.Items
		return true, nil
	}, ctx.Done()); err != nil {
		return nil, fmt.Errorf("error when waiting scale test clients to be ready: %w", err)
	}
	return
}
