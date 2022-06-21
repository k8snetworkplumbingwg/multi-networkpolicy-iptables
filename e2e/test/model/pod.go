package model

import (
	"context"
	"time"

	"github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"
)

// DefinePod creates a new pod object
func DefinePod(namespace string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "testpod-",
			Namespace:    namespace}}
}

// AddLabel adds a label to the pod's metadata
func AddLabel(pod *corev1.Pod, key, value string) *corev1.Pod {
	if pod.ObjectMeta.Labels == nil {
		pod.ObjectMeta.Labels = map[string]string{}
	}
	pod.ObjectMeta.Labels[key] = value
	return pod
}

// AddNetwork adds a network to the `k8s.v1.cni.cncf.io/networks` pod's annotations.
func AddNetwork(pod *corev1.Pod, networksSpec string) *corev1.Pod {
	pod.ObjectMeta.Annotations = map[string]string{"k8s.v1.cni.cncf.io/networks": networksSpec}
	return pod
}

// WaitPodsToBeRunning waits for all pods in the given list to be in the "Running" phase.
// It also update the input objects with the current status of the cluster.
func WaitPodsToBeRunning(c coreclient.CoreV1Interface, pods ...*corev1.Pod) {
	for _, pod := range pods {
		var res *corev1.Pod
		var err error
		gomega.Eventually(func() (corev1.PodPhase, error) {
			res, err = c.Pods(pod.Namespace).Get(context.Background(), pod.Name, metav1.GetOptions{})
			gomega.Expect(err).ToNot(gomega.HaveOccurred(), "Error while getting pod [%s/%s]", pod.Namespace, pod.Name)
			return res.Status.Phase, err
		}, 1*time.Minute, 10*time.Second).
			Should(gomega.Equal(corev1.PodRunning))

		res.DeepCopyInto(pod)
	}
}
