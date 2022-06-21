package model

import (
	"context"
	"time"

	"github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/pointer"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

// NamespaceExists tells whether the given namespace exists
func NamespaceExists(namespace string, c corev1client.CoreV1Interface) bool {
	_, err := c.Namespaces().Get(context.Background(), namespace, metav1.GetOptions{})
	return err == nil || !k8serrors.IsNotFound(err)
}

// CleanPods deletes all pods in namespace
func CleanPods(c corev1client.CoreV1Interface, namespace string) {
	if !NamespaceExists(namespace, c) {
		return
	}
	err := c.Pods(namespace).DeleteCollection(context.Background(), metav1.DeleteOptions{
		GracePeriodSeconds: pointer.Int64Ptr(0),
	}, metav1.ListOptions{})
	gomega.Expect(err).ToNot(gomega.HaveOccurred())

	gomega.Eventually(func() int {
		podsList, err := c.Pods(namespace).List(context.Background(), metav1.ListOptions{})
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
		return len(podsList.Items)
	}, 1*time.Minute, 1*time.Second).Should(gomega.BeZero())
}

// CreateNamespace creates a new namespace with the given name.
func CreateNamespace(c corev1client.CoreV1Interface, namespace string) {
	_, err := c.Namespaces().Create(
		context.Background(),
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: namespace,
			}},
		metav1.CreateOptions{})

	if k8serrors.IsAlreadyExists(err) {
		return
	}

	gomega.Expect(err).ToNot(gomega.HaveOccurred())
}
