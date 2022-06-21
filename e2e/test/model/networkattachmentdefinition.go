package model

import (
	"context"
	"fmt"
	"time"

	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netdefclientv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/typed/k8s.cni.cncf.io/v1"
	"github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
)

// DefineMacvlanNetAttachDef creates a new NetworkAttachmentDefinition object
func DefineMacvlanNetAttachDef(namespace, name, ipam string) *netdefv1.NetworkAttachmentDefinition {
	configTpl := `{
        "cniVersion": "0.3.1",
        "name": "%s",
        "plugins": [{
			"type": "macvlan",
			"capabilities": { "ips": true },
			"mode": "bridge",
			"ipam":%s
		}]
	}`
	return &netdefv1.NetworkAttachmentDefinition{
		ObjectMeta: v1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: netdefv1.NetworkAttachmentDefinitionSpec{
			Config: fmt.Sprintf(configTpl, name, ipam),
		},
	}
}

// CreateNetAttachDef creates the given NetworkAttachmentDefinition in the cluster
func CreateNetAttachDef(c netdefclientv1.K8sCniCncfIoV1Interface, nad *netdefv1.NetworkAttachmentDefinition) {
	_, err := c.NetworkAttachmentDefinitions(nad.Namespace).Create(context.Background(), nad, metav1.CreateOptions{})
	gomega.Expect(err).ToNot(gomega.HaveOccurred())
}

// CleanNetAttachDefs deletes all pods in namespace
func CleanNetAttachDefs(c netdefclientv1.K8sCniCncfIoV1Interface, namespace string) {

	err := c.NetworkAttachmentDefinitions(namespace).DeleteCollection(context.Background(), metav1.DeleteOptions{
		GracePeriodSeconds: pointer.Int64Ptr(0),
	}, metav1.ListOptions{})
	gomega.Expect(err).ToNot(gomega.HaveOccurred())
	gomega.Eventually(func() int {
		list, err := c.NetworkAttachmentDefinitions(namespace).List(context.Background(), metav1.ListOptions{})
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
		return len(list.Items)
	}, 1*time.Minute, 10*time.Second).Should(gomega.BeZero())
}
