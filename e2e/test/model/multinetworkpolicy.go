package model

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	multinetpolicyv1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	multinetpolicyclientv1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/client/clientset/versioned/typed/k8s.cni.cncf.io/v1beta1"

	"github.com/onsi/gomega"
)

// MultiNetworkPolicyOpt define an operation to be done against a MultiNetworkPolicy.
type MultiNetworkPolicyOpt func(*multinetpolicyv1.MultiNetworkPolicy)

// MakeMultiNetworkPolicy create a MultiNetworkPolicy object with mandatory fields.
func MakeMultiNetworkPolicy(targetNetwork string, opts ...MultiNetworkPolicyOpt) *multinetpolicyv1.MultiNetworkPolicy {
	ret := multinetpolicyv1.MultiNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-multinetwork-policy-",
			Annotations: map[string]string{
				"k8s.v1.cni.cncf.io/policy-for": targetNetwork,
			},
		},
	}

	for _, opt := range opts {
		opt(&ret)
	}

	return &ret
}

// WithPodSelector sets the Spec.PodSelector field in the given object.
func WithPodSelector(podSelector metav1.LabelSelector) MultiNetworkPolicyOpt {
	return func(pol *multinetpolicyv1.MultiNetworkPolicy) {
		pol.Spec.PodSelector = podSelector
	}
}

// WithEmptyIngressRules sets the Spec.Ingress to an empty array.
func WithEmptyIngressRules() MultiNetworkPolicyOpt {
	return func(pol *multinetpolicyv1.MultiNetworkPolicy) {
		pol.Spec.PolicyTypes = appendIfNotPresent(pol.Spec.PolicyTypes, multinetpolicyv1.PolicyTypeIngress)
		pol.Spec.Ingress = []multinetpolicyv1.MultiNetworkPolicyIngressRule{}
	}
}

// WithIngressRule add the given rule to the Spec.Ingress array.
func WithIngressRule(rule multinetpolicyv1.MultiNetworkPolicyIngressRule) MultiNetworkPolicyOpt {
	return func(pol *multinetpolicyv1.MultiNetworkPolicy) {
		pol.Spec.PolicyTypes = appendIfNotPresent(pol.Spec.PolicyTypes, multinetpolicyv1.PolicyTypeIngress)
		pol.Spec.Ingress = append(pol.Spec.Ingress, rule)
	}
}

// WithEmptyEgressRules sets the Spec.Egress to an empty array.
func WithEmptyEgressRules() MultiNetworkPolicyOpt {
	return func(pol *multinetpolicyv1.MultiNetworkPolicy) {
		pol.Spec.PolicyTypes = appendIfNotPresent(pol.Spec.PolicyTypes, multinetpolicyv1.PolicyTypeEgress)
		pol.Spec.Egress = []multinetpolicyv1.MultiNetworkPolicyEgressRule{}
	}
}

// WithEgressRule add the given rule to the Spec.Ingress array.
func WithEgressRule(rule multinetpolicyv1.MultiNetworkPolicyEgressRule) MultiNetworkPolicyOpt {
	return func(pol *multinetpolicyv1.MultiNetworkPolicy) {
		pol.Spec.PolicyTypes = appendIfNotPresent(pol.Spec.PolicyTypes, multinetpolicyv1.PolicyTypeEgress)
		pol.Spec.Egress = append(pol.Spec.Egress, rule)
	}
}

// CreateInNamespace issues the given client to create the object.
func CreateInNamespace(client multinetpolicyclientv1.K8sCniCncfIoV1beta1Interface, ns string) MultiNetworkPolicyOpt {
	return func(pol *multinetpolicyv1.MultiNetworkPolicy) {
		ret, err := client.MultiNetworkPolicies(ns).
			Create(context.Background(), pol, metav1.CreateOptions{})

		gomega.Expect(err).ToNot(gomega.HaveOccurred())

		ret.DeepCopyInto(pol)
	}
}

func appendIfNotPresent(input []multinetpolicyv1.MultiPolicyType, newElement multinetpolicyv1.MultiPolicyType) []multinetpolicyv1.MultiPolicyType {
	for _, e := range input {
		if e == newElement {
			return input
		}
	}

	return append(input, newElement)
}
