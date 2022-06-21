package test

import (
	"context"
	"time"

	m "github.com/k8snetworkplumbingwg/multi-networkpolicy-iptables/e2e/test/model"
	. "github.com/k8snetworkplumbingwg/multi-networkpolicy-iptables/e2e/test/reachmatcher"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	multinetpolicyv1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	TestsNetworkName = "macvlan1"
	DefaultNamespace = "default"
	TestNetwork      = DefaultNamespace + "/" + TestsNetworkName
)

var nsX, nsY, nsZ struct {
	podA *corev1.Pod
	podB *corev1.Pod
	podC *corev1.Pod
	Name string
}

var _ = BeforeSuite(func() {

	SetRestConfig(restConfig)

	nsX.Name = "x"
	nsY.Name = "y"
	nsZ.Name = "z"

	By("Cleaning old objects")
	m.CleanNetAttachDefs(cs.K8sCniCncfIoV1Interface, DefaultNamespace)
	m.CleanPods(cs.CoreV1Interface, nsX.Name)
	m.CleanPods(cs.CoreV1Interface, nsY.Name)
	m.CleanPods(cs.CoreV1Interface, nsZ.Name)

	By("Creating Namespaces")
	m.CreateNamespace(cs.CoreV1Interface, nsX.Name)
	m.CreateNamespace(cs.CoreV1Interface, nsY.Name)
	m.CreateNamespace(cs.CoreV1Interface, nsZ.Name)

	By("Creating NetworkAttachDefinition")
	ipam := `{"type": "host-local","ranges": [ [{"subnet": "2.2.2.0/24"}] ]}`
	networkAttachDef := m.DefineMacvlanNetAttachDef(DefaultNamespace, TestsNetworkName, ipam)
	m.CreateNetAttachDef(cs.K8sCniCncfIoV1Interface, networkAttachDef)

	By("Creating Pods")
	nsX.podA, nsX.podB, nsX.podC = createPodsInNamespace(nsX.Name)
	nsY.podA, nsY.podB, nsY.podC = createPodsInNamespace(nsY.Name)
	nsZ.podA, nsZ.podB, nsZ.podC = createPodsInNamespace(nsZ.Name)

	m.WaitPodsToBeRunning(cs.CoreV1Interface,
		nsX.podA, nsX.podB, nsX.podC,
		nsY.podA, nsY.podB, nsY.podC,
		nsZ.podA, nsZ.podB, nsZ.podC,
	)
})

var _ = AfterSuite(func() {

})

var _ = Describe("[multinetworkpolicy]", func() {
	BeforeEach(func() {
		cleanMultiNetworkPoliciesFromNamespace(nsX.Name)
		cleanMultiNetworkPoliciesFromNamespace(nsY.Name)
		cleanMultiNetworkPoliciesFromNamespace(nsZ.Name)
	})

	Context("Ingress", func() {
		It("DENY all traffic to a pod", func() {
			m.MakeMultiNetworkPolicy(TestNetwork,
				m.WithPodSelector(metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "a",
					},
				}),
				m.WithEmptyIngressRules(),
				m.CreateInNamespace(cs.K8sCniCncfIoV1beta1Interface, nsX.Name),
			)

			// Pod B and C are not affected by the policy
			eventually30s(nsX.podB).Should(Reach(nsX.podC, ViaTCP))
			eventually30s(nsX.podB).Should(Reach(nsX.podC, ViaUDP))

			// Pod A should not be reacheable by B and C
			eventually30s(nsX.podB).ShouldNot(Reach(nsX.podA, ViaTCP))
			eventually30s(nsX.podB).ShouldNot(Reach(nsX.podA, ViaUDP))
			eventually30s(nsX.podC).ShouldNot(Reach(nsX.podA, ViaTCP))
			eventually30s(nsX.podC).ShouldNot(Reach(nsX.podA, ViaUDP))
		})

		It("DENY all traffic to and within a namespace", func() {

			m.MakeMultiNetworkPolicy(TestNetwork,
				m.WithEmptyIngressRules(),
				m.CreateInNamespace(cs.K8sCniCncfIoV1beta1Interface, nsX.Name),
			)

			// Traffic within nsX.Name is not allowed
			eventually30s(nsX.podA).ShouldNot(Reach(nsX.podB))
			eventually30s(nsX.podB).ShouldNot(Reach(nsX.podC))
			eventually30s(nsX.podC).ShouldNot(Reach(nsX.podA))

			// Traffic to/from nsX.Name is not allowed
			eventually30s(nsY.podA).ShouldNot(Reach(nsX.podA))
			eventually30s(nsZ.podA).ShouldNot(Reach(nsX.podA))

			// Traffic within other namespaces is allowed
			eventually30s(nsY.podA).Should(Reach(nsY.podB))
			eventually30s(nsZ.podA).Should(Reach(nsZ.podB))

			// Traffic between other namespaces is allowed
			eventually30s(nsY.podA).Should(Reach(nsZ.podA))
			eventually30s(nsZ.podB).Should(Reach(nsY.podC))
		})

		It("ALLOW traffic to nsX.podA only from nsX.podB", func() {

			m.MakeMultiNetworkPolicy(TestNetwork,
				m.WithPodSelector(metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "a",
					},
				}),
				m.WithIngressRule(multinetpolicyv1.MultiNetworkPolicyIngressRule{
					From: []multinetpolicyv1.MultiNetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"pod": "b",
							},
						},
					}},
				}),
				m.CreateInNamespace(cs.K8sCniCncfIoV1beta1Interface, nsX.Name),
			)

			// The subject of test case
			eventually30s(nsX.podB).Should(Reach(nsX.podA))
			eventually30s(nsX.podC).ShouldNot(Reach(nsX.podA))

			// Traffic that should not be affected
			eventually30s(nsX.podB).Should(Reach(nsX.podC))
		})

		It("ALLOW traffic to nsX.podA only from (namespace == nsY.Name)", func() {

			m.MakeMultiNetworkPolicy(TestNetwork,
				m.WithPodSelector(metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "a",
					},
				}),
				m.WithIngressRule(multinetpolicyv1.MultiNetworkPolicyIngressRule{
					From: []multinetpolicyv1.MultiNetworkPolicyPeer{{
						NamespaceSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"kubernetes.io/metadata.name": nsY.Name,
							},
						},
					}},
				}),
				m.CreateInNamespace(cs.K8sCniCncfIoV1beta1Interface, nsX.Name),
			)

			// Allowed
			eventually30s(nsY.podA).Should(Reach(nsX.podA))
			eventually30s(nsY.podB).Should(Reach(nsX.podA))
			eventually30s(nsY.podC).Should(Reach(nsX.podA))

			// Not allowed
			eventually30s(nsZ.podA).ShouldNot(Reach(nsX.podA))
			eventually30s(nsZ.podB).ShouldNot(Reach(nsX.podA))
			eventually30s(nsZ.podC).ShouldNot(Reach(nsX.podA))

			eventually30s(nsX.podB).ShouldNot(Reach(nsX.podA))
			eventually30s(nsX.podC).ShouldNot(Reach(nsX.podA))
		})

		It("ALLOW traffic to nsX.podA only from (nsY.Name/* OR */podB)", func() {

			m.MakeMultiNetworkPolicy(TestNetwork,
				m.WithPodSelector(metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "a",
					},
				}),
				m.WithIngressRule(multinetpolicyv1.MultiNetworkPolicyIngressRule{
					From: []multinetpolicyv1.MultiNetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"kubernetes.io/metadata.name": nsY.Name,
								},
							},
						},
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"pod": "b",
								},
							},
						},
					},
				}),
				m.CreateInNamespace(cs.K8sCniCncfIoV1beta1Interface, nsX.Name),
			)

			// Allowed
			eventually30s(nsX.podA).Should(Reach(nsY.podA))
			eventually30s(nsY.podB).Should(Reach(nsX.podA))
			eventually30s(nsY.podC).Should(Reach(nsX.podA))

			eventually30s(nsZ.podB).Should(Reach(nsX.podA))
			eventually30s(nsX.podB).Should(Reach(nsX.podA))

			// Not allowed
			eventually30s(nsZ.podA).ShouldNot(Reach(nsX.podA))
			eventually30s(nsZ.podC).ShouldNot(Reach(nsX.podA))
			eventually30s(nsX.podC).ShouldNot(Reach(nsX.podA))
		})

		It("ALLOW traffic to nsX.podA only from (nsY.Name/* AND */podB)", func() {

			m.MakeMultiNetworkPolicy(TestNetwork,
				m.WithPodSelector(metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "a",
					},
				}),
				m.WithIngressRule(multinetpolicyv1.MultiNetworkPolicyIngressRule{
					From: []multinetpolicyv1.MultiNetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"kubernetes.io/metadata.name": nsY.Name,
								},
							},
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"pod": "b",
								},
							},
						},
					},
				}),
				m.CreateInNamespace(cs.K8sCniCncfIoV1beta1Interface, nsX.Name),
			)

			// Allowed

			eventually30s(nsY.podB).Should(Reach(nsX.podA))

			// Not allowed
			eventually30s(nsX.podB).ShouldNot(Reach(nsX.podA))
			eventually30s(nsX.podC).ShouldNot(Reach(nsX.podA))

			eventually30s(nsY.podA).ShouldNot(Reach(nsX.podA))
			eventually30s(nsY.podC).ShouldNot(Reach(nsX.podA))

			eventually30s(nsZ.podA).ShouldNot(Reach(nsX.podA))
			eventually30s(nsZ.podB).ShouldNot(Reach(nsX.podA))
			eventually30s(nsZ.podC).ShouldNot(Reach(nsX.podA))
		})

	})

	Context("Egress", func() {
		It("DENY all traffic from a pod", func() {

			m.MakeMultiNetworkPolicy(TestNetwork,
				m.WithPodSelector(metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "a",
					},
				}),
				m.WithEmptyEgressRules(),
				m.CreateInNamespace(cs.K8sCniCncfIoV1beta1Interface, nsX.Name),
			)

			// Pod B and C are not affected by the policy
			eventually30s(nsX.podB).Should(Reach(nsX.podC))

			// Pod A should not be reacheable by B and C
			eventually30s(nsX.podA).ShouldNot(Reach(nsX.podB))
			eventually30s(nsX.podA).ShouldNot(Reach(nsX.podB))
		})

		It("ALLOW traffic to nsX.podA only from nsX.podB", func() {

			m.MakeMultiNetworkPolicy(TestNetwork,
				m.WithPodSelector(metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "a",
					},
				}),
				m.WithEgressRule(multinetpolicyv1.MultiNetworkPolicyEgressRule{
					To: []multinetpolicyv1.MultiNetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"pod": "b",
							},
						},
					}},
				}),
				m.CreateInNamespace(cs.K8sCniCncfIoV1beta1Interface, nsX.Name),
			)

			// The subject of test case
			eventually30s(nsX.podA).Should(Reach(nsX.podB))
			eventually30s(nsX.podA).ShouldNot(Reach(nsX.podC))

			// Traffic that should not be affected
			eventually30s(nsX.podB).Should(Reach(nsX.podC))
		})
	})

	Context("Ports/Protocol", func() {
		It("Allow access only to a specific port/protocol TCP", func() {

			m.MakeMultiNetworkPolicy(TestNetwork,
				m.WithPodSelector(metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "a",
					},
				}),
				m.WithIngressRule(multinetpolicyv1.MultiNetworkPolicyIngressRule{
					Ports: []multinetpolicyv1.MultiNetworkPolicyPort{{
						Port:     &Port5555,
						Protocol: &ProtoTCP,
					}},
					From: []multinetpolicyv1.MultiNetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"pod": "b",
							},
						},
					}},
				}),
				m.CreateInNamespace(cs.K8sCniCncfIoV1beta1Interface, nsX.Name),
			)

			// Allowed
			eventually30s(nsX.podB).Should(Reach(nsX.podA, OnPort(Port5555), ViaTCP))

			// Not allowed
			eventually30s(nsX.podB).ShouldNot(Reach(nsX.podA, OnPort(Port6666), ViaTCP))
			eventually30s(nsX.podB).ShouldNot(Reach(nsX.podA, OnPort(Port6666), ViaUDP))
			eventually30s(nsX.podB).ShouldNot(Reach(nsX.podA, OnPort(Port5555), ViaUDP))
		})

		It("Allow access only to a specific port/protocol UDP", func() {

			m.MakeMultiNetworkPolicy(TestNetwork,
				m.WithPodSelector(metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "a",
					},
				}),
				m.WithIngressRule(multinetpolicyv1.MultiNetworkPolicyIngressRule{
					Ports: []multinetpolicyv1.MultiNetworkPolicyPort{{
						Port:     &Port6666,
						Protocol: &ProtoUDP,
					}},
					From: []multinetpolicyv1.MultiNetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"pod": "b",
							},
						},
					}},
				}),
				m.CreateInNamespace(cs.K8sCniCncfIoV1beta1Interface, nsX.Name),
			)

			// Allowed
			eventually30s(nsX.podB).Should(Reach(nsX.podA, OnPort(Port6666), ViaUDP))

			// Not allowed
			eventually30s(nsX.podB).ShouldNot(Reach(nsX.podA, OnPort(Port6666), ViaTCP))
			eventually30s(nsX.podB).ShouldNot(Reach(nsX.podA, OnPort(Port5555), ViaUDP))
			eventually30s(nsX.podB).ShouldNot(Reach(nsX.podA, OnPort(Port5555), ViaTCP))
		})

		It("Allow access only to a specific port/protocol TCP+UDP", func() {

			m.MakeMultiNetworkPolicy(TestNetwork,
				m.WithPodSelector(metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "a",
					},
				}),
				m.WithIngressRule(multinetpolicyv1.MultiNetworkPolicyIngressRule{
					Ports: []multinetpolicyv1.MultiNetworkPolicyPort{{
						Port:     &Port5555,
						Protocol: &ProtoTCP,
					}, {
						Port:     &Port6666,
						Protocol: &ProtoUDP,
					}},
					From: []multinetpolicyv1.MultiNetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"pod": "b",
							},
						},
					}},
				}),
				m.CreateInNamespace(cs.K8sCniCncfIoV1beta1Interface, nsX.Name),
			)

			// Allowed
			eventually30s(nsX.podB).Should(Reach(nsX.podA, OnPort(Port5555), ViaTCP))
			eventually30s(nsX.podB).Should(Reach(nsX.podA, OnPort(Port6666), ViaUDP))

			// Not allowed
			eventually30s(nsX.podB).ShouldNot(Reach(nsX.podA, OnPort(Port6666), ViaTCP))
			eventually30s(nsX.podB).ShouldNot(Reach(nsX.podA, OnPort(Port5555), ViaUDP))
		})

		It("Allow access only to a specific UDP port from any pod", func() {

			m.MakeMultiNetworkPolicy(TestNetwork,
				m.WithPodSelector(metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "a",
					},
				}),
				m.WithIngressRule(multinetpolicyv1.MultiNetworkPolicyIngressRule{
					Ports: []multinetpolicyv1.MultiNetworkPolicyPort{{
						Port:     &Port6666,
						Protocol: &ProtoUDP,
					}},
				}),
				m.CreateInNamespace(cs.K8sCniCncfIoV1beta1Interface, nsX.Name),
			)

			// Allowed
			eventually30s(nsX.podB).Should(Reach(nsX.podA, OnPort(Port6666), ViaUDP))

			// Not allowed
			eventually30s(nsX.podB).ShouldNot(Reach(nsX.podA, OnPort(Port5555), ViaTCP))
			eventually30s(nsX.podB).ShouldNot(Reach(nsX.podA, OnPort(Port5555), ViaUDP))
			eventually30s(nsX.podB).ShouldNot(Reach(nsX.podA, OnPort(Port6666), ViaTCP))
		})
	})
})

func cleanMultiNetworkPoliciesFromNamespace(namespace string) {
	err := cs.MultiNetworkPolicies(namespace).
		DeleteCollection(context.Background(), metav1.DeleteOptions{}, metav1.ListOptions{})
	Expect(err).ToNot(HaveOccurred())

	Eventually(func() int {
		ret, err := cs.MultiNetworkPolicies(namespace).
			List(context.Background(), metav1.ListOptions{})
		Expect(err).ToNot(HaveOccurred())
		return len(ret.Items)
	}, 30*time.Second, 1*time.Second).Should(BeZero())
}

func createPodsInNamespace(namespace string) (*corev1.Pod, *corev1.Pod, *corev1.Pod) {

	podA := m.DefinePod(namespace)
	podA.ObjectMeta.GenerateName = "testpod-a-"
	m.AddLabel(podA, "pod", "a")
	m.AddNetwork(podA, TestNetwork)
	AddTCPNetcatServerToPod(podA, Port5555)
	AddTCPNetcatServerToPod(podA, Port6666)
	AddUDPNetcatServerToPod(podA, Port5555)
	AddUDPNetcatServerToPod(podA, Port6666)
	AddIPTableDebugContainer(podA)
	podA = createPod(podA)

	podB := m.DefinePod(namespace)
	podB.ObjectMeta.GenerateName = "testpod-b-"
	m.AddLabel(podB, "pod", "b")
	m.AddNetwork(podB, TestNetwork)
	AddTCPNetcatServerToPod(podB, Port5555)
	AddTCPNetcatServerToPod(podB, Port6666)
	AddUDPNetcatServerToPod(podB, Port5555)
	AddUDPNetcatServerToPod(podB, Port6666)
	AddIPTableDebugContainer(podB)
	podB = createPod(podB)

	podC := m.DefinePod(namespace)
	podC.ObjectMeta.GenerateName = "testpod-c-"
	m.AddLabel(podC, "pod", "c")
	m.AddNetwork(podC, TestNetwork)
	AddTCPNetcatServerToPod(podC, Port5555)
	AddTCPNetcatServerToPod(podC, Port6666)
	AddUDPNetcatServerToPod(podC, Port5555)
	AddUDPNetcatServerToPod(podC, Port6666)
	AddIPTableDebugContainer(podC)
	podC = createPod(podC)

	return podA, podB, podC
}

func createPod(pod *corev1.Pod) *corev1.Pod {
	res, err := cs.Pods(pod.Namespace).
		Create(context.Background(), pod, metav1.CreateOptions{})
	Expect(err).ToNot(HaveOccurred())
	return res
}

func eventually30s(actual interface{}) AsyncAssertion {
	return Eventually(actual, "30s", "1s")
}
