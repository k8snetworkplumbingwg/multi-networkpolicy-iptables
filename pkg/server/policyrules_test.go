/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package server

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/k8snetworkplumbingwg/multi-networkpolicy-iptables/pkg/controllers"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	multifake "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/client/clientset/versioned/fake"
	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netfake "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/fake"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	fakeiptables "k8s.io/kubernetes/pkg/util/iptables/testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var informerFactory informers.SharedInformerFactory

// NewFakeServer creates fake server object for unit-test
func NewFakeServer(hostname string) *Server {
	fakeClient := k8sfake.NewSimpleClientset()
	netClient := netfake.NewSimpleClientset()
	policyClient := multifake.NewSimpleClientset()

	policyChanges := controllers.NewPolicyChangeTracker()
	if policyChanges == nil {
		return nil
	}
	netdefChanges := controllers.NewNetDefChangeTracker()
	if netdefChanges == nil {
		return nil
	}
	nsChanges := controllers.NewNamespaceChangeTracker()
	if nsChanges == nil {
		return nil
	}
	// expects that /var/run/containerd/containerd.sock, for docker/containerd
	hostPrefix := "/"
	networkPlugins := []string{"multi"}
	containerRuntime := controllers.RuntimeKind(controllers.Cri)
	podChanges := controllers.NewPodChangeTracker(containerRuntime, "/var/run/containerd/containerd.sock", hostname, hostPrefix, networkPlugins, netdefChanges)
	if podChanges == nil {
		return nil
	}
	informerFactory = informers.NewSharedInformerFactoryWithOptions(fakeClient, 15*time.Minute)
	podConfig := controllers.NewPodConfig(informerFactory.Core().V1().Pods(), 15*time.Minute)

	nodeRef := &v1.ObjectReference{
		Kind:      "Node",
		Name:      hostname,
		UID:       types.UID(hostname),
		Namespace: "",
	}

	server := &Server{
		Client:              fakeClient,
		Hostname:            hostname,
		NetworkPolicyClient: policyClient,
		NetDefClient:        netClient,
		ConfigSyncPeriod:    15 * time.Minute,
		NodeRef:             nodeRef,
		ip4Tables:           fakeiptables.NewFake(),
		ip6Tables:           fakeiptables.NewIPv6Fake(),
		Options:             &Options{},

		hostPrefix:    hostPrefix,
		policyChanges: policyChanges,
		podChanges:    podChanges,
		netdefChanges: netdefChanges,
		nsChanges:     nsChanges,
		podMap:        make(controllers.PodMap),
		policyMap:     make(controllers.PolicyMap),
		namespaceMap:  make(controllers.NamespaceMap),
		podLister:     informerFactory.Core().V1().Pods().Lister(),
	}
	podConfig.RegisterEventHandler(server)
	informerFactory.Start(wait.NeverStop)
	go podConfig.Run(wait.NeverStop)
	return server
}

func NewFakePodWithNetAnnotation(namespace, name, annot, status string, labels map[string]string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			UID:       "testUID",
			Annotations: map[string]string{
				"k8s.v1.cni.cncf.io/networks": annot,
				netdefv1.NetworkStatusAnnot:   status,
			},
			Labels: labels,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{Name: "ctr1", Image: "image"},
			},
		},
		Status: v1.PodStatus{
			Phase: v1.PodRunning,
		},
	}
}

func AddNamespace(s *Server, name string) {
	namespace := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"nsname": name,
			},
		},
	}
	Expect(s.nsChanges.Update(nil, namespace)).To(BeTrue())
	s.namespaceMap.Update(s.nsChanges)
}

func AddPod(s *Server, pod *v1.Pod) {
	Expect(s.podChanges.Update(nil, pod)).To(BeTrue())
	s.podMap.Update(s.podChanges)
	informerFactory.Core().V1().Pods().Informer().GetIndexer().Add(pod)
}

func NewFakeNetworkStatus(netns, netname, eth0, net1 string) string {
	// dummy interface is for testing not to include dummy ip in iptable rules
	baseStr := `
	[{
            "name": "",
            "interface": "eth0",
            "ips": [
                "%s"
            ],
            "mac": "aa:e1:20:71:15:01",
            "default": true,
            "dns": {}
        },{
            "name": "%s/%s",
            "interface": "net1",
            "ips": [
                "%s"
            ],
            "mac": "42:90:65:12:3e:bf",
            "dns": {}
        },{
            "name": "dummy-interface",
            "interface": "net2",
            "ips": [
                "244.244.244.244"
            ],
            "mac": "42:90:65:12:3e:bf",
            "dns": {}
        }]
`
	return fmt.Sprintf(baseStr, eth0, netns, netname, net1)
}

func NewNetDef(namespace, name, cniConfig string) *netdefv1.NetworkAttachmentDefinition {
	return &netdefv1.NetworkAttachmentDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Spec: netdefv1.NetworkAttachmentDefinitionSpec{
			Config: cniConfig,
		},
	}
}

func NewCNIConfig(cniName, cniType string) string {
	cniConfigTemp := `
	{
		"name": "%s",
		"type": "%s"
	}`
	return fmt.Sprintf(cniConfigTemp, cniName, cniType)
}

func NewCNIConfigList(cniName, cniType string) string {
	cniConfigTemp := `
	{
		"name": "%s",
		"plugins": [
			{
				"type": "%s"
			}]
	}`
	return fmt.Sprintf(cniConfigTemp, cniName, cniType)
}

var _ = Describe("policyrules testing", func() {
	var tmpDir string

	BeforeEach(func() {
		var err error
		tmpDir, err = ioutil.TempDir("", "multi-networkpolicy-iptables")
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		err := os.RemoveAll(tmpDir)
		Expect(err).NotTo(HaveOccurred())
	})

	It("Initialization", func() {
		ipt := fakeiptables.NewFake()
		Expect(ipt).NotTo(BeNil())
		buf := newIptableBuffer()
		Expect(buf).NotTo(BeNil())

		// verify buf initialized at init
		buf.Init(ipt)
		filterChains :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
`
		Expect(buf.filterChains.String()).To(Equal(filterChains))
		Expect(buf.policyIndex.String()).To(Equal(""))
		Expect(buf.ingressPorts.String()).To(Equal(""))
		Expect(buf.ingressFrom.String()).To(Equal(""))
		Expect(buf.egressPorts.String()).To(Equal(""))
		Expect(buf.egressTo.String()).To(Equal(""))

		// finalize buf and verify rules buffer
		buf.FinalizeRules()
		filterRules :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
COMMIT
`
		Expect(buf.filterRules.String()).To(Equal(filterRules))

		// sync and verify iptable
		Expect(buf.SyncRules(ipt)).To(BeNil())
		iptableRules := bytes.NewBuffer(nil)
		ipt.SaveInto(utiliptables.TableFilter, iptableRules)
		Expect(iptableRules.String()).To(Equal(filterRules))

		// reset and verify empty
		buf.Reset()
		Expect(buf.policyIndex.String()).To(Equal(""))
		Expect(buf.ingressPorts.String()).To(Equal(""))
		Expect(buf.ingressFrom.String()).To(Equal(""))
		Expect(buf.egressPorts.String()).To(Equal(""))
		Expect(buf.egressTo.String()).To(Equal(""))
	})

	It("ingress common - default", func() {
		buf4 := newIptableBuffer()
		buf6 := newIptableBuffer()
		Expect(buf4).NotTo(BeNil())
		Expect(buf6).NotTo(BeNil())

		// verify buf initialized at init
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())

		buf4.Init(s.ip4Tables)
		buf6.Init(s.ip6Tables)

		// check IPv4 case
		buf4.renderIngressCommon(s)
		buf4.FinalizeRules()
		finalizedRules4 :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
-A MULTI-INGRESS-COMMON -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A MULTI-INGRESS -j MULTI-INGRESS-COMMON
COMMIT
`
		Expect(buf4.filterRules.String()).To(Equal(finalizedRules4))

		// check IPv6 case
		buf6.renderIngressCommon(s)
		buf6.FinalizeRules()
		finalizedRules6 :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
-A MULTI-INGRESS-COMMON -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A MULTI-INGRESS -j MULTI-INGRESS-COMMON
COMMIT
`
		Expect(buf6.filterRules.String()).To(Equal(finalizedRules6))
	})

	It("ingress common - icmp", func() {
		buf4 := newIptableBuffer()
		buf6 := newIptableBuffer()
		Expect(buf4).NotTo(BeNil())
		Expect(buf6).NotTo(BeNil())

		// verify buf initialized at init
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())
		s.Options.acceptICMP = true

		buf4.Init(s.ip4Tables)
		buf6.Init(s.ip6Tables)

		// check IPv4 case
		buf4.renderIngressCommon(s)
		buf4.FinalizeRules()
		finalizedRules4 :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
-A MULTI-INGRESS-COMMON -p icmp -j ACCEPT
-A MULTI-INGRESS-COMMON -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A MULTI-INGRESS -j MULTI-INGRESS-COMMON
COMMIT
`
		Expect(buf4.filterRules.String()).To(Equal(finalizedRules4))

		// check IPv6 case
		buf6.renderIngressCommon(s)
		buf6.FinalizeRules()
		finalizedRules6 :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
-A MULTI-INGRESS-COMMON -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A MULTI-INGRESS -j MULTI-INGRESS-COMMON
COMMIT
`
		Expect(buf6.filterRules.String()).To(Equal(finalizedRules6))
	})

	It("ingress common - icmpv6", func() {
		buf4 := newIptableBuffer()
		buf6 := newIptableBuffer()
		Expect(buf4).NotTo(BeNil())
		Expect(buf6).NotTo(BeNil())

		// verify buf initialized at init
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())
		s.Options.acceptICMPv6 = true

		buf4.Init(s.ip4Tables)
		buf6.Init(s.ip6Tables)

		// check IPv4 case
		buf4.renderIngressCommon(s)
		buf4.FinalizeRules()
		finalizedRules4 :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
-A MULTI-INGRESS-COMMON -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A MULTI-INGRESS -j MULTI-INGRESS-COMMON
COMMIT
`
		Expect(buf4.filterRules.String()).To(Equal(finalizedRules4))

		// check IPv6 case
		buf6.renderIngressCommon(s)
		buf6.FinalizeRules()
		finalizedRules6 :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
-A MULTI-INGRESS-COMMON -p icmpv6 -j ACCEPT
-A MULTI-INGRESS-COMMON -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A MULTI-INGRESS -j MULTI-INGRESS-COMMON
COMMIT
`
		Expect(buf6.filterRules.String()).To(Equal(finalizedRules6))
	})

	It("ingress common - allow src v6 prefix", func() {
		buf4 := newIptableBuffer()
		buf6 := newIptableBuffer()
		Expect(buf4).NotTo(BeNil())
		Expect(buf6).NotTo(BeNil())

		// verify buf initialized at init
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())
		s.Options.allowIPv6SrcPrefixText = "11::/8 ,   22::/64"
		err := s.Options.Validate()
		Expect(err).NotTo(HaveOccurred())

		buf4.Init(s.ip4Tables)
		buf6.Init(s.ip6Tables)

		// check IPv4 case
		buf4.renderIngressCommon(s)
		buf4.FinalizeRules()
		finalizedRules4 :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
-A MULTI-INGRESS-COMMON -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A MULTI-INGRESS -j MULTI-INGRESS-COMMON
COMMIT
`
		Expect(buf4.filterRules.String()).To(Equal(finalizedRules4))

		// check IPv6 case
		buf6.renderIngressCommon(s)
		buf6.FinalizeRules()
		finalizedRules6 :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
-A MULTI-INGRESS-COMMON -s 11::/8 -j ACCEPT
-A MULTI-INGRESS-COMMON -s 22::/64 -j ACCEPT
-A MULTI-INGRESS-COMMON -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A MULTI-INGRESS -j MULTI-INGRESS-COMMON
COMMIT
`
		Expect(buf6.filterRules.String()).To(Equal(finalizedRules6))
	})

	It("ingress common - allow dst v6 prefix", func() {
		buf4 := newIptableBuffer()
		buf6 := newIptableBuffer()
		Expect(buf4).NotTo(BeNil())
		Expect(buf6).NotTo(BeNil())

		// verify buf initialized at init
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())
		s.Options.allowIPv6DstPrefixText = "11::/8 ,   22::/64"
		Expect(s.Options.Validate()).To(BeNil())

		buf4.Init(s.ip4Tables)
		buf6.Init(s.ip6Tables)

		// check IPv4 case
		buf4.renderIngressCommon(s)
		buf4.FinalizeRules()
		finalizedRules4 :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
-A MULTI-INGRESS-COMMON -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A MULTI-INGRESS -j MULTI-INGRESS-COMMON
COMMIT
`
		Expect(buf4.filterRules.String()).To(Equal(finalizedRules4))

		// check IPv6 case
		buf6.renderIngressCommon(s)
		buf6.FinalizeRules()
		finalizedRules6 :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
-A MULTI-INGRESS-COMMON -d 11::/8 -j ACCEPT
-A MULTI-INGRESS-COMMON -d 22::/64 -j ACCEPT
-A MULTI-INGRESS-COMMON -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A MULTI-INGRESS -j MULTI-INGRESS-COMMON
COMMIT
`
		Expect(buf6.filterRules.String()).To(Equal(finalizedRules6))
	})

	It("ingress common - custom v4 rules", func() {
		tmpRuleFile := filepath.Join(tmpDir, "testInputRules.txt")
		ioutil.WriteFile(tmpRuleFile, []byte(
			`# comment: this accepts DHCP packet
-m udp -p udp --sport bootps --dport bootpc -j ACCEPT
`), 0600)
		buf4 := newIptableBuffer()
		buf6 := newIptableBuffer()
		Expect(buf4).NotTo(BeNil())
		Expect(buf6).NotTo(BeNil())

		// verify buf initialized at init
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())

		// configure rule file and parse it
		s.Options.customIPv4IngressRuleFile = tmpRuleFile
		Expect(s.Options.Validate()).To(BeNil())

		buf4.Init(s.ip4Tables)
		buf6.Init(s.ip6Tables)

		// check IPv4 case
		buf4.renderIngressCommon(s)
		buf4.FinalizeRules()
		finalizedRules4 :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
-A MULTI-INGRESS-COMMON -m udp -p udp --sport bootps --dport bootpc -j ACCEPT
-A MULTI-INGRESS-COMMON -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A MULTI-INGRESS -j MULTI-INGRESS-COMMON
COMMIT
`
		Expect(buf4.filterRules.String()).To(Equal(finalizedRules4))

		// check IPv6 case
		buf6.renderIngressCommon(s)
		buf6.FinalizeRules()
		finalizedRules6 :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
-A MULTI-INGRESS-COMMON -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A MULTI-INGRESS -j MULTI-INGRESS-COMMON
COMMIT
`
		Expect(buf6.filterRules.String()).To(Equal(finalizedRules6))
	})

	It("ingress common - custom v6 rules", func() {
		tmpRuleFile := filepath.Join(tmpDir, "testInputRules.txt")
		ioutil.WriteFile(tmpRuleFile, []byte(
			`# comment: this accepts DHCPv6 packets from link-local address
-m udp -p udp --dport 546 -d fe80::/64 -j ACCEPT
`), 0600)
		buf4 := newIptableBuffer()
		buf6 := newIptableBuffer()
		Expect(buf4).NotTo(BeNil())
		Expect(buf6).NotTo(BeNil())

		// verify buf initialized at init
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())

		// configure rule file and parse it
		s.Options.customIPv6IngressRuleFile = tmpRuleFile
		Expect(s.Options.Validate()).To(BeNil())

		buf4.Init(s.ip4Tables)
		buf6.Init(s.ip6Tables)

		// check IPv4 case
		buf4.renderIngressCommon(s)
		buf4.FinalizeRules()
		finalizedRules4 :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
-A MULTI-INGRESS-COMMON -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A MULTI-INGRESS -j MULTI-INGRESS-COMMON
COMMIT
`
		Expect(buf4.filterRules.String()).To(Equal(finalizedRules4))

		// check IPv6 case
		buf6.renderIngressCommon(s)
		buf6.FinalizeRules()
		finalizedRules6 :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
-A MULTI-INGRESS-COMMON -m udp -p udp --dport 546 -d fe80::/64 -j ACCEPT
-A MULTI-INGRESS-COMMON -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A MULTI-INGRESS -j MULTI-INGRESS-COMMON
COMMIT
`
		Expect(buf6.filterRules.String()).To(Equal(finalizedRules6))
	})

	It("egress common - default", func() {
		buf4 := newIptableBuffer()
		buf6 := newIptableBuffer()
		Expect(buf4).NotTo(BeNil())
		Expect(buf6).NotTo(BeNil())

		// verify buf initialized at init
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())

		buf4.Init(s.ip4Tables)
		buf6.Init(s.ip6Tables)

		// check IPv4 case
		buf4.renderEgressCommon(s)
		buf4.FinalizeRules()
		finalizedRules4 :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
-A MULTI-EGRESS-COMMON -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A MULTI-EGRESS -j MULTI-EGRESS-COMMON
COMMIT
`
		Expect(buf4.filterRules.String()).To(Equal(finalizedRules4))

		// check IPv6 case
		buf6.renderEgressCommon(s)
		buf6.FinalizeRules()
		finalizedRules6 :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
-A MULTI-EGRESS-COMMON -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A MULTI-EGRESS -j MULTI-EGRESS-COMMON
COMMIT
`
		Expect(buf6.filterRules.String()).To(Equal(finalizedRules6))
	})

	It("egress common - icmp", func() {
		buf4 := newIptableBuffer()
		buf6 := newIptableBuffer()
		Expect(buf4).NotTo(BeNil())
		Expect(buf6).NotTo(BeNil())

		// verify buf initialized at init
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())
		s.Options.acceptICMP = true

		buf4.Init(s.ip4Tables)
		buf6.Init(s.ip6Tables)

		// check IPv4 case
		buf4.renderEgressCommon(s)
		buf4.FinalizeRules()
		finalizedRules4 :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
-A MULTI-EGRESS-COMMON -p icmp -j ACCEPT
-A MULTI-EGRESS-COMMON -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A MULTI-EGRESS -j MULTI-EGRESS-COMMON
COMMIT
`
		Expect(buf4.filterRules.String()).To(Equal(finalizedRules4))

		// check IPv6 case
		buf6.renderEgressCommon(s)
		buf6.FinalizeRules()
		finalizedRules6 :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
-A MULTI-EGRESS-COMMON -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A MULTI-EGRESS -j MULTI-EGRESS-COMMON
COMMIT
`
		Expect(buf6.filterRules.String()).To(Equal(finalizedRules6))
	})

	It("egress common - icmpv6", func() {
		buf4 := newIptableBuffer()
		buf6 := newIptableBuffer()
		Expect(buf4).NotTo(BeNil())
		Expect(buf6).NotTo(BeNil())

		// verify buf initialized at init
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())
		s.Options.acceptICMPv6 = true

		buf4.Init(s.ip4Tables)
		buf6.Init(s.ip6Tables)

		// check IPv4 case
		buf4.renderEgressCommon(s)
		buf4.FinalizeRules()
		finalizedRules4 :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
-A MULTI-EGRESS-COMMON -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A MULTI-EGRESS -j MULTI-EGRESS-COMMON
COMMIT
`
		Expect(buf4.filterRules.String()).To(Equal(finalizedRules4))

		// check IPv6 case
		buf6.renderEgressCommon(s)
		buf6.FinalizeRules()
		finalizedRules6 :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
-A MULTI-EGRESS-COMMON -p icmpv6 -j ACCEPT
-A MULTI-EGRESS-COMMON -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A MULTI-EGRESS -j MULTI-EGRESS-COMMON
COMMIT
`
		Expect(buf6.filterRules.String()).To(Equal(finalizedRules6))
	})

	It("egress common - allow src v6 prefix", func() {
		buf4 := newIptableBuffer()
		buf6 := newIptableBuffer()
		Expect(buf4).NotTo(BeNil())
		Expect(buf6).NotTo(BeNil())

		// verify buf initialized at init
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())
		s.Options.allowIPv6SrcPrefixText = "11::/8 ,   22::/64"
		Expect(s.Options.Validate()).To(BeNil())

		buf4.Init(s.ip4Tables)
		buf6.Init(s.ip6Tables)

		// check IPv4 case
		buf4.renderEgressCommon(s)
		buf4.FinalizeRules()
		finalizedRules4 :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
-A MULTI-EGRESS-COMMON -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A MULTI-EGRESS -j MULTI-EGRESS-COMMON
COMMIT
`
		Expect(buf4.filterRules.String()).To(Equal(finalizedRules4))

		// check IPv6 case
		buf6.renderEgressCommon(s)
		buf6.FinalizeRules()
		finalizedRules6 :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
-A MULTI-EGRESS-COMMON -s 11::/8 -j ACCEPT
-A MULTI-EGRESS-COMMON -s 22::/64 -j ACCEPT
-A MULTI-EGRESS-COMMON -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A MULTI-EGRESS -j MULTI-EGRESS-COMMON
COMMIT
`
		Expect(buf6.filterRules.String()).To(Equal(finalizedRules6))
	})

	It("egress common - allow dest v6 prefix", func() {
		buf4 := newIptableBuffer()
		buf6 := newIptableBuffer()
		Expect(buf4).NotTo(BeNil())
		Expect(buf6).NotTo(BeNil())

		// verify buf initialized at init
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())
		s.Options.allowIPv6DstPrefixText = "11::/8 ,   22::/64"
		Expect(s.Options.Validate()).To(BeNil())

		buf4.Init(s.ip4Tables)
		buf6.Init(s.ip6Tables)

		// check IPv4 case
		buf4.renderEgressCommon(s)
		buf4.FinalizeRules()
		finalizedRules4 :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
-A MULTI-EGRESS-COMMON -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A MULTI-EGRESS -j MULTI-EGRESS-COMMON
COMMIT
`
		Expect(buf4.filterRules.String()).To(Equal(finalizedRules4))

		// check IPv6 case
		buf6.renderEgressCommon(s)
		buf6.FinalizeRules()
		finalizedRules6 :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
-A MULTI-EGRESS-COMMON -d 11::/8 -j ACCEPT
-A MULTI-EGRESS-COMMON -d 22::/64 -j ACCEPT
-A MULTI-EGRESS-COMMON -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A MULTI-EGRESS -j MULTI-EGRESS-COMMON
COMMIT
`
		Expect(buf6.filterRules.String()).To(Equal(finalizedRules6))
	})

	It("egress common - custom v4 rules", func() {
		tmpRuleFile := filepath.Join(tmpDir, "testInputRules.txt")
		ioutil.WriteFile(tmpRuleFile, []byte(
			`# comment: this rules accepts DHCP packets
-m udp -p udp --sport bootc --dport bootps -j ACCEPT
`), 0600)
		buf4 := newIptableBuffer()
		buf6 := newIptableBuffer()
		Expect(buf4).NotTo(BeNil())
		Expect(buf6).NotTo(BeNil())

		// verify buf initialized at init
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())

		// configure rule file and parse it
		s.Options.customIPv4EgressRuleFile = tmpRuleFile
		Expect(s.Options.Validate()).To(BeNil())

		buf4.Init(s.ip4Tables)
		buf6.Init(s.ip6Tables)

		// check IPv4 case
		buf4.renderEgressCommon(s)
		buf4.FinalizeRules()
		finalizedRules4 :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
-A MULTI-EGRESS-COMMON -m udp -p udp --sport bootc --dport bootps -j ACCEPT
-A MULTI-EGRESS-COMMON -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A MULTI-EGRESS -j MULTI-EGRESS-COMMON
COMMIT
`
		Expect(buf4.filterRules.String()).To(Equal(finalizedRules4))

		// check IPv6 case
		buf6.renderEgressCommon(s)
		buf6.FinalizeRules()
		finalizedRules6 :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
-A MULTI-EGRESS-COMMON -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A MULTI-EGRESS -j MULTI-EGRESS-COMMON
COMMIT
`
		Expect(buf6.filterRules.String()).To(Equal(finalizedRules6))
	})

	It("egress common - custom v6 rules", func() {
		tmpRuleFile := filepath.Join(tmpDir, "testInputRules.txt")
		ioutil.WriteFile(tmpRuleFile, []byte(
			`# comment: this rules accepts DHCPv6 packet to dhcp relay agents/servers
-m udp -p udp --dport 547 -d ff02::1:2 -j ACCEPT
`), 0600)
		buf4 := newIptableBuffer()
		buf6 := newIptableBuffer()
		Expect(buf4).NotTo(BeNil())
		Expect(buf6).NotTo(BeNil())

		// verify buf initialized at init
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())

		// configure rule file and parse it
		s.Options.customIPv6EgressRuleFile = tmpRuleFile
		Expect(s.Options.Validate()).To(BeNil())

		buf4.Init(s.ip4Tables)
		buf6.Init(s.ip6Tables)

		// check IPv4 case
		buf4.renderEgressCommon(s)
		buf4.FinalizeRules()
		finalizedRules4 :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
-A MULTI-EGRESS-COMMON -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A MULTI-EGRESS -j MULTI-EGRESS-COMMON
COMMIT
`
		Expect(buf4.filterRules.String()).To(Equal(finalizedRules4))

		// check IPv6 case
		buf6.renderEgressCommon(s)
		buf6.FinalizeRules()
		finalizedRules6 :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
-A MULTI-EGRESS-COMMON -m udp -p udp --dport 547 -d ff02::1:2 -j ACCEPT
-A MULTI-EGRESS-COMMON -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A MULTI-EGRESS -j MULTI-EGRESS-COMMON
COMMIT
`
		Expect(buf6.filterRules.String()).To(Equal(finalizedRules6))
	})

	It("ingress rules ipblock", func() {
		port := intstr.FromInt(8888)
		protoTCP := v1.ProtocolTCP
		ingressPolicies1 := &multiv1beta1.MultiNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ingressPolicies1",
				Namespace: "testns1",
			},
			Spec: multiv1beta1.MultiNetworkPolicySpec{
				Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
					{
						Ports: []multiv1beta1.MultiNetworkPolicyPort{
							{
								Protocol: &protoTCP,
								Port:     &port,
							},
						},
						From: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								IPBlock: &multiv1beta1.IPBlock{
									CIDR:   "10.1.1.1/24",
									Except: []string{"10.1.1.254"},
								},
							},
						},
					},
				},
			},
		}

		ipt := fakeiptables.NewFake()
		Expect(ipt).NotTo(BeNil())
		buf := newIptableBuffer()
		Expect(buf).NotTo(BeNil())

		// verify buf initialized at init
		buf.Init(ipt)
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())

		Expect(s.netdefChanges.Update(
			nil,
			NewNetDef("testns1", "net-attach1", NewCNIConfig("testCNI", "multi")))).To(BeTrue())
		Expect(s.netdefChanges.GetPluginType(types.NamespacedName{Namespace: "testns1", Name: "net-attach1"})).To(Equal("multi"))

		pod1 := NewFakePodWithNetAnnotation(
			"testns1",
			"testpod1",
			"net-attach1",
			NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.1", "10.1.1.1"),
			nil)
		AddPod(s, pod1)
		podInfo1, err := s.podMap.GetPodInfo(pod1)
		Expect(err).NotTo(HaveOccurred())

		buf.renderIngress(s, podInfo1, 0, ingressPolicies1, []string{"testns1/net-attach1"})

		portRules := `-A MULTI-0-INGRESS-0-PORTS -i net1 -m tcp -p tcp --dport 8888 -j MARK --set-xmark 0x10000/0x10000
`
		Expect(buf.ingressPorts.String()).To(Equal(portRules))

		fromRules :=
			`-A MULTI-0-INGRESS-0-FROM -i net1 -s 10.1.1.254 -j DROP
-A MULTI-0-INGRESS-0-FROM -i net1 -s 10.1.1.1/24 -j MARK --set-xmark 0x20000/0x20000
-A MULTI-0-INGRESS-0-FROM -i net1 -s 10.1.1.1 -j MARK --set-xmark 0x20000/0x20000
`
		Expect(buf.ingressFrom.String()).To(Equal(fromRules))

		buf.FinalizeRules()
		finalizedRules :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
:MULTI-0-INGRESS - [0:0]
:MULTI-0-INGRESS-0-PORTS - [0:0]
:MULTI-0-INGRESS-0-FROM - [0:0]
-A MULTI-INGRESS -m comment --comment "policy:ingressPolicies1 net-attach-def:testns1/net-attach1" -i net1 -j MULTI-0-INGRESS
-A MULTI-INGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-INGRESS -j MARK --set-xmark 0x0/0x30000
-A MULTI-0-INGRESS -j MULTI-0-INGRESS-0-PORTS
-A MULTI-0-INGRESS -j MULTI-0-INGRESS-0-FROM
-A MULTI-0-INGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-INGRESS-0-PORTS -i net1 -m tcp -p tcp --dport 8888 -j MARK --set-xmark 0x10000/0x10000
-A MULTI-0-INGRESS-0-FROM -i net1 -s 10.1.1.254 -j DROP
-A MULTI-0-INGRESS-0-FROM -i net1 -s 10.1.1.1/24 -j MARK --set-xmark 0x20000/0x20000
-A MULTI-0-INGRESS-0-FROM -i net1 -s 10.1.1.1 -j MARK --set-xmark 0x20000/0x20000
COMMIT
`
		Expect(buf.filterRules.String()).To(Equal(finalizedRules))
	})

	It("ingress rules podselector/matchlabels", func() {
		port := intstr.FromInt(8888)
		protoTCP := v1.ProtocolTCP
		ingressPolicies1 := &multiv1beta1.MultiNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ingressPolicies1",
				Namespace: "testns1",
			},
			Spec: multiv1beta1.MultiNetworkPolicySpec{
				Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
					{
						Ports: []multiv1beta1.MultiNetworkPolicyPort{
							{
								Protocol: &protoTCP,
								Port:     &port,
							},
						},
						From: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"foobar": "enabled",
									},
								},
							},
						},
					},
				},
			},
		}

		ipt := fakeiptables.NewFake()
		Expect(ipt).NotTo(BeNil())
		buf := newIptableBuffer()
		Expect(buf).NotTo(BeNil())

		// verify buf initialized at init
		buf.Init(ipt)
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())

		AddNamespace(s, "testns1")

		Expect(s.netdefChanges.Update(
			nil,
			NewNetDef("testns1", "net-attach1", NewCNIConfig("testCNI", "multi")))).To(BeTrue())
		Expect(s.netdefChanges.GetPluginType(types.NamespacedName{Namespace: "testns1", Name: "net-attach1"})).To(Equal("multi"))

		pod1 := NewFakePodWithNetAnnotation(
			"testns1",
			"testpod1",
			"net-attach1",
			NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.1", "10.1.1.1"),
			nil)
		AddPod(s, pod1)
		podInfo1, err := s.podMap.GetPodInfo(pod1)
		Expect(err).NotTo(HaveOccurred())

		pod2 := NewFakePodWithNetAnnotation(
			"testns1",
			"testpod2",
			"net-attach1",
			NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.2", "10.1.1.2"),
			map[string]string{
				"foobar": "enabled",
			})
		AddPod(s, pod2)

		buf.renderIngress(s, podInfo1, 0, ingressPolicies1, []string{"testns1/net-attach1"})

		portRules := `-A MULTI-0-INGRESS-0-PORTS -i net1 -m tcp -p tcp --dport 8888 -j MARK --set-xmark 0x10000/0x10000
`
		Expect(buf.ingressPorts.String()).To(Equal(portRules))

		fromRules :=
			`-A MULTI-0-INGRESS-0-FROM -i net1 -s 10.1.1.2 -j MARK --set-xmark 0x20000/0x20000
-A MULTI-0-INGRESS-0-FROM -i net1 -s 10.1.1.1 -j MARK --set-xmark 0x20000/0x20000
`
		Expect(buf.ingressFrom.String()).To(Equal(fromRules))

		buf.FinalizeRules()
		finalizedRules :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
:MULTI-0-INGRESS - [0:0]
:MULTI-0-INGRESS-0-PORTS - [0:0]
:MULTI-0-INGRESS-0-FROM - [0:0]
-A MULTI-INGRESS -m comment --comment "policy:ingressPolicies1 net-attach-def:testns1/net-attach1" -i net1 -j MULTI-0-INGRESS
-A MULTI-INGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-INGRESS -j MARK --set-xmark 0x0/0x30000
-A MULTI-0-INGRESS -j MULTI-0-INGRESS-0-PORTS
-A MULTI-0-INGRESS -j MULTI-0-INGRESS-0-FROM
-A MULTI-0-INGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-INGRESS-0-PORTS -i net1 -m tcp -p tcp --dport 8888 -j MARK --set-xmark 0x10000/0x10000
-A MULTI-0-INGRESS-0-FROM -i net1 -s 10.1.1.2 -j MARK --set-xmark 0x20000/0x20000
-A MULTI-0-INGRESS-0-FROM -i net1 -s 10.1.1.1 -j MARK --set-xmark 0x20000/0x20000
COMMIT
`
		Expect(buf.filterRules.String()).To(Equal(finalizedRules))
	})

	It("ingress rules namespace selector", func() {
		ingressPolicies1 := &multiv1beta1.MultiNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ingressPolicies1",
				Namespace: "testns1",
			},
			Spec: multiv1beta1.MultiNetworkPolicySpec{
				Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
					{
						From: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								NamespaceSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"nsname": "testns2",
									},
								},
							},
						},
					},
				},
			},
		}

		ipt := fakeiptables.NewFake()
		Expect(ipt).NotTo(BeNil())
		buf := newIptableBuffer()
		Expect(buf).NotTo(BeNil())

		// verify buf initialized at init
		buf.Init(ipt)
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())

		AddNamespace(s, "testns1")
		AddNamespace(s, "testns2")

		Expect(s.netdefChanges.Update(
			nil,
			NewNetDef("testns1", "net-attach1", NewCNIConfig("testCNI", "multi")))).To(BeTrue())
		Expect(s.netdefChanges.GetPluginType(types.NamespacedName{Namespace: "testns1", Name: "net-attach1"})).To(Equal("multi"))
		Expect(s.netdefChanges.Update(
			nil,
			NewNetDef("testns2", "net-attach1", NewCNIConfig("testCNI", "multi")))).To(BeTrue())
		Expect(s.netdefChanges.GetPluginType(types.NamespacedName{Namespace: "testns2", Name: "net-attach1"})).To(Equal("multi"))

		pod1 := NewFakePodWithNetAnnotation(
			"testns1",
			"testpod1",
			"net-attach1",
			NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.1", "10.1.1.1"),
			nil)
		AddPod(s, pod1)
		podInfo1, err := s.podMap.GetPodInfo(pod1)
		Expect(err).NotTo(HaveOccurred())

		pod2 := NewFakePodWithNetAnnotation(
			"testns2",
			"testpod2",
			"net-attach1",
			NewFakeNetworkStatus("testns2", "net-attach1", "192.168.1.2", "10.1.1.2"),
			nil)
		AddPod(s, pod2)
		buf.renderIngress(s, podInfo1, 0, ingressPolicies1, []string{"testns1/net-attach1", "testns2/net-attach1"})

		buf.FinalizeRules()
		finalizedRules :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
:MULTI-0-INGRESS - [0:0]
:MULTI-0-INGRESS-0-PORTS - [0:0]
:MULTI-0-INGRESS-0-FROM - [0:0]
-A MULTI-INGRESS -m comment --comment "policy:ingressPolicies1 net-attach-def:testns1/net-attach1" -i net1 -j MULTI-0-INGRESS
-A MULTI-INGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-INGRESS -j MARK --set-xmark 0x0/0x30000
-A MULTI-0-INGRESS -j MULTI-0-INGRESS-0-PORTS
-A MULTI-0-INGRESS -j MULTI-0-INGRESS-0-FROM
-A MULTI-0-INGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-INGRESS-0-PORTS -m comment --comment "no ingress ports, skipped" -j MARK --set-xmark 0x10000/0x10000
-A MULTI-0-INGRESS-0-FROM -i net1 -s 10.1.1.2 -j MARK --set-xmark 0x20000/0x20000
-A MULTI-0-INGRESS-0-FROM -i net1 -s 10.1.1.1 -j MARK --set-xmark 0x20000/0x20000
COMMIT
`

		Expect(buf.filterRules.String()).To(Equal(string(finalizedRules)))
	})

	It("enforce policy with net-attach-def in a different namespace than pods", func() {
		ingressPolicies1 := &multiv1beta1.MultiNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ingressPolicies1",
				Namespace: "testns1",
			},
			Spec: multiv1beta1.MultiNetworkPolicySpec{
				Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
					{
						From: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								NamespaceSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"nsname": "testns2",
									},
								},
							},
						},
					},
				},
			},
		}

		ipt := fakeiptables.NewFake()
		Expect(ipt).NotTo(BeNil())
		buf := newIptableBuffer()
		Expect(buf).NotTo(BeNil())

		// verify buf initialized at init
		buf.Init(ipt)
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())

		AddNamespace(s, "default")
		AddNamespace(s, "testns1")
		AddNamespace(s, "testns2")

		Expect(s.netdefChanges.Update(
			nil,
			NewNetDef("default", "net-attach1", NewCNIConfig("testCNI", "multi")))).To(BeTrue())
		Expect(s.netdefChanges.GetPluginType(types.NamespacedName{Namespace: "default", Name: "net-attach1"})).To(Equal("multi"))

		pod1 := NewFakePodWithNetAnnotation(
			"testns1",
			"testpod1",
			"default/net-attach1",
			NewFakeNetworkStatus("default", "net-attach1", "192.168.1.1", "10.1.1.1"),
			nil)
		AddPod(s, pod1)
		podInfo1, err := s.podMap.GetPodInfo(pod1)
		Expect(err).NotTo(HaveOccurred())

		pod2 := NewFakePodWithNetAnnotation(
			"testns2",
			"testpod2",
			"default/net-attach1",
			NewFakeNetworkStatus("default", "net-attach1", "192.168.1.2", "10.1.1.2"),
			nil)
		AddPod(s, pod2)
		buf.renderIngress(s, podInfo1, 0, ingressPolicies1, []string{"default/net-attach1"})

		buf.FinalizeRules()
		finalizedRules :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
:MULTI-0-INGRESS - [0:0]
:MULTI-0-INGRESS-0-PORTS - [0:0]
:MULTI-0-INGRESS-0-FROM - [0:0]
-A MULTI-INGRESS -m comment --comment "policy:ingressPolicies1 net-attach-def:default/net-attach1" -i net1 -j MULTI-0-INGRESS
-A MULTI-INGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-INGRESS -j MARK --set-xmark 0x0/0x30000
-A MULTI-0-INGRESS -j MULTI-0-INGRESS-0-PORTS
-A MULTI-0-INGRESS -j MULTI-0-INGRESS-0-FROM
-A MULTI-0-INGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-INGRESS-0-PORTS -m comment --comment "no ingress ports, skipped" -j MARK --set-xmark 0x10000/0x10000
-A MULTI-0-INGRESS-0-FROM -i net1 -s 10.1.1.2 -j MARK --set-xmark 0x20000/0x20000
-A MULTI-0-INGRESS-0-FROM -i net1 -s 10.1.1.1 -j MARK --set-xmark 0x20000/0x20000
COMMIT
`
		Expect(buf.filterRules.String()).To(Equal(string(finalizedRules)))
	})

	It("egress rules ipblock", func() {
		port := intstr.FromInt(8888)
		protoTCP := v1.ProtocolTCP
		egressPolicies1 := &multiv1beta1.MultiNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "EgressPolicies1",
				Namespace: "testns1",
			},
			Spec: multiv1beta1.MultiNetworkPolicySpec{
				Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
					{
						Ports: []multiv1beta1.MultiNetworkPolicyPort{
							{
								Protocol: &protoTCP,
								Port:     &port,
							},
						},
						To: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								IPBlock: &multiv1beta1.IPBlock{
									CIDR:   "10.1.1.1/24",
									Except: []string{"10.1.1.254"},
								},
							},
						},
					},
				},
			},
		}

		ipt := fakeiptables.NewFake()
		Expect(ipt).NotTo(BeNil())
		buf := newIptableBuffer()
		Expect(buf).NotTo(BeNil())

		// verify buf initialized at init
		buf.Init(ipt)
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())

		Expect(s.netdefChanges.Update(
			nil,
			NewNetDef("testns1", "net-attach1", NewCNIConfig("testCNI", "multi")))).To(BeTrue())
		Expect(s.netdefChanges.GetPluginType(types.NamespacedName{Namespace: "testns1", Name: "net-attach1"})).To(Equal("multi"))

		pod1 := NewFakePodWithNetAnnotation(
			"testns1",
			"testpod1",
			"net-attach1",
			NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.1", "10.1.1.1"),
			nil)
		AddPod(s, pod1)
		podInfo1, err := s.podMap.GetPodInfo(pod1)
		Expect(err).NotTo(HaveOccurred())

		buf.renderEgress(s, podInfo1, 0, egressPolicies1, []string{"testns1/net-attach1"})

		portRules := `-A MULTI-0-EGRESS-0-PORTS -o net1 -m tcp -p tcp --dport 8888 -j MARK --set-xmark 0x10000/0x10000
`
		Expect(buf.egressPorts.String()).To(Equal(portRules))

		toRules :=
			`-A MULTI-0-EGRESS-0-TO -o net1 -d 10.1.1.254 -j DROP
-A MULTI-0-EGRESS-0-TO -o net1 -d 10.1.1.1/24 -j MARK --set-xmark 0x20000/0x20000
-A MULTI-0-EGRESS-0-TO -o net1 -d 10.1.1.1 -j MARK --set-xmark 0x20000/0x20000
`
		Expect(buf.egressTo.String()).To(Equal(toRules))

		buf.FinalizeRules()
		finalizedRules :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
:MULTI-0-EGRESS - [0:0]
:MULTI-0-EGRESS-0-PORTS - [0:0]
:MULTI-0-EGRESS-0-TO - [0:0]
-A MULTI-EGRESS -m comment --comment "policy:EgressPolicies1 net-attach-def:testns1/net-attach1" -o net1 -j MULTI-0-EGRESS
-A MULTI-EGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-EGRESS -j MARK --set-xmark 0x0/0x30000
-A MULTI-0-EGRESS -j MULTI-0-EGRESS-0-PORTS
-A MULTI-0-EGRESS -j MULTI-0-EGRESS-0-TO
-A MULTI-0-EGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-EGRESS-0-PORTS -o net1 -m tcp -p tcp --dport 8888 -j MARK --set-xmark 0x10000/0x10000
-A MULTI-0-EGRESS-0-TO -o net1 -d 10.1.1.254 -j DROP
-A MULTI-0-EGRESS-0-TO -o net1 -d 10.1.1.1/24 -j MARK --set-xmark 0x20000/0x20000
-A MULTI-0-EGRESS-0-TO -o net1 -d 10.1.1.1 -j MARK --set-xmark 0x20000/0x20000
COMMIT
`
		Expect(buf.filterRules.String()).To(Equal(finalizedRules))
	})

	It("egress rules podselector/matchlabels", func() {
		port := intstr.FromInt(8888)
		protoTCP := v1.ProtocolTCP
		egressPolicies1 := &multiv1beta1.MultiNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "EgressPolicies1",
				Namespace: "testns1",
			},
			Spec: multiv1beta1.MultiNetworkPolicySpec{
				Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
					{
						Ports: []multiv1beta1.MultiNetworkPolicyPort{
							{
								Protocol: &protoTCP,
								Port:     &port,
							},
						},
						To: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"foobar": "enabled",
									},
								},
							},
						},
					},
				},
			},
		}

		ipt := fakeiptables.NewFake()
		Expect(ipt).NotTo(BeNil())
		buf := newIptableBuffer()
		Expect(buf).NotTo(BeNil())

		// verify buf initialized at init
		buf.Init(ipt)
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())

		AddNamespace(s, "testns1")

		Expect(s.netdefChanges.Update(
			nil,
			NewNetDef("testns1", "net-attach1", NewCNIConfig("testCNI", "multi")))).To(BeTrue())
		Expect(s.netdefChanges.GetPluginType(types.NamespacedName{Namespace: "testns1", Name: "net-attach1"})).To(Equal("multi"))

		pod1 := NewFakePodWithNetAnnotation(
			"testns1",
			"testpod1",
			"net-attach1",
			NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.1", "10.1.1.1"),
			nil)
		AddPod(s, pod1)
		podInfo1, err := s.podMap.GetPodInfo(pod1)
		Expect(err).NotTo(HaveOccurred())

		pod2 := NewFakePodWithNetAnnotation(
			"testns1",
			"testpod2",
			"net-attach1",
			NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.2", "10.1.1.2"),
			map[string]string{
				"foobar": "enabled",
			})
		AddPod(s, pod2)

		buf.renderEgress(s, podInfo1, 0, egressPolicies1, []string{"testns1/net-attach1"})

		portRules := `-A MULTI-0-EGRESS-0-PORTS -o net1 -m tcp -p tcp --dport 8888 -j MARK --set-xmark 0x10000/0x10000
`
		Expect(buf.egressPorts.String()).To(Equal(portRules))

		toRules :=
			`-A MULTI-0-EGRESS-0-TO -o net1 -d 10.1.1.2 -j MARK --set-xmark 0x20000/0x20000
-A MULTI-0-EGRESS-0-TO -o net1 -d 10.1.1.1 -j MARK --set-xmark 0x20000/0x20000
`
		Expect(buf.egressTo.String()).To(Equal(toRules))

		buf.FinalizeRules()
		finalizedRules :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
:MULTI-0-EGRESS - [0:0]
:MULTI-0-EGRESS-0-PORTS - [0:0]
:MULTI-0-EGRESS-0-TO - [0:0]
-A MULTI-EGRESS -m comment --comment "policy:EgressPolicies1 net-attach-def:testns1/net-attach1" -o net1 -j MULTI-0-EGRESS
-A MULTI-EGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-EGRESS -j MARK --set-xmark 0x0/0x30000
-A MULTI-0-EGRESS -j MULTI-0-EGRESS-0-PORTS
-A MULTI-0-EGRESS -j MULTI-0-EGRESS-0-TO
-A MULTI-0-EGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-EGRESS-0-PORTS -o net1 -m tcp -p tcp --dport 8888 -j MARK --set-xmark 0x10000/0x10000
-A MULTI-0-EGRESS-0-TO -o net1 -d 10.1.1.2 -j MARK --set-xmark 0x20000/0x20000
-A MULTI-0-EGRESS-0-TO -o net1 -d 10.1.1.1 -j MARK --set-xmark 0x20000/0x20000
COMMIT
`
		Expect(buf.filterRules.String()).To(Equal(finalizedRules))
	})

	It("default values", func() {
		port := intstr.FromInt(8888)
		policies1 := &multiv1beta1.MultiNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "policies1",
				Namespace: "testns1",
			},
			Spec: multiv1beta1.MultiNetworkPolicySpec{
				Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
					{
						Ports: []multiv1beta1.MultiNetworkPolicyPort{
							{
								Port: &port,
							},
						},
					},
				},
				Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
					{
						Ports: []multiv1beta1.MultiNetworkPolicyPort{
							{
								Port: &port,
							},
						},
					},
				},
			},
		}

		ipt := fakeiptables.NewFake()
		Expect(ipt).NotTo(BeNil())
		buf := newIptableBuffer()
		Expect(buf).NotTo(BeNil())
		buf.Init(ipt)

		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())

		AddNamespace(s, "testns1")

		Expect(s.netdefChanges.Update(
			nil,
			NewNetDef("testns1", "net-attach1", NewCNIConfig("testCNI", "multi"))),
		).To(BeTrue())
		Expect(s.netdefChanges.GetPluginType(types.NamespacedName{Namespace: "testns1", Name: "net-attach1"})).
			To(Equal("multi"))

		pod1 := NewFakePodWithNetAnnotation(
			"testns1",
			"testpod1",
			"net-attach1",
			NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.1", "10.1.1.1"),
			nil)
		AddPod(s, pod1)
		podInfo1, err := s.podMap.GetPodInfo(pod1)
		Expect(err).NotTo(HaveOccurred())

		buf.renderIngress(s, podInfo1, 0, policies1, []string{"testns1/net-attach1"})
		buf.renderEgress(s, podInfo1, 0, policies1, []string{"testns1/net-attach1"})

		portRules := `-A MULTI-0-INGRESS-0-PORTS -i net1 -m tcp -p tcp --dport 8888 -j MARK --set-xmark 0x10000/0x10000
`
		Expect(buf.ingressPorts.String()).To(Equal(portRules))

		portRules = `-A MULTI-0-EGRESS-0-PORTS -o net1 -m tcp -p tcp --dport 8888 -j MARK --set-xmark 0x10000/0x10000
`
		Expect(buf.egressPorts.String()).To(Equal(portRules))
	})

	It("policyType should be implicitly inferred", func() {

		policy1 := &multiv1beta1.MultiNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ingressPolicies1",
				Namespace: "testns1",
				Annotations: map[string]string{
					PolicyNetworkAnnotation: "net-attach1",
				},
			},
			Spec: multiv1beta1.MultiNetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"role": "targetpod",
					},
				},
				Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{{
					From: []multiv1beta1.MultiNetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"foobar": "enabled",
							},
						},
					}},
				}},
			},
		}

		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())

		AddNamespace(s, "testns1")

		Expect(
			s.netdefChanges.Update(nil, NewNetDef("testns1", "net-attach1", NewCNIConfig("testCNI", "multi"))),
		).To(BeTrue())

		pod1 := NewFakePodWithNetAnnotation(
			"testns1",
			"testpod1",
			"net-attach1",
			NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.1", "10.1.1.1"),
			map[string]string{
				"role": "targetpod",
			})
		pod1.Spec.NodeName = "samplehost"

		AddPod(s, pod1)
		podInfo1, err := s.podMap.GetPodInfo(pod1)
		Expect(err).NotTo(HaveOccurred())

		pod2 := NewFakePodWithNetAnnotation(
			"testns1",
			"testpod2",
			"net-attach1",
			NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.2", "10.1.1.2"),
			map[string]string{
				"foobar": "enabled",
			})
		AddPod(s, pod2)

		Expect(
			s.policyChanges.Update(nil, policy1),
		).To(BeTrue())
		s.policyMap.Update(s.policyChanges)

		result := fakeiptables.NewFake()
		s.ip4Tables = result

		s.generatePolicyRulesForPod(pod1, podInfo1)

		Expect(string(result.Lines)).To(Equal(`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
:MULTI-0-INGRESS - [0:0]
:MULTI-0-INGRESS-0-PORTS - [0:0]
:MULTI-0-INGRESS-0-FROM - [0:0]
-A MULTI-INGRESS-COMMON -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A MULTI-INGRESS -j MULTI-INGRESS-COMMON
-A MULTI-INGRESS -m comment --comment "policy:ingressPolicies1 net-attach-def:testns1/net-attach1" -i net1 -j MULTI-0-INGRESS
-A MULTI-INGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-INGRESS -j MARK --set-xmark 0x0/0x30000
-A MULTI-0-INGRESS -j MULTI-0-INGRESS-0-PORTS
-A MULTI-0-INGRESS -j MULTI-0-INGRESS-0-FROM
-A MULTI-0-INGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-INGRESS -j DROP
-A MULTI-0-INGRESS-0-PORTS -m comment --comment "no ingress ports, skipped" -j MARK --set-xmark 0x10000/0x10000
-A MULTI-0-INGRESS-0-FROM -i net1 -s 10.1.1.2 -j MARK --set-xmark 0x20000/0x20000
-A MULTI-0-INGRESS-0-FROM -i net1 -s 10.1.1.1 -j MARK --set-xmark 0x20000/0x20000
COMMIT
`))

	})

	Context("IPv6", func() {
		It("shoud avoid using IPv4 addresses on ip6tables", func() {

			policy1 := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingressPolicies1",
					Namespace: "testns1",
				},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{{
						From: []multiv1beta1.MultiNetworkPolicyPeer{{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"foobar": "enabled",
								},
							},
						}},
					}},
					Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{{
						To: []multiv1beta1.MultiNetworkPolicyPeer{{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"foobar": "enabled",
								},
							},
						}},
					}},
				},
			}

			s := NewFakeServer("samplehost")
			Expect(s).NotTo(BeNil())

			AddNamespace(s, "testns1")

			Expect(
				s.netdefChanges.Update(nil, NewNetDef("testns1", "net-attach1", NewCNIConfig("testCNI", "multi"))),
			).To(BeTrue())

			pod1 := NewFakePodWithNetAnnotation(
				"testns1",
				"testpod1",
				"net-attach1",
				NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.1", "10.1.1.1"),
				nil)
			AddPod(s, pod1)
			podInfo1, err := s.podMap.GetPodInfo(pod1)
			Expect(err).NotTo(HaveOccurred())

			pod2 := NewFakePodWithNetAnnotation(
				"testns1",
				"testpod2",
				"net-attach1",
				NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.2", "10.1.1.2"),
				map[string]string{
					"foobar": "enabled",
				})
			AddPod(s, pod2)

			ipt := fakeiptables.NewIPv6Fake()
			buf := newIptableBuffer()
			buf.Init(ipt)

			buf.renderIngress(s, podInfo1, 0, policy1, []string{"testns1/net-attach1"})
			buf.renderEgress(s, podInfo1, 0, policy1, []string{"testns1/net-attach1"})

			buf.FinalizeRules()

			expectedRules :=
				`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
:MULTI-0-INGRESS - [0:0]
:MULTI-0-INGRESS-0-PORTS - [0:0]
:MULTI-0-INGRESS-0-FROM - [0:0]
:MULTI-0-EGRESS - [0:0]
:MULTI-0-EGRESS-0-PORTS - [0:0]
:MULTI-0-EGRESS-0-TO - [0:0]
-A MULTI-INGRESS -m comment --comment "policy:ingressPolicies1 net-attach-def:testns1/net-attach1" -i net1 -j MULTI-0-INGRESS
-A MULTI-INGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-INGRESS -j MARK --set-xmark 0x0/0x30000
-A MULTI-0-INGRESS -j MULTI-0-INGRESS-0-PORTS
-A MULTI-0-INGRESS -j MULTI-0-INGRESS-0-FROM
-A MULTI-0-INGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-EGRESS -m comment --comment "policy:ingressPolicies1 net-attach-def:testns1/net-attach1" -o net1 -j MULTI-0-EGRESS
-A MULTI-EGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-EGRESS -j MARK --set-xmark 0x0/0x30000
-A MULTI-0-EGRESS -j MULTI-0-EGRESS-0-PORTS
-A MULTI-0-EGRESS -j MULTI-0-EGRESS-0-TO
-A MULTI-0-EGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-INGRESS-0-PORTS -m comment --comment "no ingress ports, skipped" -j MARK --set-xmark 0x10000/0x10000
-A MULTI-0-INGRESS-0-FROM -m comment --comment "no ingress from, skipped" -j MARK --set-xmark 0x20000/0x20000
-A MULTI-0-EGRESS-0-PORTS -m comment --comment "no egress ports, skipped" -j MARK --set-xmark 0x10000/0x10000
-A MULTI-0-EGRESS-0-TO -m comment --comment "no egress to, skipped" -j MARK --set-xmark 0x20000/0x20000
COMMIT
`

			Expect(buf.filterRules.String()).To(Equal(expectedRules), buf.filterRules.String())
		})

		It("shoud manage dual stack networks", func() {

			policy1 := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingressPolicies1",
					Namespace: "testns1",
				},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{{
						From: []multiv1beta1.MultiNetworkPolicyPeer{{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"foobar": "enabled",
								},
							},
						}},
					}},
					Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{{
						To: []multiv1beta1.MultiNetworkPolicyPeer{{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"foobar": "enabled",
								},
							},
						}},
					}},
				},
			}

			s := NewFakeServer("samplehost")
			Expect(s).NotTo(BeNil())

			AddNamespace(s, "testns1")

			Expect(
				s.netdefChanges.Update(nil, NewNetDef("testns1", "net-attach1", NewCNIConfig("testCNI", "multi"))),
			).To(BeTrue())

			pod1 := NewFakePodWithNetAnnotation(
				"testns1",
				"testpod1",
				"net-attach1",
				NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.1", "10.1.1.1\",\"2001:db8:a::11"),
				nil)
			AddPod(s, pod1)
			podInfo1, err := s.podMap.GetPodInfo(pod1)
			Expect(err).NotTo(HaveOccurred())

			pod2 := NewFakePodWithNetAnnotation(
				"testns1",
				"testpod2",
				"net-attach1",
				NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.2", "10.1.1.2\",\"2001:db8:a::12"),
				map[string]string{
					"foobar": "enabled",
				})
			AddPod(s, pod2)
			_, err = s.podMap.GetPodInfo(pod2)
			Expect(err).NotTo(HaveOccurred())

			ipt := fakeiptables.NewIPv6Fake()
			buf := newIptableBuffer()
			buf.Init(ipt)

			buf.renderIngress(s, podInfo1, 0, policy1, []string{"testns1/net-attach1"})
			buf.renderEgress(s, podInfo1, 0, policy1, []string{"testns1/net-attach1"})

			buf.FinalizeRules()

			expectedRules :=
				`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
:MULTI-0-INGRESS - [0:0]
:MULTI-0-INGRESS-0-PORTS - [0:0]
:MULTI-0-INGRESS-0-FROM - [0:0]
:MULTI-0-EGRESS - [0:0]
:MULTI-0-EGRESS-0-PORTS - [0:0]
:MULTI-0-EGRESS-0-TO - [0:0]
-A MULTI-INGRESS -m comment --comment "policy:ingressPolicies1 net-attach-def:testns1/net-attach1" -i net1 -j MULTI-0-INGRESS
-A MULTI-INGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-INGRESS -j MARK --set-xmark 0x0/0x30000
-A MULTI-0-INGRESS -j MULTI-0-INGRESS-0-PORTS
-A MULTI-0-INGRESS -j MULTI-0-INGRESS-0-FROM
-A MULTI-0-INGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-EGRESS -m comment --comment "policy:ingressPolicies1 net-attach-def:testns1/net-attach1" -o net1 -j MULTI-0-EGRESS
-A MULTI-EGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-EGRESS -j MARK --set-xmark 0x0/0x30000
-A MULTI-0-EGRESS -j MULTI-0-EGRESS-0-PORTS
-A MULTI-0-EGRESS -j MULTI-0-EGRESS-0-TO
-A MULTI-0-EGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-INGRESS-0-PORTS -m comment --comment "no ingress ports, skipped" -j MARK --set-xmark 0x10000/0x10000
-A MULTI-0-INGRESS-0-FROM -i net1 -s 2001:db8:a::12 -j MARK --set-xmark 0x20000/0x20000
-A MULTI-0-INGRESS-0-FROM -i net1 -s 2001:db8:a::11 -j MARK --set-xmark 0x20000/0x20000
-A MULTI-0-EGRESS-0-PORTS -m comment --comment "no egress ports, skipped" -j MARK --set-xmark 0x10000/0x10000
-A MULTI-0-EGRESS-0-TO -o net1 -d 2001:db8:a::12 -j MARK --set-xmark 0x20000/0x20000
-A MULTI-0-EGRESS-0-TO -o net1 -d 2001:db8:a::11 -j MARK --set-xmark 0x20000/0x20000
COMMIT
`
			Expect(buf.filterRules.String()).To(Equal(expectedRules))
		})
	})
})

var _ = Describe("policyrules testing - invalid case", func() {
	It("Initialization", func() {
		ipt := fakeiptables.NewFake()
		Expect(ipt).NotTo(BeNil())
		buf := newIptableBuffer()
		Expect(buf).NotTo(BeNil())

		// verify buf initialized at init
		buf.Init(ipt)
		filterChains :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
`
		Expect(buf.filterChains.String()).To(Equal(filterChains))
		Expect(buf.policyIndex.String()).To(Equal(""))
		Expect(buf.ingressPorts.String()).To(Equal(""))
		Expect(buf.ingressFrom.String()).To(Equal(""))
		Expect(buf.egressPorts.String()).To(Equal(""))
		Expect(buf.egressTo.String()).To(Equal(""))

		// finalize buf and verify rules buffer
		buf.FinalizeRules()
		filterRules :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
COMMIT
`
		Expect(buf.filterRules.String()).To(Equal(filterRules))

		// sync and verify iptable
		Expect(buf.SyncRules(ipt)).To(BeNil())
		iptableRules := bytes.NewBuffer(nil)
		ipt.SaveInto(utiliptables.TableFilter, iptableRules)
		Expect(iptableRules.String()).To(Equal(filterRules))

		// reset and verify empty
		buf.Reset()
		Expect(buf.policyIndex.String()).To(Equal(""))
		Expect(buf.ingressPorts.String()).To(Equal(""))
		Expect(buf.ingressFrom.String()).To(Equal(""))
		Expect(buf.egressPorts.String()).To(Equal(""))
		Expect(buf.egressTo.String()).To(Equal(""))
	})

	It("ingress rules ipblock", func() {
		port := intstr.FromInt(8888)
		protoTCP := v1.ProtocolTCP
		ingressPolicies1 := &multiv1beta1.MultiNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ingressPolicies1",
				Namespace: "testns1",
			},
			Spec: multiv1beta1.MultiNetworkPolicySpec{
				Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
					{
						Ports: []multiv1beta1.MultiNetworkPolicyPort{
							{
								Protocol: &protoTCP,
								Port:     &port,
							},
						},
						From: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								IPBlock: &multiv1beta1.IPBlock{
									CIDR:   "10.1.1.1/24",
									Except: []string{"10.1.1.1"},
								},
							},
						},
					},
				},
			},
		}

		ipt := fakeiptables.NewFake()
		Expect(ipt).NotTo(BeNil())
		buf := newIptableBuffer()
		Expect(buf).NotTo(BeNil())

		// verify buf initialized at init
		buf.Init(ipt)
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())

		Expect(s.netdefChanges.Update(
			nil,
			NewNetDef("testns1", "net-attach1", NewCNIConfig("testCNI", "multi")))).To(BeTrue())
		Expect(s.netdefChanges.GetPluginType(types.NamespacedName{Namespace: "testns1", Name: "net-attach1"})).To(Equal("multi"))

		pod1 := NewFakePodWithNetAnnotation(
			"testns1",
			"testpod1",
			"net-attach1",
			NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.1", "10.1.1.1"),
			nil)
		AddPod(s, pod1)
		podInfo1, err := s.podMap.GetPodInfo(pod1)
		Expect(err).NotTo(HaveOccurred())

		buf.renderIngress(s, podInfo1, 0, ingressPolicies1, []string{})

		buf.FinalizeRules()
		finalizedRules :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
:MULTI-0-INGRESS - [0:0]
:MULTI-0-INGRESS-0-PORTS - [0:0]
:MULTI-0-INGRESS-0-FROM - [0:0]
-A MULTI-0-INGRESS -j MARK --set-xmark 0x0/0x30000
-A MULTI-0-INGRESS -j MULTI-0-INGRESS-0-PORTS
-A MULTI-0-INGRESS -j MULTI-0-INGRESS-0-FROM
-A MULTI-0-INGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-INGRESS-0-PORTS -m comment --comment "no ingress ports, skipped" -j MARK --set-xmark 0x10000/0x10000
-A MULTI-0-INGRESS-0-FROM -m comment --comment "no ingress from, skipped" -j MARK --set-xmark 0x20000/0x20000
COMMIT
`
		Expect(buf.filterRules.String()).To(Equal(finalizedRules))
	})

	It("ingress rules podselector/matchlabels", func() {
		port := intstr.FromInt(8888)
		protoTCP := v1.ProtocolTCP
		ingressPolicies1 := &multiv1beta1.MultiNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ingressPolicies1",
				Namespace: "testns1",
			},
			Spec: multiv1beta1.MultiNetworkPolicySpec{
				Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
					{
						Ports: []multiv1beta1.MultiNetworkPolicyPort{
							{
								Protocol: &protoTCP,
								Port:     &port,
							},
						},
						From: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"foobar": "enabled",
									},
								},
							},
						},
					},
				},
			},
		}

		ipt := fakeiptables.NewFake()
		Expect(ipt).NotTo(BeNil())
		buf := newIptableBuffer()
		Expect(buf).NotTo(BeNil())

		// verify buf initialized at init
		buf.Init(ipt)
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())

		AddNamespace(s, "testns1")

		Expect(s.netdefChanges.Update(
			nil,
			NewNetDef("testns1", "net-attach1", NewCNIConfig("testCNI", "multi")))).To(BeTrue())
		Expect(s.netdefChanges.GetPluginType(types.NamespacedName{Namespace: "testns1", Name: "net-attach1"})).To(Equal("multi"))

		pod1 := NewFakePodWithNetAnnotation(
			"testns1",
			"testpod1",
			"net-attach1",
			NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.1", "10.1.1.1"),
			nil)
		AddPod(s, pod1)
		podInfo1, err := s.podMap.GetPodInfo(pod1)
		Expect(err).NotTo(HaveOccurred())

		pod2 := NewFakePodWithNetAnnotation(
			"testns1",
			"testpod2",
			"net-attach1",
			NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.2", "10.1.1.2"),
			map[string]string{
				"foobar": "enabled",
			})
		AddPod(s, pod2)

		buf.renderIngress(s, podInfo1, 0, ingressPolicies1, []string{})

		buf.FinalizeRules()
		finalizedRules :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
:MULTI-0-INGRESS - [0:0]
:MULTI-0-INGRESS-0-PORTS - [0:0]
:MULTI-0-INGRESS-0-FROM - [0:0]
-A MULTI-0-INGRESS -j MARK --set-xmark 0x0/0x30000
-A MULTI-0-INGRESS -j MULTI-0-INGRESS-0-PORTS
-A MULTI-0-INGRESS -j MULTI-0-INGRESS-0-FROM
-A MULTI-0-INGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-INGRESS-0-PORTS -m comment --comment "no ingress ports, skipped" -j MARK --set-xmark 0x10000/0x10000
-A MULTI-0-INGRESS-0-FROM -m comment --comment "no ingress from, skipped" -j MARK --set-xmark 0x20000/0x20000
COMMIT
`
		Expect(buf.filterRules.String()).To(Equal(finalizedRules))
	})

	It("egress rules ipblock", func() {
		port := intstr.FromInt(8888)
		protoTCP := v1.ProtocolTCP
		egressPolicies1 := &multiv1beta1.MultiNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "EgressPolicies1",
				Namespace: "testns1",
			},
			Spec: multiv1beta1.MultiNetworkPolicySpec{
				Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
					{
						Ports: []multiv1beta1.MultiNetworkPolicyPort{
							{
								Protocol: &protoTCP,
								Port:     &port,
							},
						},
						To: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								IPBlock: &multiv1beta1.IPBlock{
									CIDR:   "10.1.1.1/24",
									Except: []string{"10.1.1.1"},
								},
							},
						},
					},
				},
			},
		}

		ipt := fakeiptables.NewFake()
		Expect(ipt).NotTo(BeNil())
		buf := newIptableBuffer()
		Expect(buf).NotTo(BeNil())

		// verify buf initialized at init
		buf.Init(ipt)
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())

		Expect(s.netdefChanges.Update(
			nil,
			NewNetDef("testns1", "net-attach1", NewCNIConfig("testCNI", "multi")))).To(BeTrue())
		Expect(s.netdefChanges.GetPluginType(types.NamespacedName{Namespace: "testns1", Name: "net-attach1"})).To(Equal("multi"))

		pod1 := NewFakePodWithNetAnnotation(
			"testns1",
			"testpod1",
			"net-attach1",
			NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.1", "10.1.1.1"),
			nil)
		AddPod(s, pod1)
		podInfo1, err := s.podMap.GetPodInfo(pod1)
		Expect(err).NotTo(HaveOccurred())

		buf.renderEgress(s, podInfo1, 0, egressPolicies1, []string{})

		buf.FinalizeRules()
		finalizedRules :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
:MULTI-0-EGRESS - [0:0]
:MULTI-0-EGRESS-0-PORTS - [0:0]
:MULTI-0-EGRESS-0-TO - [0:0]
-A MULTI-0-EGRESS -j MARK --set-xmark 0x0/0x30000
-A MULTI-0-EGRESS -j MULTI-0-EGRESS-0-PORTS
-A MULTI-0-EGRESS -j MULTI-0-EGRESS-0-TO
-A MULTI-0-EGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-EGRESS-0-PORTS -m comment --comment "no egress ports, skipped" -j MARK --set-xmark 0x10000/0x10000
-A MULTI-0-EGRESS-0-TO -m comment --comment "no egress to, skipped" -j MARK --set-xmark 0x20000/0x20000
COMMIT
`
		Expect(buf.filterRules.String()).To(Equal(finalizedRules))
	})

	It("egress rules podselector/matchlabels", func() {
		port := intstr.FromInt(8888)
		protoTCP := v1.ProtocolTCP
		egressPolicies1 := &multiv1beta1.MultiNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "EgressPolicies1",
				Namespace: "testns1",
			},
			Spec: multiv1beta1.MultiNetworkPolicySpec{
				Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
					{
						Ports: []multiv1beta1.MultiNetworkPolicyPort{
							{
								Protocol: &protoTCP,
								Port:     &port,
							},
						},
						To: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"foobar": "enabled",
									},
								},
							},
						},
					},
				},
			},
		}

		ipt := fakeiptables.NewFake()
		Expect(ipt).NotTo(BeNil())
		buf := newIptableBuffer()
		Expect(buf).NotTo(BeNil())

		// verify buf initialized at init
		buf.Init(ipt)
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())

		AddNamespace(s, "testns1")

		Expect(s.netdefChanges.Update(
			nil,
			NewNetDef("testns1", "net-attach1", NewCNIConfig("testCNI", "multi")))).To(BeTrue())
		Expect(s.netdefChanges.GetPluginType(types.NamespacedName{Namespace: "testns1", Name: "net-attach1"})).To(Equal("multi"))

		pod1 := NewFakePodWithNetAnnotation(
			"testns1",
			"testpod1",
			"net-attach1",
			NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.1", "10.1.1.1"),
			nil)
		AddPod(s, pod1)
		podInfo1, err := s.podMap.GetPodInfo(pod1)
		Expect(err).NotTo(HaveOccurred())

		pod2 := NewFakePodWithNetAnnotation(
			"testns1",
			"testpod2",
			"net-attach1",
			NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.2", "10.1.1.2"),
			map[string]string{
				"foobar": "enabled",
			})
		AddPod(s, pod2)

		buf.renderEgress(s, podInfo1, 0, egressPolicies1, []string{"testns2/net-attach1"})

		buf.FinalizeRules()
		finalizedRules :=
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-INGRESS-COMMON - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-EGRESS-COMMON - [0:0]
:MULTI-0-EGRESS - [0:0]
:MULTI-0-EGRESS-0-PORTS - [0:0]
:MULTI-0-EGRESS-0-TO - [0:0]
-A MULTI-0-EGRESS -j MARK --set-xmark 0x0/0x30000
-A MULTI-0-EGRESS -j MULTI-0-EGRESS-0-PORTS
-A MULTI-0-EGRESS -j MULTI-0-EGRESS-0-TO
-A MULTI-0-EGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-EGRESS-0-PORTS -m comment --comment "no egress ports, skipped" -j MARK --set-xmark 0x10000/0x10000
-A MULTI-0-EGRESS-0-TO -m comment --comment "no egress to, skipped" -j MARK --set-xmark 0x20000/0x20000
COMMIT
`
		Expect(buf.filterRules.String()).To(Equal(finalizedRules))
	})

})
