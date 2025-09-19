package server

import (
	"fmt"
	"math"
	"net/netip"
	"strings"
	"testing"
	"time"

	nftables "github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/k8snetworkplumbingwg/multi-networkpolicy-iptables/pkg/controllers"
	"github.com/k8snetworkplumbingwg/multi-networkpolicy-iptables/pkg/nftest"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	multifake "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/client/clientset/versioned/fake"
	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netfake "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/fake"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

const DEBUG = false

func TestBootstrap(t *testing.T) {
	// Open a system connection in a separate network namespace it requires root
	c, newNS := nftest.OpenSystemConn(t, true, DEBUG)
	defer c.CloseLasting()
	defer nftest.CleanupSystemConn(t, newNS, DEBUG)
	c.FlushRuleset()
	defer c.FlushRuleset()
	podMockInfo := &controllers.PodInfo{
		Interfaces: []controllers.InterfaceInfo{
			{InterfaceName: "eth0", IPs: []string{"10.0.0.0", "fd00::"}},
			{InterfaceName: "eth1", IPs: []string{"fd01::"}},
			{InterfaceName: "eth2", IPs: []string{"10.0.0.0"}},
		},
	}

	_, err := bootstrapNetfilterRules(c, podMockInfo)
	if err != nil {
		t.Fatalf("bootstrapNetfilterRules() failed: %v", err)
	}
	checkForBootstrap := func() bool {

		filterTable, err := c.ListTableOfFamily("filter", nftables.TableFamilyINet)
		if err != nil {
			t.Fatalf("c.ListTable(\"filter\") failed: %v", err)
		}
		natTable, err := c.ListTableOfFamily("nat", nftables.TableFamilyINet)
		if err != nil {
			t.Fatalf("c.ListTable(\"nat\") failed: %v", err)
		}
		if filterTable == nil || natTable == nil {
			t.Errorf("filterTable or natTable is nil %v, %v", filterTable, natTable)
			return false
		}
		chains, err := c.ListChains()
		if err != nil {
			t.Fatalf("c.ListChains() failed: %v", err)
		}
		var foundInput, foundOutput, foundIngress, foundEgress, foundCommonIngress, foundCommonEgress, foundPreRouting bool
		for _, ch := range chains {
			if ch.Table.Name == "filter" {
				switch ch.Name {
				case ingressChain:
					foundIngress = true
				case egressChain:
					foundEgress = true
				case fmt.Sprintf("%s-%s", ingressChain, common):
					foundCommonIngress = true
				case fmt.Sprintf("%s-%s", egressChain, common):
					foundCommonEgress = true
				case "input":
					foundInput = true
				case "output":
					foundOutput = true
				}
			}
			if ch.Table.Name == "nat" {
				if ch.Name == "prerouting" {
					foundPreRouting = true
				}
			}
		}
		if !foundIngress || !foundEgress || !foundCommonIngress || !foundCommonEgress || !foundPreRouting || !foundInput || !foundOutput {
			t.Errorf("chains not found: ingress %v, egress %v, commonIngress %v, commonEgress %v, prerouting %v, input %v, output %v",
				foundIngress, foundEgress, foundCommonIngress, foundCommonEgress, foundPreRouting, foundInput, foundOutput)
			return false
		}
		inputRules, err := c.GetRules(filterTable, &nftables.Chain{
			Name: "input",
		})
		if err != nil {
			t.Fatalf("c.GetRules(filterTable, \"input\") failed: %v", err)
		}
		outputRules, err := c.GetRules(filterTable, &nftables.Chain{
			Name: "output",
		})
		if err != nil {
			t.Fatalf("c.GetRules(filterTable, \"output\") failed: %v", err)
		}
		natRules, err := c.GetRules(natTable, &nftables.Chain{
			Name: "prerouting",
		})
		if err != nil {
			t.Fatalf("c.GetRules(natTable, \"prerouting\") failed: %v", err)
		}
		if len(inputRules) != 1 || len(outputRules) != 1 || len(natRules) != 1 {
			t.Errorf("inputRules, outputRules or natRules does not have the expected rules: 1!=%d, 1!=%d, 1!=%d", len(inputRules), len(outputRules), len(natRules))
			return false
		}
		return true
	}
	if !checkForBootstrap() {
		t.Fatal("Something in Bootstrap did not complete as expected")
	}
}

func TestApplyCommonChainRules(t *testing.T) {
	c, newNS := nftest.OpenSystemConn(t, true, DEBUG)
	defer c.CloseLasting()
	defer nftest.CleanupSystemConn(t, newNS, DEBUG)
	c.FlushRuleset()
	defer c.FlushRuleset()
	podMockInfo := &controllers.PodInfo{
		Interfaces: []controllers.InterfaceInfo{
			{InterfaceName: "eth0", IPs: []string{"10.0.0.0", "fd00::"}},
			{InterfaceName: "eth1", IPs: []string{"fd01::"}},
			{InterfaceName: "eth2", IPs: []string{"10.0.0.0"}},
		},
	}
	nftState, err := bootstrapNetfilterRules(c, podMockInfo)
	if err != nil {
		t.Fatalf("bootstrapNetfilterRules() failed: %v", err)
	}
	if nftState == nil {
		t.Fatalf("bootstrapNetfilterRules() returned nil state")
	}

	mockServer := &Server{
		Options: &Options{
			acceptICMPv6:   true,
			acceptICMP:     true,
			allowSrcPrefix: []string{"fc00::/8", "fd00::/8", "10.0.0.1/32", "10.0.1.0/24"},
			allowDstPrefix: []string{"fe00::/8", "ff00::/8", "10.0.0.2/32", "10.0.2.0/24"},
		},
	}
	err = nftState.applyCommonChainRules(mockServer)
	if err != nil {
		t.Fatalf("applyCommonChainRules() failed: %v", err)
	}
	checkCommon := func() bool {
		filterTable, err := c.ListTableOfFamily(nftState.filter.Name, nftables.TableFamilyINet)
		if err != nil {
			t.Fatalf("c.ListTable(\"filter\") failed: %v", err)
		}
		if filterTable == nil {
			t.Errorf("filterTable is nil")
			return false
		}
		ingressRules, err := c.GetRules(filterTable, &nftables.Chain{
			Name: fmt.Sprintf("%s-%s", ingressChain, common),
		})
		if err != nil {
			t.Fatalf("c.GetRules(%q, %q) failed: %v", filterTable.Name, fmt.Sprintf("%s-%s", ingressChain, common), err)
		}
		egressRules, err := c.GetRules(filterTable, &nftables.Chain{
			Name: fmt.Sprintf("%s-%s", egressChain, common),
		})
		if err != nil {
			t.Fatalf("c.GetRules(%q, %q) failed: %v", filterTable.Name, fmt.Sprintf("%s-%s", egressChain, common), err)
		}
		if len(ingressRules) != 5 {
			t.Errorf("ingressRules does not have the expected number of rules: 5 != %d", len(ingressRules))
			return false
		}
		if len(egressRules) != 5 {
			t.Errorf("egressRules does not have the expected number of rules: 5 != %d", len(egressRules))
			return false
		}
		sets, err := c.GetSets(filterTable)
		if err != nil {
			t.Fatalf("c.GetSets(%q) failed: %v", filterTable.Name, err)
		}
		for _, set := range sets {
			if set.Name == fmt.Sprintf("%s_v4_%s", common, sourceAddressSuffix) || set.Name == fmt.Sprintf("%s_v4_%s", common, destinationAddressSuffix) ||
				set.Name == fmt.Sprintf("%s_v6_%s", common, sourceAddressSuffix) || set.Name == fmt.Sprintf("%s_v6_%s", common, destinationAddressSuffix) {
				if set.Table.Name != filterTable.Name {
					t.Errorf("set %q is not in table %q", set.Name, filterTable.Name)
				}
				elements, err := c.GetSetElements(set)
				if err != nil {
					t.Fatalf("c.GetSetElements(%q) failed: %v", set.Name, err)
				}
				if len(elements) == 0 {
					t.Errorf("set %q does not have any elements", set.Name)
				}
				for _, elem := range elements {
					if len(elem.Key) == 0 {
						t.Errorf("set %q has an element with no data", set.Name)
					}
					ip, ok := netip.AddrFromSlice(elem.Key)
					if !ok {
						t.Errorf("set %q has an element with invalid IP data: %v", set.Name, err)
					}
					t.Logf("set %q has element %q", set.Name, ip.String())
				}
			}
		}
		return true
	}
	if !checkCommon() {
		t.Fatal("Something in applyCommonChainRules did not complete as expected")
	}
}

func TestApplyPodRules(t *testing.T) {
	// TODO: still needs proper validation against the MultiNetworkPolicy CR content
	c, newNS := nftest.OpenSystemConn(t, true, DEBUG)
	defer c.CloseLasting()
	defer nftest.CleanupSystemConn(t, newNS, DEBUG)
	c.FlushRuleset()
	defer c.FlushRuleset()

	nftState, testNs, mockServer, podMockInfo, err := prepareEnv(c)
	if err != nil {
		t.Fatalf("failed to prepare test env: %s", err.Error())
	}

	// Define protocol variables to take their addresses
	protocolTCP := corev1.ProtocolTCP
	protocolUDP := corev1.ProtocolUDP
	protocolSCTP := corev1.ProtocolSCTP

	eighty, ninety, fiftythree, oneTwoThreeFour, twoFourSixEight :=
		intstr.FromInt(80), int32(intstr.FromInt(90).IntVal), intstr.FromInt(53),
		intstr.FromInt(1234), int32(intstr.FromInt(2468).IntVal)

	mockPolicy := &multiv1beta1.MultiNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "policy-net-1",
			Namespace: testNs,
			Annotations: map[string]string{
				"k8s.v1.cni.cncf.io/policy-for": fmt.Sprintf("%s/policy-net-1", testNs),
			},
		},
		Spec: multiv1beta1.MultiNetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "app",
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{"test"},
					},
				},
			},
			Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
				{
					Ports: []multiv1beta1.MultiNetworkPolicyPort{
						{
							Protocol: &protocolTCP,
							Port:     &eighty,
							EndPort:  &ninety,
						},
						{
							Protocol: &protocolUDP,
							Port:     &fiftythree,
						},
						{
							Protocol: &protocolSCTP,
							Port:     &oneTwoThreeFour,
							EndPort:  &twoFourSixEight,
						},
					},
					From: []multiv1beta1.MultiNetworkPolicyPeer{
						{
							IPBlock: &multiv1beta1.IPBlock{
								CIDR: "face::/16",
							},
						},
						{
							PodSelector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{
										Key:      "app",
										Operator: metav1.LabelSelectorOpIn,
										Values:   []string{"test2"},
									},
								},
							},
						},
					},
				},
			},
			Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
				{
					Ports: []multiv1beta1.MultiNetworkPolicyPort{
						{
							Protocol: &protocolTCP,
							Port:     &eighty,

							EndPort: &ninety,
						},
						{
							Protocol: &protocolUDP,
							Port:     &fiftythree,
						},
						{
							Protocol: &protocolSCTP,
							Port:     &oneTwoThreeFour,
							EndPort:  &twoFourSixEight,
						},
					},
					To: []multiv1beta1.MultiNetworkPolicyPeer{
						{
							IPBlock: &multiv1beta1.IPBlock{
								CIDR: "badc::/16",
							},
						},
						{
							PodSelector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{
										Key:      "app",
										Operator: metav1.LabelSelectorOpIn,
										Values:   []string{"test2"},
									},
								},
							},
						},
					},
				},
			},
			PolicyTypes: []multiv1beta1.MultiPolicyType{
				multiv1beta1.PolicyTypeEgress,
				multiv1beta1.PolicyTypeIngress,
			},
		},
	}
	err = nftState.applyPodRules(mockServer, nftState.ingressChain, podMockInfo, 0, mockPolicy, []string{"net1", "net2"})
	if err != nil {
		t.Fatalf("applyPodRules() for ingress failed: %v", err)
	}
	if err := nftState.nft.Flush(); err != nil {
		t.Fatalf("nft flush failed after applying ingress rules: %v", err)
	}

	err = nftState.applyPodRules(mockServer, nftState.egressChain, podMockInfo, 0, mockPolicy, []string{"net1", "net2"})
	if err != nil {
		t.Fatalf("applyPodRules() for egress failed: %v", err)
	}
	if err := nftState.nft.Flush(); err != nil {
		t.Fatalf("nft flush failed after applying egress rules: %v", err)
	}

	check := func() bool {
		filterTable, err := c.ListTableOfFamily(nftState.filter.Name, nftables.TableFamilyINet)
		if err != nil {
			t.Fatalf("c.ListTable(\"filter\") failed: %v", err)
		}
		if filterTable == nil {
			t.Errorf("filterTable is nil")
			return false
		}
		ingressRules, err := c.GetRules(filterTable, &nftables.Chain{
			Name: fmt.Sprintf("%s-%s", ingressChain, common),
		})
		if err != nil {
			t.Fatalf("c.GetRules(%q, %q) failed: %v", filterTable.Name, fmt.Sprintf("%s-%s", ingressChain, common), err)
		}
		egressRules, err := c.GetRules(filterTable, &nftables.Chain{
			Name: fmt.Sprintf("%s-%s", egressChain, common),
		})
		if err != nil {
			t.Fatalf("c.GetRules(%q, %q) failed: %v", filterTable.Name, fmt.Sprintf("%s-%s", egressChain, common), err)
		}
		if len(ingressRules) != 1 {
			t.Errorf("ingressRules does not have the expected number of rules: 1 != %d", len(ingressRules))
			return false
		}
		if len(egressRules) != 1 {
			t.Errorf("egressRules does not have the expected number of rules: 1 != %d", len(egressRules))
			return false
		}

		set, err := c.GetSetByName(filterTable, "pod_interfaces")
		if err != nil {
			t.Fatalf("c.GetSetByName(%q, 'pod_interfaces') failed: %v", filterTable.Name, err)
		}
		elements, err := c.GetSetElements(set)
		if err != nil {
			t.Fatalf("unable to get elements for set 'pod_interfaces': %v", err)
		}

		if len(elements) != 3 {
			t.Fatalf("pod_interfaces set does not have the expected number of elements: 3 != %d", len(elements))
		}

		ingressChain0 := fmt.Sprintf("%s-%d", ingressChain, 0)
		ingressPortChain := fmt.Sprintf("%s-ports-0", ingressChain0)
		ingressPeerChain := fmt.Sprintf("%s-peers-0", ingressChain0)
		if err := verifyVerdicts(c, filterTable, ingressChain0, ingressPortChain, ingressPeerChain); err != nil {
			t.Fatal(err.Error())
		}

		egressChain0 := fmt.Sprintf("%s-%d", egressChain, 0)
		egressPortChain := fmt.Sprintf("%s-ports-0", egressChain0)
		egressPeerChain := fmt.Sprintf("%s-peers-0", egressChain0)
		if err := verifyVerdicts(c, filterTable, egressChain0, egressPortChain, egressPeerChain); err != nil {
			t.Fatal(err.Error())
		}

		ingressPortChainRules, err := c.GetRules(filterTable, &nftables.Chain{
			Name: ingressPortChain,
		})
		if err != nil {
			t.Fatalf("c.GetRules(%q, %q) failed: %s", filterTable.Name, ingressPortChain, err.Error())
		}

		for _, r := range ingressPortChainRules {
			for _, e := range r.Exprs {
				if el, ok := e.(*expr.Lookup); ok {
					set, err := c.GetSetByName(filterTable, el.SetName)
					if err != nil {
						t.Fatalf("failed to get set %q: %s", el.SetName, err.Error())
					}
					port, err := getSetPorts(c, set)
					if err != nil {
						t.Fatalf("failed to get port data for set %q: %s", el.SetName, err.Error())
					}

					var start, end uint16
					switch port.protocol {
					case "tcp":
						start = uint16(eighty.IntVal)
						end = uint16(ninety)
					case "udp":
						start = uint16(fiftythree.IntVal)
						end = uint16(fiftythree.IntVal)
					case "sctp":
						start = uint16(oneTwoThreeFour.IntVal)
						end = uint16(twoFourSixEight)
					}

					if err := checkPort(port, start, end); err != nil {
						t.Fatalf("invalid configuration: %s", err.Error())
					}
				}
			}

		}
		return true
	}

	if !check() {
		t.Fatal("Something in applyPodRules did not complete as expected")
	}
}

func TestApplyPodRulesNoPorts(t *testing.T) {
	c, newNS := nftest.OpenSystemConn(t, true, DEBUG)
	defer c.CloseLasting()
	defer nftest.CleanupSystemConn(t, newNS, DEBUG)
	c.FlushRuleset()
	defer c.FlushRuleset()

	nftState, testNs, mockServer, podMockInfo, err := prepareEnv(c)
	if err != nil {
		t.Fatalf("failed to prepare test env: %s", err.Error())
	}

	// Define protocol variables to take their addresses
	protocolTCP := corev1.ProtocolTCP
	protocolUDP := corev1.ProtocolUDP
	protocolSCTP := corev1.ProtocolSCTP

	mockPolicy := &multiv1beta1.MultiNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "policy-net-1",
			Namespace: testNs,
			Annotations: map[string]string{
				"k8s.v1.cni.cncf.io/policy-for": fmt.Sprintf("%s/policy-net-1", testNs),
			},
		},
		Spec: multiv1beta1.MultiNetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "app",
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{"test"},
					},
				},
			},
			Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
				{
					Ports: []multiv1beta1.MultiNetworkPolicyPort{
						{
							Protocol: &protocolTCP,
						},
						{
							Protocol: &protocolUDP,
						},
						{
							Protocol: &protocolSCTP,
						},
					},
					From: []multiv1beta1.MultiNetworkPolicyPeer{
						{
							IPBlock: &multiv1beta1.IPBlock{
								CIDR: "face::/16",
							},
						},
						{
							PodSelector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{
										Key:      "app",
										Operator: metav1.LabelSelectorOpIn,
										Values:   []string{"test2"},
									},
								},
							},
						},
					},
				},
			},
			Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
				{
					Ports: []multiv1beta1.MultiNetworkPolicyPort{
						{
							Protocol: &protocolTCP,
						},
						{
							Protocol: &protocolUDP,
						},
						{
							Protocol: &protocolSCTP,
						},
					},
					To: []multiv1beta1.MultiNetworkPolicyPeer{
						{
							IPBlock: &multiv1beta1.IPBlock{
								CIDR: "badc::/16",
							},
						},
						{
							PodSelector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{
										Key:      "app",
										Operator: metav1.LabelSelectorOpIn,
										Values:   []string{"test2"},
									},
								},
							},
						},
					},
				},
			},
			PolicyTypes: []multiv1beta1.MultiPolicyType{
				multiv1beta1.PolicyTypeEgress,
				multiv1beta1.PolicyTypeIngress,
			},
		},
	}
	err = nftState.applyPodRules(mockServer, nftState.ingressChain, podMockInfo, 0, mockPolicy, []string{"net1", "net2"})
	if err != nil {
		t.Fatalf("applyPodRules() for ingress failed: %v", err)
	}
	if err := nftState.nft.Flush(); err != nil {
		t.Fatalf("nft flush failed after applying ingress rules: %v", err)
	}

	err = nftState.applyPodRules(mockServer, nftState.egressChain, podMockInfo, 0, mockPolicy, []string{"net1", "net2"})
	if err != nil {
		t.Fatalf("applyPodRules() for egress failed: %v", err)
	}
	if err := nftState.nft.Flush(); err != nil {
		t.Fatalf("nft flush failed after applying egress rules: %v", err)
	}

	check := func() bool {
		filterTable, err := c.ListTableOfFamily(nftState.filter.Name, nftables.TableFamilyINet)
		if err != nil {
			t.Fatalf("c.ListTable(\"filter\") failed: %v", err)
		}
		if filterTable == nil {
			t.Errorf("filterTable is nil")
			return false
		}
		ingressRules, err := c.GetRules(filterTable, &nftables.Chain{
			Name: fmt.Sprintf("%s-%s", ingressChain, common),
		})
		if err != nil {
			t.Fatalf("c.GetRules(%q, %q) failed: %v", filterTable.Name, fmt.Sprintf("%s-%s", ingressChain, common), err)
		}
		egressRules, err := c.GetRules(filterTable, &nftables.Chain{
			Name: fmt.Sprintf("%s-%s", egressChain, common),
		})
		if err != nil {
			t.Fatalf("c.GetRules(%q, %q) failed: %v", filterTable.Name, fmt.Sprintf("%s-%s", egressChain, common), err)
		}
		if len(ingressRules) != 1 {
			t.Errorf("ingressRules does not have the expected number of rules: 1 != %d", len(ingressRules))
			return false
		}
		if len(egressRules) != 1 {
			t.Errorf("egressRules does not have the expected number of rules: 1 != %d", len(egressRules))
			return false
		}

		set, err := c.GetSetByName(filterTable, "pod_interfaces")
		if err != nil {
			t.Fatalf("c.GetSetByName(%q, 'pod_interfaces') failed: %v", filterTable.Name, err)
		}
		elements, err := c.GetSetElements(set)
		if err != nil {
			t.Fatalf("unable to get elements for set 'pod_interfaces': %v", err)
		}

		if len(elements) != 3 {
			t.Fatalf("pod_interfaces set does not have the expected number of elements: 3 != %d", len(elements))
		}

		ingressChain0 := fmt.Sprintf("%s-%d", ingressChain, 0)
		ingressPortChain := fmt.Sprintf("%s-ports-0", ingressChain0)
		ingressPeerChain := fmt.Sprintf("%s-peers-0", ingressChain0)
		if err := verifyVerdicts(c, filterTable, ingressChain0, ingressPortChain, ingressPeerChain); err != nil {
			t.Fatal(err.Error())
		}

		egressChain0 := fmt.Sprintf("%s-%d", egressChain, 0)
		egressPortChain := fmt.Sprintf("%s-ports-0", egressChain0)
		egressPeerChain := fmt.Sprintf("%s-peers-0", egressChain0)
		if err := verifyVerdicts(c, filterTable, egressChain0, egressPortChain, egressPeerChain); err != nil {
			t.Fatal(err.Error())
		}

		ingressPortChainRules, err := c.GetRules(filterTable, &nftables.Chain{
			Name: ingressPortChain,
		})
		if err != nil {
			t.Fatalf("c.GetRules(%q, %q) failed: %s", filterTable.Name, ingressPortChain, err.Error())
		}

		for _, r := range ingressPortChainRules {
			for _, e := range r.Exprs {
				if el, ok := e.(*expr.Lookup); ok {
					set, err := c.GetSetByName(filterTable, el.SetName)
					if err != nil {
						t.Fatalf("failed to get set %q: %s", el.SetName, err.Error())
					}
					port, err := getSetPorts(c, set)
					if err != nil {
						t.Fatalf("failed to get port data for set %q: %s", el.SetName, err.Error())
					}

					if err := checkPort(port, 1, math.MaxUint16); err != nil {
						t.Fatalf("invalid configuration: %s", err.Error())
					}
				}
			}

		}
		return true
	}

	if !check() {
		t.Fatal("Something in applyPodRules did not complete as expected")
	}
}

func TestApplyPolicyPortsRules(t *testing.T) {
	c, newNS := nftest.OpenSystemConn(t, true, DEBUG)
	defer c.CloseLasting()
	defer nftest.CleanupSystemConn(t, newNS, DEBUG)
	c.FlushRuleset()
	defer c.FlushRuleset()

	nftState, testNs, _, _, err := prepareEnv(c)
	if err != nil {
		t.Fatalf("failed to prepare test env: %s", err.Error())
	}

	// Define protocol variables to take their addresses
	protocolTCP := corev1.ProtocolTCP
	protocolUDP := corev1.ProtocolUDP
	protocolSCTP := corev1.ProtocolSCTP

	mockPolicy := &multiv1beta1.MultiNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "policy-net-1",
			Namespace: testNs,
			Annotations: map[string]string{
				"k8s.v1.cni.cncf.io/policy-for": fmt.Sprintf("%s/policy-net-1", testNs),
			},
		},
		Spec: multiv1beta1.MultiNetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "app",
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{"test"},
					},
				},
			},
			Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
				{
					Ports: []multiv1beta1.MultiNetworkPolicyPort{
						{
							Protocol: &protocolTCP,
						},
						{
							Protocol: &protocolUDP,
						},
						{
							Protocol: &protocolSCTP,
						},
					},
					From: []multiv1beta1.MultiNetworkPolicyPeer{
						{
							IPBlock: &multiv1beta1.IPBlock{
								CIDR: "face::/16",
							},
						},
						{
							PodSelector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{
										Key:      "app",
										Operator: metav1.LabelSelectorOpIn,
										Values:   []string{"test2"},
									},
								},
							},
						},
					},
				},
			},
			Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
				{
					To: []multiv1beta1.MultiNetworkPolicyPeer{
						{
							IPBlock: &multiv1beta1.IPBlock{
								CIDR: "badc::/16",
							},
						},
						{
							PodSelector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{
										Key:      "app",
										Operator: metav1.LabelSelectorOpIn,
										Values:   []string{"test2"},
									},
								},
							},
						},
					},
				},
			},
			PolicyTypes: []multiv1beta1.MultiPolicyType{
				multiv1beta1.PolicyTypeEgress,
				multiv1beta1.PolicyTypeIngress,
			},
		},
	}

	err = nftState.applyPolicyPortsRules(nftState.ingressChain, mockPolicy.Name, []multiv1beta1.MultiNetworkPolicyPort{}, 0)
	if err != nil {
		t.Fatalf("applyPolicyPortsRules() for ingress failed: %v", err)
	}

	err = nftState.applyPolicyPortsRules(nftState.egressChain, mockPolicy.Name, []multiv1beta1.MultiNetworkPolicyPort{}, 0)
	if err != nil {
		t.Fatalf("applyPolicyPortsRules() for egress failed: %v", err)
	}

	nftState.nft.Flush()

	ingressPortChain := fmt.Sprintf("%s-ports-0", ingressChain)

	egressPortChain := fmt.Sprintf("%s-ports-0", egressChain)

	check := func() bool {
		filterTable, err := c.ListTableOfFamily(nftState.filter.Name, nftables.TableFamilyINet)
		if err != nil {
			t.Fatalf("c.ListTable(\"filter\") failed: %v", err)
		}
		if filterTable == nil {
			t.Errorf("filterTable is nil")
			return false
		}
		ingressRules, err := c.GetRules(filterTable, &nftables.Chain{
			Name: ingressPortChain,
		})
		if err != nil {
			t.Fatalf("c.GetRules(%q, %q) failed: %v", filterTable.Name, fmt.Sprintf("%s-%s", ingressChain, common), err)
		}
		egressRules, err := c.GetRules(filterTable, &nftables.Chain{
			Name: egressPortChain,
		})
		if err != nil {
			t.Fatalf("c.GetRules(%q, %q) failed: %v", filterTable.Name, fmt.Sprintf("%s-%s", egressChain, common), err)
		}

		if len(ingressRules) != 1 {
			t.Errorf("ingressRules does not have the expected number of rules: 1 != %d", len(ingressRules))
			return false
		}

		if !strings.Contains(string(ingressRules[0].UserData), "accept all") {
			t.Errorf("ingress rule is invalid")
			return false
		}

		if len(egressRules) != 1 {
			t.Errorf("egressRules does not have the expected number of rules: 1 != %d", len(egressRules))
			return false
		}

		if !strings.Contains(string(egressRules[0].UserData), "accept all") {
			t.Errorf("egress rule is invalid")
			return false
		}

		return true
	}

	if !check() {
		t.Fatal("Something in applyPodPolicyPortsRules did not complete as expected")
	}
}

type testPort struct {
	protocol string
	start    uint16
	end      uint16
}

func getSetPorts(c *nftables.Conn, set *nftables.Set) (*testPort, error) {
	setEls, err := c.GetSetElements(set)
	if err != nil {
		return nil, fmt.Errorf("failed to get set %q elements: %w", set.Name, err)
	}
	var start, end uint16
	for _, e := range setEls {
		if e.IntervalEnd {
			end = binaryutil.BigEndian.Uint16(e.Key) - 1
		} else {
			start = binaryutil.BigEndian.Uint16(e.Key)
		}
	}
	pname := strings.Split(set.Name, "_")
	return &testPort{
		protocol: pname[len(pname)-1],
		start:    start,
		end:      end,
	}, nil
}

func checkPort(port *testPort, start, end uint16) error {
	if port.start != start {
		return fmt.Errorf("invalid %s start port configuration: is %d, shoud be %d", strings.ToUpper(port.protocol), port.start, start)
	}
	if port.end != end {
		return fmt.Errorf("invalid %s end port configuration: is %d, shoud be %d", strings.ToUpper(port.protocol), port.end, end)
	}
	return nil
}

func verifyVerdicts(c *nftables.Conn, table *nftables.Table, chain, portChain, peerChain string) error {
	rules, err := c.GetRules(table, &nftables.Chain{
		Name: chain,
	})
	if err != nil {
		return fmt.Errorf("failed to get egress pod rules: %s", err.Error())
	}

	if !checkVerdictPresence(rules, portChain) {
		return fmt.Errorf("chain %q does not contain %q verdict", chain, portChain)
	}

	if !checkVerdictPresence(rules, peerChain) {
		return fmt.Errorf("chain %q does not contain %q verdict", chain, peerChain)
	}

	return nil
}

func checkVerdictPresence(rules []*nftables.Rule, name string) bool {
	for _, rule := range rules {
		for _, exp := range rule.Exprs {
			if e, ok := exp.(*expr.Verdict); ok && e.Chain == name {
				return true
			}
		}
	}
	return false
}

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

	nodeRef := &corev1.ObjectReference{
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

func NewFakePodWithNetAnnotation(namespace, name, annot, status string, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
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
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "ctr1", Image: "image"},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
		},
	}
}

func AddNamespace(s *Server, name string) error {
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"nsname": name,
			},
		},
	}
	if updated := s.nsChanges.Update(nil, namespace); !updated {
		return fmt.Errorf("failed to update nasespace %q", namespace)
	}
	s.namespaceMap.Update(s.nsChanges)
	return nil
}

func AddPod(s *Server, pod *corev1.Pod) error {
	if added := s.podChanges.Update(nil, pod); !added {
		return fmt.Errorf("failed to add pod '%s/%s'", pod.Namespace, pod.Name)
	}
	s.podMap.Update(s.podChanges)
	if err := informerFactory.Core().V1().Pods().Informer().GetIndexer().Add(pod); err != nil {
		return fmt.Errorf("failed to update indexer: %w", err)
	}

	return nil
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

func prepareEnv(c *nftables.Conn) (*nftState, string, *Server, *controllers.PodInfo, error) {
	podMockInfo := &controllers.PodInfo{
		Name:      "mock-pod",
		Namespace: "default",
		Interfaces: []controllers.InterfaceInfo{
			{NetattachName: "net0", InterfaceType: "macvlan", InterfaceName: "eth0", IPs: []string{"10.0.0.0", "fd00::"}},
			{NetattachName: "net1", InterfaceType: "macvlan", InterfaceName: "eth1", IPs: []string{"fd01::"}},
			{NetattachName: "net2", InterfaceType: "ipvlan", InterfaceName: "eth2", IPs: []string{"10.0.0.0"}},
		},
	}
	nftState, err := bootstrapNetfilterRules(c, podMockInfo)
	if err != nil {
		return nil, "", nil, podMockInfo, fmt.Errorf("bootstrapNetfilterRules() failed: %w", err)
	}
	if nftState == nil {
		return nil, "", nil, podMockInfo, fmt.Errorf("bootstrapNetfilterRules() returned nil state")
	}
	mockServer := NewFakeServer("server")

	testNs := "testns1"
	if err := AddNamespace(mockServer, testNs); err != nil {
		return nftState, testNs, mockServer, podMockInfo, fmt.Errorf("failed to add namespace %q: %w", testNs, err)
	}

	mockServer.netdefChanges.Update(nil, NewNetDef(testNs, "policy-net-1", NewCNIConfig("testCNI", "multi")))
	mockServer.netdefChanges.Update(nil, NewNetDef(testNs, "policy-net-2", NewCNIConfig("testCNI", "multi")))

	pod1 := NewFakePodWithNetAnnotation(
		testNs,
		"testpod1",
		"policy-net-1",
		NewFakeNetworkStatus(testNs, "policy-net-1", "192.168.1.1", "10.1.1.1"),
		map[string]string{"app": "test"})
	if err := AddPod(mockServer, pod1); err != nil {
		return nftState, testNs, mockServer, podMockInfo, fmt.Errorf("failed to add pod: %w", err)
	}

	pod2 := NewFakePodWithNetAnnotation(
		testNs,
		"testpod2",
		"policy-net-1",
		NewFakeNetworkStatus(testNs, "policy-net-1", "192.168.1.2", "10.1.1.2"),
		map[string]string{"app": "test2"})
	if err := AddPod(mockServer, pod2); err != nil {
		return nftState, testNs, mockServer, podMockInfo, fmt.Errorf("failed to add pod: %w", err)
	}

	err = nftState.applyCommonChainRules(mockServer)
	if err != nil {
		return nftState, testNs, mockServer, podMockInfo, fmt.Errorf("applyCommonChainRules() failed: %w", err)
	}

	return nftState, testNs, mockServer, podMockInfo, nil
}
