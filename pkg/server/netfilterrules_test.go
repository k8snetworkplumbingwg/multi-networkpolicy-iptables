package server

import (
	"fmt"
	"net/netip"
	"testing"

	nftables "github.com/google/nftables"
	"github.com/k8snetworkplumbingwg/multi-networkpolicy-iptables/pkg/controllers"
	"github.com/k8snetworkplumbingwg/multi-networkpolicy-iptables/pkg/nftest"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestBootstrap(t *testing.T) {
	// Open a system connection in a separate network namespace it requires root
	c, newNS := nftest.OpenSystemConn(t, true)
	defer c.CloseLasting()
	defer nftest.CleanupSystemConn(t, newNS)
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
	c, newNS := nftest.OpenSystemConn(t, true)
	defer c.CloseLasting()
	defer nftest.CleanupSystemConn(t, newNS)
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
	c, newNS := nftest.OpenSystemConn(t, true)
	defer c.CloseLasting()
	defer nftest.CleanupSystemConn(t, newNS)
	c.FlushRuleset()
	defer c.FlushRuleset()
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
		t.Fatalf("bootstrapNetfilterRules() failed: %v", err)
	}
	if nftState == nil {
		t.Fatalf("bootstrapNetfilterRules() returned nil state")
	}
	mockServer := &Server{Options: &Options{}}
	err = nftState.applyCommonChainRules(mockServer)
	if err != nil {
		t.Fatalf("applyCommonChainRules() failed: %v", err)
	}
	// Define protocol variables to take their addresses
	protocolTCP := corev1.ProtocolTCP
	protocolUDP := corev1.ProtocolUDP
	protocolSCTP := corev1.ProtocolSCTP

	eighty, ninety, fiftythree, oneTwoThreeFour, twoFourSixEight := intstr.FromInt(80), int32(intstr.FromInt(90).IntVal), intstr.FromInt(53), intstr.FromInt(1234), int32(intstr.FromInt(2468).IntVal)

	mockPolicy := &multiv1beta1.MultiNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "policy-net-1",
			Namespace: "default",
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
}
