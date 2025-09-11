package server

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	nftables "github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"github.com/k8snetworkplumbingwg/multi-networkpolicy-iptables/pkg/controllers"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	"go4.org/netipx"
	"golang.org/x/sys/unix"
	v1 "k8s.io/api/core/v1"
	"k8s.io/klog"
)

const (
	IPv4OffSet = uint32(12) // IPs start at byte 12 in the NetworkBaseHeader
	IPv6OffSet = uint32(8)  // IPv6 IPs start at byte 8 in the NetworkBaseHeader
)

type nftState struct {
	nft *nftables.Conn
	// Tables
	filter *nftables.Table
	nat    *nftables.Table

	// Interface set
	interfaceFilterSet *nftables.Set
	interfaceNatSet    *nftables.Set
	// Interface

	// Common Chains
	input      *nftables.Chain
	output     *nftables.Chain
	prerouting *nftables.Chain

	// multi-networkpolicy chains
	ingressChain       *nftables.Chain
	egressChain        *nftables.Chain
	commonIngressChain *nftables.Chain
	commonEgressChain  *nftables.Chain
}

func bootstrapNetfilterRules(nft *nftables.Conn, podInfo *controllers.PodInfo) (*nftState, error) {
	if podInfo == nil || len(podInfo.Interfaces) == 0 {
		return nil, fmt.Errorf("podInfo or podInfo.Interfaces is nil/empty")
	}

	nftState := &nftState{
		nft: nft,
		// Create filter and nat tables if they don't already exist
		filter: nft.AddTable(&nftables.Table{
			Family: nftables.TableFamilyINet,
			Name:   "filter",
		}),
		nat: nft.AddTable(&nftables.Table{
			Family: nftables.TableFamilyINet,
			Name:   "nat",
		}),
	}
	// Create our chains if they don't already exist
	// nft add chain inet filter input { type filter hook input priority 0 \; }
	nftState.input = nft.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    nftState.filter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Type:     nftables.ChainTypeFilter,
	})
	// nft add chain inet filter output { type filter hook output priority 0 \; }
	nftState.output = nft.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    nftState.filter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Type:     nftables.ChainTypeFilter,
	})
	// nft add chain inet filter prerouting { type filter hook prerouting priority 0 \; }
	nftState.prerouting = nft.AddChain(&nftables.Chain{
		Name:     "prerouting",
		Table:    nftState.nat,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
		Type:     nftables.ChainTypeNAT,
	})
	// add chain inet filter MULTI-INGRESS
	nftState.ingressChain = nft.AddChain(&nftables.Chain{
		Name:  ingressChain,
		Table: nftState.filter,
	})
	// add chain inet filter MULTI-EGRESS
	nftState.egressChain = nft.AddChain(&nftables.Chain{
		Name:  egressChain,
		Table: nftState.filter,
	})
	// nft add chain inet filter MULTI-INGRESS-COMMON
	nftState.commonIngressChain = nft.AddChain(&nftables.Chain{
		Name:  fmt.Sprintf("%s-%s", ingressChain, common),
		Table: nftState.filter,
	})
	// nft add chain inet filter MULTI-EGRESS-COMMON
	nftState.commonEgressChain = nft.AddChain(&nftables.Chain{
		Name:  fmt.Sprintf("%s-%s", egressChain, common),
		Table: nftState.filter,
	})
	slices.SortFunc(podInfo.Interfaces, func(a, b controllers.InterfaceInfo) int {
		return strings.Compare(a.InterfaceName, b.InterfaceName)
	})

	nftState.interfaceFilterSet = &nftables.Set{
		Table:        nftState.filter,
		Name:         podInterfacesName,
		KeyType:      nftables.TypeIFName,
		KeyByteOrder: binaryutil.NativeEndian,
		Counter:      true,
		Comment:      "Pod interfaces",
	}
	nftState.interfaceNatSet = &nftables.Set{
		Table:        nftState.nat,
		Name:         podInterfacesName,
		KeyType:      nftables.TypeIFName,
		KeyByteOrder: binaryutil.NativeEndian,
		Counter:      true,
		Comment:      "Pod interfaces",
	}
	interfaceSetElements := []nftables.SetElement{}
	for index, multiIF := range podInfo.Interfaces {
		interfaceSetElements = append(interfaceSetElements, nftables.SetElement{
			Key:     ifname(multiIF.InterfaceName),
			Comment: fmt.Sprintf("pod interface [%d]: %s", index, multiIF.InterfaceName),
		})
	}
	if err := nft.AddSet(nftState.interfaceFilterSet, interfaceSetElements); err != nil {
		return nil, fmt.Errorf("failed to add interface set: %v", err)
	}
	if err := nft.AddSet(nftState.interfaceNatSet, interfaceSetElements); err != nil {
		return nil, fmt.Errorf("failed to add interface set: %v", err)
	}
	// Add rules to jump to MULTI-INGRESS and MULTI-EGRESS chains from input and output chains respectively
	nft.AddRule(&nftables.Rule{
		Table: nftState.filter,
		Chain: nftState.input,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Lookup{
				SetName:        nftState.interfaceFilterSet.Name,
				SetID:          nftState.interfaceFilterSet.ID,
				SourceRegister: 1,
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: nftState.ingressChain.Name,
			},
		},
	})
	if err := nft.Flush(); err != nil {
		return nil, fmt.Errorf("nftables flush failed input interfaceFilterSet cannot be used: %v", err)
	}
	nft.AddRule(&nftables.Rule{
		Table: nftState.filter,
		Chain: nftState.output,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Lookup{
				SetName:        nftState.interfaceFilterSet.Name,
				SetID:          nftState.interfaceFilterSet.ID,
				SourceRegister: 1,
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: nftState.egressChain.Name,
			},
		},
	})
	if err := nft.Flush(); err != nil {
		return nil, fmt.Errorf("nftables flush failed ouput interfaceFilterSet cannot be used: %v", err)
	}
	nft.AddRule(&nftables.Rule{
		Table: nftState.nat,
		Chain: nftState.prerouting,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Lookup{
				SetName:        nftState.interfaceNatSet.Name,
				SetID:          nftState.interfaceNatSet.ID,
				SourceRegister: 1,
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind: expr.VerdictReturn,
			},
		},
	})
	if err := nft.Flush(); err != nil {
		return nil, fmt.Errorf("nftables flush failed prerouting interfaceNatSet cannot be used: %v", err)
	}
	nft.AddRule(&nftables.Rule{
		Table: nftState.filter,
		Chain: nftState.ingressChain,
		Exprs: []expr.Any{
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: nftState.commonIngressChain.Name,
			},
		},
	})
	nft.AddRule(&nftables.Rule{
		Table: nftState.filter,
		Chain: nftState.egressChain,
		Exprs: []expr.Any{
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: nftState.commonEgressChain.Name,
			},
		},
	})
	err := nft.Flush()
	if err != nil {
		return nil, fmt.Errorf("nftables flush failed for rules with: %v", err)
	}
	return nftState, nil
}
func (n *nftState) allowICMP(chain *nftables.Chain, icmpv6 bool) error {
	data := []byte{unix.IPPROTO_ICMP}
	if icmpv6 {
		data = []byte{unix.IPPROTO_ICMPV6}
	}
	n.nft.AddRule(&nftables.Rule{
		Table: n.filter,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{
				Register: 1,
				Op:       expr.CmpOpEq,
				Data:     data,
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})
	return nil
}

func (n *nftState) applyPrefixRules(chain *nftables.Chain, prefixes []string, prefix string) error {
	v4Set := &nftables.Set{
		Table:    n.filter,
		Name:     fmt.Sprintf("%s_v4_%s", prefix, getAddressSuffix(chain)),
		KeyType:  nftables.TypeIPAddr,
		Interval: true,
	}
	v6Set := &nftables.Set{
		Table:    n.filter,
		Name:     fmt.Sprintf("%s_v6_%s", prefix, getAddressSuffix(chain)),
		KeyType:  nftables.TypeIP6Addr,
		Interval: true,
	}
	v4Prefixes := []nftables.SetElement{
		{
			Key:         netip.IPv4Unspecified().AsSlice(),
			IntervalEnd: true,
		},
	}
	v6Prefixes := []nftables.SetElement{
		{
			Key:         netip.IPv6Unspecified().AsSlice(),
			IntervalEnd: true,
		},
	}
	for index, addr := range prefixes {
		net, err := netip.ParsePrefix(addr) // validate
		if err != nil {
			return fmt.Errorf("failed to parse CIDR %q allowSrcPrefix[%d]: %v", addr, index, err)
		}
		if net.Addr().Is4() {
			v4Prefixes = append(v4Prefixes, convertPrefixToSet(net)...)
		} else {
			v6Prefixes = append(v6Prefixes, convertPrefixToSet(net)...)
		}
	}
	if len(v4Prefixes) > 0 {
		if err := n.nft.AddSet(v4Set, v4Prefixes); err != nil {
			return fmt.Errorf("failed to add ipv4 set %q: %w", v4Set.Name, err)
		}
		// Add rule to accept traffic from allowed IPv4 source prefixes
		// destination address offset is 16, source address offset is 12
		// for ingress chain use offset 12, for egress chain use offset 16
		// nft add rule inet filter MULTI-INGRESS-COMMON ip saddr @allowed_src_prefix_v4 accept
		offset := IPv4OffSet
		if !isIngressChain(chain) {
			offset = IPv4OffSet + net.IPv4len
		}
		n.nft.AddRule(&nftables.Rule{
			Table: n.filter,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       offset,
					Len:          uint32(net.IPv4len),
				},
				&expr.Lookup{
					SetName:        v4Set.Name,
					SetID:          v4Set.ID,
					SourceRegister: 1,
				},
				&expr.Counter{},
				&expr.Verdict{
					Kind: expr.VerdictAccept,
				},
			},
		})
	}
	if len(v6Prefixes) > 0 {
		if err := n.nft.AddSet(v6Set, v6Prefixes); err != nil {
			return fmt.Errorf("failed to add ipv6 set %q: %w", v6Set.Name, err)
		}
		offset := IPv6OffSet
		if !isIngressChain(chain) {
			offset = IPv6OffSet + uint32(net.IPv6len)
		}
		n.nft.AddRule(&nftables.Rule{
			Table: n.filter,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       offset,              // IPv6 offset
					Len:          uint32(net.IPv6len), // IPv6 byte length
				},
				&expr.Lookup{
					SetName:        v6Set.Name,
					SetID:          v6Set.ID,
					SourceRegister: 1,
				},
				&expr.Counter{},
				&expr.Verdict{
					Kind: expr.VerdictAccept,
				},
			},
		})
	}
	return nil
}

func (n *nftState) allowConntracked(chain *nftables.Chain) error {
	// nft add rule inet filter MULTI-<chain>-COMMON ct state related,established accept
	n.nft.AddRule(&nftables.Rule{
		Table: n.filter,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Ct{Register: 1, SourceRegister: false, Key: expr.CtKeySTATE},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
				Xor:            binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})
	return nil
}

func (n *nftState) applyCommonChainRules(s *Server) error {
	if s.Options.acceptICMPv6 {
		n.allowICMP(n.commonIngressChain, true)
		n.allowICMP(n.commonEgressChain, true)
	}
	if s.Options.acceptICMP {
		n.allowICMP(n.commonIngressChain, false)
		n.allowICMP(n.commonEgressChain, false)
	}

	if len(s.Options.allowSrcPrefix) != 0 {
		if err := n.applyPrefixRules(n.commonIngressChain, s.Options.allowSrcPrefix, common); err != nil {
			return fmt.Errorf("failed to apply common ingress rules: %v", err)
		}
		if err := n.allowConntracked(n.commonIngressChain); err != nil {
			return fmt.Errorf("failed to apply common ingress conntrack rules: %v", err)
		}
	}

	if len(s.Options.allowDstPrefix) != 0 {
		if err := n.applyPrefixRules(n.commonEgressChain, s.Options.allowDstPrefix, common); err != nil {
			return fmt.Errorf("failed to apply common egress rules: %v", err)
		}
		if err := n.allowConntracked(n.commonEgressChain); err != nil {
			return fmt.Errorf("failed to apply common egress conntrack rules: %v", err)
		}
	}
	if err := n.nft.Flush(); err != nil {
		return fmt.Errorf("nftables flush failed for common chain rules with: %v", err)
	}
	return nil
}

func convertPrefixToSet(prefix netip.Prefix) []nftables.SetElement {
	// nftables needs half-open intervals [firstIP, lastIP) for prefixes
	// e.g. 10.0.0.0/24 becomes [10.0.0.0, 10.0.1.0), 10.1.1.1/32 becomes [10.1.1.1, 10.1.1.2) etc
	firstIP := prefix.Masked().Addr()
	lastIP := netipx.PrefixLastIP(prefix).Next()
	elements := []nftables.SetElement{
		{Key: firstIP.AsSlice()},
	}
	// It seems .Next does not return a valid IP for the all-0s address
	// So we need to special case that here
	if (lastIP == netip.Addr{}) {
		// we had a turnover, so add the all-0s address as the interval end
		if firstIP.Is4() {
			return append(elements, nftables.SetElement{Key: netip.IPv4Unspecified().AsSlice(), IntervalEnd: true})
		}
		return append(elements, nftables.SetElement{Key: netip.IPv6Unspecified().AsSlice(), IntervalEnd: true})
	}

	return append(elements, nftables.SetElement{Key: lastIP.AsSlice(), IntervalEnd: true})
}

func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, []byte(n+"\x00"))
	return b
}

func userDataComment(comment string) []byte {
	userComment := []byte{}
	userdata.AppendString(userComment, userdata.TypeComment, comment)
	return userComment
}

func (n *nftState) applyPortRules() error {
	return nil
}

func (n *nftState) applyHostRules() error {

	return nil
}

func (n *nftState) applyPodInterfaceRules(chain, policyChain *nftables.Chain, policy *multiv1beta1.MultiNetworkPolicy, podInterface controllers.InterfaceInfo) error {
	// add rule to jump to MULTI-INGRESS-<idx> from MULTI-INGRESS
	// -A MULTI-INGRESS -m comment --comment "policy:policy1 net-attach-def:net-attach-def1" -i net1 -j MULTI-INGRESS-0
	// -A MULTI-INGRESS -m mark --mark 0x30000/0x30000 -j RETURN
	n.nft.AddRule(&nftables.Rule{
		Table:    n.filter,
		Chain:    chain,
		UserData: userDataComment(fmt.Sprintf("policy:%s net-attach-def:%s", policy.Name, podInterface.NetattachName)),
		Exprs: []expr.Any{
			&expr.Meta{Key: getMetaKeyInterface(chain), Register: 1},
			&expr.Cmp{
				Register: 1,
				Op:       expr.CmpOpEq,
				Data:     ifname(podInterface.InterfaceName),
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: policyChain.Name,
			},
		},
	})
	n.nft.AddRule(&nftables.Rule{
		Table: n.filter,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(0x30000),
				Xor:            binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Cmp{
				Register: 1,
				Op:       expr.CmpOpEq,
				Data:     binaryutil.NativeEndian.PutUint32(0x30000),
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind: expr.VerdictReturn,
			},
		},
	})
	return nil
}

// reset previous mark bits
func (n *nftState) applyMarkReset(policyChain *nftables.Chain, policyName string, index int) error {
	n.nft.AddRule(&nftables.Rule{
		Table:    n.filter,
		Chain:    policyChain,
		UserData: userDataComment(fmt.Sprintf("policy:%s ingress[%d] reset", policyName, index)),
		Exprs: []expr.Any{
			&expr.Counter{},
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(^uint32(0x30000)), // 0xfffcffff
				Xor:            binaryutil.NativeEndian.PutUint32(0x0),
			},
			&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1},
		},
	})
	return nil
}

// Check if we matched something and do a early return
func (n *nftState) applyMarkCheck(policyChain *nftables.Chain, policyName string, index int) error {
	n.nft.AddRule(&nftables.Rule{
		Table:    policyChain.Table,
		Chain:    policyChain,
		UserData: userDataComment(fmt.Sprintf("policy:%s ingress[%d] return", policyName, index)),
		Exprs: []expr.Any{
			&expr.Counter{},
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(0x30000),
				Xor:            binaryutil.NativeEndian.PutUint32(0x0),
			},
			&expr.Cmp{
				Register: 1,
				Op:       expr.CmpOpEq,
				Data:     binaryutil.NativeEndian.PutUint32(0x30000),
			},
			&expr.Verdict{Kind: expr.VerdictReturn},
		}})
	return nil
}

func getSetName(str string) string {
	return strings.ReplaceAll(str, "-", "_")
}

// Drop remaining traffic that did not match any policy
func (n *nftState) applyDropRemaining(chain *nftables.Chain) error {
	n.nft.AddRule(&nftables.Rule{
		Table: chain.Table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	})
	return nil
}

func isIngressChain(chain *nftables.Chain) bool {
	return strings.HasPrefix(chain.Name, ingressChain)
}

func getMetaKeyInterface(chain *nftables.Chain) expr.MetaKey {
	if isIngressChain(chain) {
		return expr.MetaKeyIIFNAME
	}
	return expr.MetaKeyOIFNAME
}

func getProtocolInfo(protocol v1.Protocol) (string, []byte) {
	switch protocol {
	case v1.ProtocolUDP:
		return "udp", []byte{unix.IPPROTO_UDP}
	case v1.ProtocolSCTP:
		return "sctp", []byte{unix.IPPROTO_SCTP}
	default:
		return "tcp", []byte{unix.IPPROTO_TCP}
	}
}

func getAddressSuffix(chain *nftables.Chain) string {
	if isIngressChain(chain) {
		return sourceAddressSuffix
	}
	return destinationAddressSuffix
}

func (n *nftState) applyPolicyPeersRulesIPBlock(chain *nftables.Chain, peer multiv1beta1.MultiNetworkPolicyPeer, podInfo *controllers.PodInfo, policyNetworks []string, peerIndex int) error {
	// TODO: implement IPBlock rules
	return nil
}

func (n *nftState) applyPolicyPeersRulesSelector(s *Server, chain *nftables.Chain, peer multiv1beta1.MultiNetworkPolicyPeer, podInfo *controllers.PodInfo, policyNetworks []string, peerIndex int) error {
	// TODO: implement selector rules
	return nil
}

func (n *nftState) applyPolicyPeersRules(s *Server, chain *nftables.Chain, peers []multiv1beta1.MultiNetworkPolicyPeer, podInfo *controllers.PodInfo, policyNetworks []string, peerIndex int) error {
	peersName := fmt.Sprintf("%s-%s-%d", chain.Name, peersChainSuffix, peerIndex)
	peersChain := n.nft.AddChain(&nftables.Chain{
		Name:  peersName,
		Table: chain.Table,
	})
	// sync podmap before calculating rules
	s.podMap.Update(s.podChanges)
	for index, peer := range peers {
		if peer.IPBlock != nil {
			n.applyPolicyPeersRulesIPBlock(peersChain, peer, podInfo, policyNetworks, index)
			continue
		}
		if peer.PodSelector != nil || peer.NamespaceSelector != nil {
			n.applyPolicyPeersRulesSelector(s, peersChain, peer, podInfo, policyNetworks, index)
			continue
		}
		klog.Errorf("unknown rule: %+v", peer)
	}
	if len(peers) == 0 {
		// if no ports are specified, accept all ports
		n.nft.AddRule(&nftables.Rule{
			Table:    chain.Table,
			Chain:    peersChain,
			UserData: userDataComment(fmt.Sprintf("policy:%s no ports skipped accept all", peersChain.Name)),
			Exprs: []expr.Any{
				&expr.Counter{},
				&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            4,
					Mask:           binaryutil.NativeEndian.PutUint32(^uint32(0x20000)), // 0xfffdffff
					Xor:            binaryutil.NativeEndian.PutUint32(0),
				},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            4,
					Mask:           binaryutil.NativeEndian.PutUint32(0xffffffff),
					Xor:            binaryutil.NativeEndian.PutUint32(0x20000), // 0x200000
				},
				&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1},
			}})
	}
	_ = peersChain
	return nil
}

func (n *nftState) getInetSet(chain *nftables.Chain, portsName, suffix string) *nftables.Set {
	return &nftables.Set{
		Table:     chain.Table,
		Name:      fmt.Sprintf("%s_%s", getSetName(portsName), suffix),
		Anonymous: true,
		Constant:  true,
		Counter:   true,
		KeyType:   nftables.TypeInetService,
		Interval:  true,
	}
}

func (n *nftState) applyProtoPortsRules(chain *nftables.Chain, set *nftables.Set, interfaceName string, unixProto []byte) error {
	n.nft.AddRule(&nftables.Rule{
		Table: chain.Table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: getMetaKeyInterface(chain), Register: 1},
			&expr.Cmp{
				Register: 1,
				Op:       expr.CmpOpEq,
				Data:     ifname(interfaceName),
			},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{
				Register: 1,
				Op:       expr.CmpOpEq,
				Data:     unixProto,
			},
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2, // l4 offset
				Len:          2, // l4 offset
			},
			&expr.Lookup{
				SetName:        set.Name,
				SetID:          set.ID,
				SourceRegister: 1,
			},
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			// implement the mark as follows:
			// clear the 0x10000 bit
			// set the 0x10000 bit
			// this allows us to check if we matched any port rule
			// without affecting any other bits that might be in use
			// e.g. 0x20000 for address detection
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(^uint32(0x10000)), // 0xfffeffff
				Xor:            binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(0xffffffff),
				Xor:            binaryutil.NativeEndian.PutUint32(0x10000), // 0x100000
			},
			&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1},
		},
	})
	return nil
}

func (n *nftState) applyPolicyPortRules(chain *nftables.Chain, ports []multiv1beta1.MultiNetworkPolicyPort, podInterface controllers.InterfaceInfo, portIndex int) error {
	portsName := fmt.Sprintf("%s-%s-%d", chain.Name, portsChainSuffix, portIndex)
	// create ports chain
	portChain := n.nft.AddChain(&nftables.Chain{
		Name:  portsName,
		Table: chain.Table,
	})
	n.nft.AddRule(&nftables.Rule{
		Table: chain.Table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Counter{},
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: portChain.Name,
			},
		}})
	// 	writeLine(ipt.policyIndex, "-A", fmt.Sprintf("MULTI-%d-INGRESS", pIndex), "-j", chainName)
	portsTCP := []nftables.SetElement{}
	portsUDP := []nftables.SetElement{}
	portsSCTP := []nftables.SetElement{}
	// validate ports and protocols
	for _, port := range ports {
		var portElements []nftables.SetElement
		// validate port range
		if port.Port != nil {
			if port.Port.IntValue() < 1 || port.Port.IntValue() > 65535 {
				return fmt.Errorf("port %d out of range, must be between 1 and 65535", port.Port.IntValue())
			}
			portElements = append(portElements, nftables.SetElement{
				Key: binaryutil.BigEndian.PutUint16(uint16(port.Port.IntValue())),
			})
			if port.EndPort != nil && *port.EndPort > int32(port.Port.IntValue()) {
				if *port.EndPort < 1 || *port.EndPort > 65535 {
					return fmt.Errorf("port %d out of range, must be between 1 and 65535", port.Port.IntValue())
				}
				// keep the half open interval semantics of nftables
				// e.g. 1000-2000 becomes [1000, 2001)
				// so we need to add 1 to the end port
				portElements = append(portElements, nftables.SetElement{
					Key:         binaryutil.BigEndian.PutUint16(uint16(*port.EndPort) + 1),
					IntervalEnd: true,
				})
			} else {
				// keep the half open interval semantics of nftables
				// e.g. 1000 becomes [1000, 1001)
				// so we need to add 1 to the port
				portElements = append(portElements, nftables.SetElement{
					Key:         binaryutil.BigEndian.PutUint16(uint16(port.Port.IntValue()) + 1),
					IntervalEnd: true,
				})
			}
		}
		switch *port.Protocol {
		case v1.ProtocolUDP:
			portsUDP = append(portsUDP, portElements...)
		case v1.ProtocolSCTP:
			portsSCTP = append(portsSCTP, portElements...)
		default:
			// case v1.ProtocolTCP:
			portsTCP = append(portsTCP, portElements...)
		}
	}
	if len(portsTCP) > 0 {
		suffix, unixFlag := getProtocolInfo(v1.ProtocolTCP)
		tcpSet := n.getInetSet(chain, portsName, suffix)
		if err := n.nft.AddSet(tcpSet, portsTCP); err != nil {
			return fmt.Errorf("failed to add tcp port set %q: %w", tcpSet.Name, err)
		}
		if err := n.applyProtoPortsRules(portChain, tcpSet, podInterface.InterfaceName, unixFlag); err != nil {
			return fmt.Errorf("failed to apply tcp port rules for set %q: %w", tcpSet.Name, err)
		}
	}
	if len(portsUDP) > 0 {
		suffix, unixFlag := getProtocolInfo(v1.ProtocolUDP)
		udpSet := n.getInetSet(chain, portsName, suffix)
		if err := n.nft.AddSet(udpSet, portsUDP); err != nil {
			return fmt.Errorf("failed to add udp port set %q: %w", udpSet.Name, err)
		}
		if err := n.applyProtoPortsRules(portChain, udpSet, podInterface.InterfaceName, unixFlag); err != nil {
			return fmt.Errorf("failed to apply udp port rules for set %q: %w", udpSet.Name, err)
		}
	}
	if len(portsSCTP) > 0 {
		suffix, unixFlag := getProtocolInfo(v1.ProtocolSCTP)
		sctpSet := n.getInetSet(chain, portsName, suffix)
		if err := n.nft.AddSet(sctpSet, portsSCTP); err != nil {
			return fmt.Errorf("failed to add sctp port set %q: %w", sctpSet.Name, err)
		}
		if err := n.applyProtoPortsRules(portChain, sctpSet, podInterface.InterfaceName, unixFlag); err != nil {
			return fmt.Errorf("failed to apply sctp port rules for set %q: %w", sctpSet.Name, err)
		}
	}
	if len(ports) == 0 || (len(portsTCP) == 0 && len(portsUDP) == 0 && len(portsSCTP) == 0) {
		// if no ports are specified, accept all ports
		n.nft.AddRule(&nftables.Rule{
			Table:    chain.Table,
			Chain:    portChain,
			UserData: userDataComment(fmt.Sprintf("policy:%s no ports skipped accept all", portChain.Name)),
			Exprs: []expr.Any{
				&expr.Counter{},
				&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            4,
					Mask:           binaryutil.NativeEndian.PutUint32(^uint32(0x10000)), // 0xfffeffff
					Xor:            binaryutil.NativeEndian.PutUint32(0),
				},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            4,
					Mask:           binaryutil.NativeEndian.PutUint32(0xffffffff),
					Xor:            binaryutil.NativeEndian.PutUint32(0x10000), // 0x100000
				},
				&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1},
			}})
	}
	return nil
}

// s *Server, podInfo *controllers.PodInfo, pIndex, iIndex int, from []multiv1beta1.MultiNetworkPolicyPeer, policyNetworks []string
func (n *nftState) applyPodRules(s *Server, chain *nftables.Chain, podInfo *controllers.PodInfo, idx int, policy *multiv1beta1.MultiNetworkPolicy, policyNetworks []string) error {
	_ = s
	// add chain inet filter MULTI-INGRESS-<idx>
	policyChain := n.nft.AddChain(&nftables.Chain{
		Name:  fmt.Sprintf("%s-%d", chain.Name, idx),
		Table: n.filter,
	})
	for _, podIntf := range podInfo.Interfaces {
		if podIntf.CheckPolicyNetwork(policyNetworks) {
			n.applyPodInterfaceRules(chain, policyChain, policy, podIntf)
		}
	}
	if isIngressChain(chain) {
		for index, ingress := range policy.Spec.Ingress {
			// reset previous mark bits
			n.applyMarkReset(policyChain, policy.Name, index)
			// apply ports

			for _, podIntf := range podInfo.Interfaces {
				if podIntf.CheckPolicyNetwork(policyNetworks) {
					if err := n.applyPolicyPortRules(policyChain, ingress.Ports, podIntf, index); err != nil {
						return fmt.Errorf("failed to apply ingress ports for policy %q: %w", policy.Name, err)
					}
					if err := n.applyPolicyPeersRules(s, policyChain, ingress.From, podInfo, policyNetworks, index); err != nil {
						return fmt.Errorf("failed to apply ingress address rules for policy %q: %w", policy.Name, err)
					}
				}
			}

			// apply addresses
			_ = ingress

			// Check if we matched something and do a early return
			n.applyMarkCheck(policyChain, policy.Name, index)
		}
	} else {
		for index, egress := range policy.Spec.Egress {
			n.applyMarkReset(policyChain, policy.Name, index)
			for _, podIntf := range podInfo.Interfaces {
				if podIntf.CheckPolicyNetwork(policyNetworks) {
					if err := n.applyPolicyPortRules(policyChain, egress.Ports, podIntf, index); err != nil {
						return fmt.Errorf("failed to apply egress ports for policy %q: %w", policy.Name, err)
					}
					if err := n.applyPolicyPeersRules(s, policyChain, egress.To, podInfo, policyNetworks, index); err != nil {
						return fmt.Errorf("failed to apply egress address rules for policy %q: %w", policy.Name, err)
					}
				}
			}
			_ = egress

			n.applyMarkCheck(policyChain, policy.Name, index)
		}
	}
	return nil
}
