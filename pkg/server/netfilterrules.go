package server

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"

	nftables "github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"github.com/k8snetworkplumbingwg/multi-networkpolicy-iptables/pkg/controllers"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	"go4.org/netipx"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
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

	rules  map[string]*nftables.Rule
	sets   map[string]*nftables.Set
	chains map[string]*nftables.Chain
}

func bootstrapNetfilterChains(nftState *nftState) {
	// the netfilter hook system
	// ref: https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks
	// Create our chains if they don't already exist
	// nft add chain inet filter input { type filter hook input priority 0 \; }
	var err error
	if nftState.input, err = nftState.addChain(&nftables.Chain{
		Name:     "input",
		Table:    nftState.filter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Type:     nftables.ChainTypeFilter,
	}); err != nil {
		klog.Errorf("failed to create chain: %v", err)
	}
	// nft add chain inet filter output { type filter hook output priority 0 \; }
	if nftState.output, err = nftState.addChain(&nftables.Chain{
		Name:     "output",
		Table:    nftState.filter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Type:     nftables.ChainTypeFilter,
	}); err != nil {
		klog.Errorf("failed to create chain: %v", err)
	}
	// nft add chain inet filter prerouting { type filter hook prerouting priority 0 \; }
	if nftState.prerouting, err = nftState.addChain(&nftables.Chain{
		Name:     "prerouting",
		Table:    nftState.nat,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
		Type:     nftables.ChainTypeNAT,
	}); err != nil {
		klog.Errorf("failed to create chain: %v", err)
	}
	// add chain inet filter MULTI-INGRESS
	if nftState.ingressChain, err = nftState.addChain(&nftables.Chain{
		Name:  ingressChain,
		Table: nftState.filter,
	}); err != nil {
		klog.Errorf("failed to create chain: %v", err)
	}
	// add chain inet filter MULTI-EGRESS
	if nftState.egressChain, err = nftState.addChain(&nftables.Chain{
		Name:  egressChain,
		Table: nftState.filter,
	}); err != nil {
		klog.Errorf("failed to create chain: %v", err)
	}
	// nft add chain inet filter MULTI-INGRESS-COMMON
	if nftState.commonIngressChain, err = nftState.addChain(&nftables.Chain{
		Name:  fmt.Sprintf("%s-%s", ingressChain, common),
		Table: nftState.filter,
	}); err != nil {
		klog.Errorf("failed to create chain: %v", err)
	}
	// nft add chain inet filter MULTI-EGRESS-COMMON
	if nftState.commonEgressChain, err = nftState.addChain(&nftables.Chain{
		Name:  fmt.Sprintf("%s-%s", egressChain, common),
		Table: nftState.filter,
	}); err != nil {
		klog.Errorf("failed to create chain: %v", err)
	}
}

func addTable(nft *nftables.Conn, table *nftables.Table) (*nftables.Table, error) {
	t, err := nft.ListTableOfFamily(table.Name, table.Family)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("failed to check existance of table %q: %w", table.Name, err)
	} else if err != nil && errors.Is(err, os.ErrNotExist) {
		klog.V(8).Infof("adding table %q", table.Name)
		t = nft.AddTable(table)
	}

	return t, nil
}

func bootstrapNetfilterRules(nft *nftables.Conn, podInfo *controllers.PodInfo) (*nftState, error) {
	if podInfo == nil || len(podInfo.Interfaces) == 0 {
		return nil, fmt.Errorf("podInfo or podInfo.Interfaces is nil/empty")
	}

	filterTable, err := addTable(nft, &nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "filter",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add table: %w", err)
	}

	natTable, err := addTable(nft, &nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "nat",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add table: %w", err)
	}

	nftState := &nftState{
		nft: nft,
		// Create filter and nat tables if they don't already exist
		filter: filterTable,
		nat:    natTable,
		rules:  make(map[string]*nftables.Rule),
		sets:   make(map[string]*nftables.Set),
		chains: make(map[string]*nftables.Chain),
	}

	bootstrapNetfilterChains(nftState)

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
		Comment:      "Pod interfaces NAT",
	}

	interfaceSetElements := []nftables.SetElement{}
	for index, multiIF := range podInfo.Interfaces {
		interfaceSetElements = append(interfaceSetElements, nftables.SetElement{
			Key:     ifname(multiIF.InterfaceName),
			Comment: fmt.Sprintf("pod interface [%d]: %s", index, multiIF.InterfaceName),
		})
	}

	if err := nftState.updateSet(nftState.interfaceFilterSet, interfaceSetElements); err != nil {
		return nftState, fmt.Errorf("failed to update filter set: %w", err)
	}

	inputInterfaceFilterComment := "input-interface-filter"
	outputInterfaceFilterComment := "output-interface-filter"

	filterInputRule := &nftables.Rule{
		Table:    nftState.filter,
		Chain:    nftState.input,
		UserData: userDataComment(inputInterfaceFilterComment),
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
	}

	if err := nftState.updateRule(filterInputRule, nft.InsertRule); err != nil {
		return nftState, fmt.Errorf("failed to install rule: %w", err)
	}

	filterOutputRule := &nftables.Rule{
		Table:    nftState.filter,
		Chain:    nftState.output,
		UserData: userDataComment(outputInterfaceFilterComment),
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
	}

	if err := nftState.updateRule(filterOutputRule, nft.InsertRule); err != nil {
		return nftState, fmt.Errorf("failed to install rule: %w", err)
	}

	if err := nftState.updateSet(nftState.interfaceNatSet, interfaceSetElements); err != nil {
		return nftState, fmt.Errorf("failed to update NAT set: %w", err)
	}

	if err := nftState.updateRule(&nftables.Rule{
		Table:    nftState.nat,
		Chain:    nftState.prerouting,
		UserData: userDataComment("nat-filter-rule"),
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
	}, nft.InsertRule); err != nil {
		return nftState, err
	}

	if err := nftState.updateRule(&nftables.Rule{
		Table:    nftState.filter,
		Chain:    nftState.ingressChain,
		UserData: userDataComment("common-ingress-chain"),
		Exprs: []expr.Any{
			&expr.Counter{},
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: nftState.commonIngressChain.Name,
			},
		},
	}, nft.InsertRule); err != nil {
		return nftState, err
	}

	if err := nftState.updateRule(&nftables.Rule{
		Table:    nftState.filter,
		Chain:    nftState.egressChain,
		UserData: userDataComment("common-egress-chain"),
		Exprs: []expr.Any{
			&expr.Counter{},
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: nftState.commonEgressChain.Name,
			},
		},
	}, nft.InsertRule); err != nil {
		return nftState, err
	}

	return nftState, nil
}

func (n *nftState) updateRule(rule *nftables.Rule, action func(r *nftables.Rule) *nftables.Rule) error {
	comment, _ := userdata.GetString(rule.UserData, userdata.TypeComment)

	existingRule, err := n.findRule(rule)
	if err != nil {
		return fmt.Errorf("failed to get rule by comment: %w", err)
	}

	if existingRule != nil {
		rule = existingRule
	} else {
		klog.V(8).Infof("adding rule %q", comment)
		action(rule)
	}

	key, err := hash(rule)
	if err != nil {
		return fmt.Errorf("failed to get hash for rule %q: %w", comment, err)
	}
	n.rules[key] = rule

	return nil
}

func ruleEqual(a, b *nftables.Rule) bool {
	if a.Chain.Name != b.Chain.Name {
		return false
	}
	if a.Table.Name != b.Table.Name {
		return false
	}

	if !bytes.Equal(a.UserData, b.UserData) {
		return false
	}

	for i := range a.Exprs {
		switch a.Exprs[i].(type) {
		case *expr.Meta:
			if !exprEqual(&expr.Meta{}, a.Exprs[i], b.Exprs[i]) {
				return false
			}
		case *expr.Lookup:
			if !exprEqual(&expr.Lookup{}, a.Exprs[i], b.Exprs[i]) {
				return false
			}
		case *expr.Verdict:
			if !exprEqual(&expr.Verdict{}, a.Exprs[i], b.Exprs[i]) {
				return false
			}
		case *expr.Cmp:
			if !exprEqual(&expr.Cmp{}, a.Exprs[i], b.Exprs[i]) {
				return false
			}
		case *expr.Payload:
			if !exprEqual(&expr.Payload{}, a.Exprs[i], b.Exprs[i]) {
				return false
			}
		case *expr.Ct:
			if !exprEqual(&expr.Ct{}, a.Exprs[i], b.Exprs[i]) {
				return false
			}
		case *expr.Bitwise:
			if !exprEqual(&expr.Bitwise{}, a.Exprs[i], b.Exprs[i]) {
				return false
			}
		}
	}

	return true
}

func exprEqual[V *expr.Meta | *expr.Lookup | *expr.Verdict | *expr.Cmp | *expr.Payload | *expr.Ct | *expr.Bitwise](_ V, aExpr, bExpr expr.Any) bool {
	aExprCast, ok := aExpr.(V)
	if !ok {
		return false
	}
	bExprCast, ok := bExpr.(V)
	if !ok {
		return false
	}
	if reflect.DeepEqual(aExprCast, bExprCast) {
		return true
	}
	return false
}

func (n *nftState) updateSet(set *nftables.Set, elements []nftables.SetElement) error {
	if len(set.Name) > 31 {
		var err error
		set.Name, err = hash(set.Name)
		if err != nil {
			return fmt.Errorf("failed to hash set name %q: %w", set.Name, err)
		}
	}
	existingSet, err := n.nft.GetSetByName(set.Table, set.Name)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to get set: %w", err)
	}

	exists := err == nil && existingSet != nil

	if exists {
		existingElements, err := n.nft.GetSetElements(existingSet)
		if err != nil {
			return fmt.Errorf("failed to get elements for set %q, table %q", existingSet.Name, existingSet.Table.Name)
		}

		toAdd, toDel := processElements(elements, existingElements)

		if len(toAdd) > 0 || len(toDel) > 0 {
			klog.V(8).Infof("updating set %q, table %q", existingSet.Name, existingSet.Table.Name)
			if len(toDel) > 0 {
				if err := n.nft.SetDeleteElements(existingSet, toDel); err != nil {
					return fmt.Errorf("failed to remove elements from set %q: %w", existingSet.Name, err)
				}
			}

			if len(toAdd) > 0 {
				if err := n.nft.SetAddElements(existingSet, toAdd); err != nil {
					return fmt.Errorf("failed to add elements to set %q: %w", existingSet.Name, err)
				}
			}
		}

		n.sets[fmt.Sprintf("%s-%s", set.Table.Name, set.Name)] = existingSet

		return nil
	}

	klog.V(8).Infof("adding set %q, table %q", set.Name, set.Table.Name)
	if err := n.nft.AddSet(set, elements); err != nil {
		return fmt.Errorf("failed to add interface set: %v", err)
	}

	n.sets[fmt.Sprintf("%s-%s", set.Table.Name, set.Name)] = set
	return nil
}

func processElements(newEls, existingEls []nftables.SetElement) (toAdd, toDel []nftables.SetElement) {
	toAdd = findNonCommon(newEls, existingEls)
	toDel = findNonCommon(existingEls, newEls)
	return
}

func findNonCommon(a, b []nftables.SetElement) []nftables.SetElement {
	nonCommon := []nftables.SetElement{}
	for i := range a {
		if !isPresent(a[i], b) {
			nonCommon = append(nonCommon, a[i])
		}
	}
	return nonCommon
}

func isPresent(toCheck nftables.SetElement, elements []nftables.SetElement) bool {
	for _, e := range elements {
		if slices.Compare(toCheck.Key, e.Key) == 0 {
			return true
		}
	}

	return false
}

func (n *nftState) allowICMP(chain *nftables.Chain, icmpv6 bool) error {
	data := []byte{unix.IPPROTO_ICMP}
	proto := protoIPv4
	if icmpv6 {
		data = []byte{unix.IPPROTO_ICMPV6}
		proto = protoIPv6
	}

	return n.updateRule(&nftables.Rule{
		Table:    n.filter,
		Chain:    chain,
		UserData: userDataComment(fmt.Sprintf("allow_icmp_%s", proto)),
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
	}, n.nft.AddRule)
}

func (n *nftState) allowNeighborDiscovery(chain *nftables.Chain) error {
	ndpSetName := "ndp_set"

	ndpSet := &nftables.Set{
		Table:   n.filter,
		Name:    ndpSetName,
		KeyType: nftables.TypeICMP6Type,
		Counter: true,
	}

	ndpElements := []nftables.SetElement{
		{
			Key: []byte{byte(ipv6.ICMPTypeRouterSolicitation)},
		},
		{
			Key: []byte{byte(ipv6.ICMPTypeRouterAdvertisement)},
		},
		{
			Key: []byte{byte(ipv6.ICMPTypeNeighborSolicitation)},
		},
		{
			Key: []byte{byte(ipv6.ICMPTypeNeighborAdvertisement)},
		},
	}

	if err := n.updateSet(ndpSet, ndpElements); err != nil {
		return fmt.Errorf("failed to update NDP set: %w", err)
	}

	if err := n.updateRule(&nftables.Rule{
		Table:    n.filter,
		Chain:    chain,
		UserData: userDataComment("allow IPv6 NDP"),
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.NativeEndian.PutUint32(0x0000000a),
			},
			&expr.Meta{
				Key:      expr.MetaKeyL4PROTO,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.NativeEndian.PutUint32(0x0000003a),
			},
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Len:          1,
			},
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        ndpSet.Name,
				SetID:          ndpSet.ID,
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	}, n.nft.AddRule); err != nil {
		return fmt.Errorf("failed to add IPv6 NDP discovery rule: %w", err)
	}

	return nil
}

func getPrefixesAsSetInterval(prefixes []string) ([]nftables.SetElement, []nftables.SetElement, error) {
	v4Prefixes := []nftables.SetElement{}
	v6Prefixes := []nftables.SetElement{}
	for index, addr := range prefixes {
		net, err := netip.ParsePrefix(addr) // validate
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse CIDR %q prefix[%d]: %v", addr, index, err)
		}
		if net.Addr().Is4() {
			// specific first element to inform nftables this is an interval set
			if index == 0 {
				v4Prefixes = append(v4Prefixes, nftables.SetElement{
					Key:         netip.IPv4Unspecified().AsSlice(),
					IntervalEnd: true,
				})
			}
			v4Prefixes = append(v4Prefixes, convertPrefixToSet(net)...)
		} else {
			// specific first element to inform nftables this is an interval set
			if index == 0 {
				v6Prefixes = append(v6Prefixes, nftables.SetElement{
					Key:         netip.IPv6Unspecified().AsSlice(),
					IntervalEnd: true,
				})
			}
			v6Prefixes = append(v6Prefixes, convertPrefixToSet(net)...)
		}
	}
	return v4Prefixes, v6Prefixes, nil
}

func (n *nftState) applyCommonPrefixRules(chain *nftables.Chain, prefixes []string, prefix string) error {
	v4Set := &nftables.Set{
		Table:    n.filter,
		Name:     fmt.Sprintf("%s_%s_%s", prefix, protoIPv4, getAddressSuffix(chain)),
		KeyType:  nftables.TypeIPAddr,
		Interval: true,
	}
	v6Set := &nftables.Set{
		Table:    n.filter,
		Name:     fmt.Sprintf("%s_%s_%s", prefix, protoIPv6, getAddressSuffix(chain)),
		KeyType:  nftables.TypeIP6Addr,
		Interval: true,
	}
	v4Prefixes, v6Prefixes, err := getPrefixesAsSetInterval(prefixes)
	if err != nil {
		return fmt.Errorf("failed to get prefix sets of prefixes [%s]: %w", prefixes, err)
	}

	if len(v4Prefixes) > 0 {
		if err := n.updateSet(v4Set, v4Prefixes); err != nil {
			return fmt.Errorf("failed to update set: %w", err)
		}

		// Add rule to accept traffic from allowed IPv4 source prefixes
		// destination address offset is 16, source address offset is 12
		// for ingress chain use offset 12, for egress chain use offset 16
		// nft add rule inet filter MULTI-INGRESS-COMMON ip saddr @allowed_src_prefix_ipv4 accept
		offset := IPv4OffSet
		if !isIngressChain(chain) {
			offset = IPv4OffSet + net.IPv4len
		}

		if err := n.updateRule(&nftables.Rule{
			Table:    n.filter,
			Chain:    chain,
			UserData: userDataComment(fmt.Sprintf("common rule:%s", v4Set.Name)),
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
		}, n.nft.AddRule); err != nil {
			return err
		}
	}
	if len(v6Prefixes) > 0 {
		if err := n.updateSet(v6Set, v6Prefixes); err != nil {
			return fmt.Errorf("failed to update set: %w", err)
		}

		offset := IPv6OffSet
		if !isIngressChain(chain) {
			offset = IPv6OffSet + uint32(net.IPv6len)
		}
		if err := n.updateRule(&nftables.Rule{
			Table:    n.filter,
			Chain:    chain,
			UserData: userDataComment(fmt.Sprintf("common rule:%s", v6Set.Name)),
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
		}, n.nft.AddRule); err != nil {
			return err
		}
	}
	return nil
}

func (n *nftState) allowConntracked(chain *nftables.Chain) error {
	// nft add rule inet filter MULTI-<chain>-COMMON ct state related,established accept
	return n.updateRule(&nftables.Rule{
		Table:    n.filter,
		Chain:    chain,
		UserData: userDataComment(allowConntrackRuleName),
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
	}, n.nft.AddRule)
}

func (n *nftState) applyCommonChainRules(s *Server) error {
	klog.V(8).Info("applying common chain rules")
	if s.Options.acceptICMPv6 {
		if err := n.allowICMP(n.commonIngressChain, true); err != nil {
			return fmt.Errorf("failed to allow ICMPv6 in common ingress chain: %v", err)
		}
		if err := n.allowICMP(n.commonEgressChain, true); err != nil {
			return fmt.Errorf("failed to allow ICMPv6 in common egress chain: %v", err)
		}
	} else {
		if err := n.allowNeighborDiscovery(n.commonIngressChain); err != nil {
			return fmt.Errorf("failed to allow ICMPv6 neighbor discovery in common ingress chain: %v", err)
		}
		if err := n.allowNeighborDiscovery(n.commonEgressChain); err != nil {
			return fmt.Errorf("failed to allow ICMPv6 neighbor discovery in common egress chain: %v", err)
		}
	}
	if s.Options.acceptICMP {
		if err := n.allowICMP(n.commonIngressChain, false); err != nil {
			return fmt.Errorf("failed to allow ICMP in common ingress chain: %v", err)
		}
		if err := n.allowICMP(n.commonEgressChain, false); err != nil {
			return fmt.Errorf("failed to allow ICMP in common egress chain: %v", err)
		}
	}

	if len(s.Options.allowSrcPrefix) != 0 {
		if err := n.applyCommonPrefixRules(n.commonIngressChain, s.Options.allowSrcPrefix, common); err != nil {
			return fmt.Errorf("failed to apply common ingress rules: %v", err)
		}
	}

	if len(s.Options.allowDstPrefix) != 0 {
		if err := n.applyCommonPrefixRules(n.commonEgressChain, s.Options.allowDstPrefix, common); err != nil {
			return fmt.Errorf("failed to apply common egress rules: %v", err)
		}
	}
	// Always allow conntracked connections
	if err := n.allowConntracked(n.commonIngressChain); err != nil {
		return fmt.Errorf("failed to apply common ingress conntrack rules: %v", err)
	}
	if err := n.allowConntracked(n.commonEgressChain); err != nil {
		return fmt.Errorf("failed to apply common egress conntrack rules: %v", err)
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
	return userdata.AppendString([]byte{}, userdata.TypeComment, comment)
}

func (n *nftState) applyPodInterfaceRules(chain, policyChain *nftables.Chain, policy *multiv1beta1.MultiNetworkPolicy, podInterface controllers.InterfaceInfo) error {
	// add rule to jump to MULTI-INGRESS-<idx> from MULTI-INGRESS
	// -A MULTI-INGRESS -m comment --comment "policy:policy1 net-attach-def:net-attach-def1" -i net1 -j MULTI-INGRESS-0
	// -A MULTI-INGRESS -m mark --mark 0x30000/0x30000 -j RETURN

	klog.V(8).Infof("applying pod interface:%s [%q] polcy %q chain: %s", podInterface.InterfaceName, podInterface.InterfaceType, policyNamespacedName(policy), policyChain.Name)

	if err := n.updateRule(&nftables.Rule{
		Table:    n.filter,
		Chain:    chain,
		UserData: userDataComment(fmt.Sprintf("policy:%s net-attach-def:%s interface:%s [%q]", policy.Name, podInterface.NetattachName, podInterface.InterfaceName, podInterface.InterfaceType)),
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
	}, n.nft.AddRule); err != nil {
		return err
	}

	if err := n.updateRule(&nftables.Rule{
		Table:    n.filter,
		Chain:    chain,
		UserData: userDataComment(fmt.Sprintf("policy:%s check mark 0x30000, %s", policy.Name, podInterface.InterfaceName)),
		Exprs: []expr.Any{
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
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictReturn},
		}}, n.nft.AddRule); err != nil {
		return err
	}

	return nil
}

// reset previous mark bits
func (n *nftState) applyMarkReset(policyChain *nftables.Chain, policyName string, index int) error {
	klog.V(8).Infof("applying mark reset %q: %s", policyName, policyChain.Name)
	return n.updateRule(&nftables.Rule{
		Table:    n.filter,
		Chain:    policyChain,
		UserData: userDataComment(fmt.Sprintf("policy:%s ingress[%d] reset", policyName, index)),
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(^uint32(0x30000)), // 0xfffcffff
				Xor:            binaryutil.NativeEndian.PutUint32(0x0),
			},
			&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1},
			&expr.Counter{},
		},
	}, n.nft.AddRule)
}

// Check if we matched something and do a early return
func (n *nftState) applyMarkCheck(policyChain *nftables.Chain, policyName string, index int) error {
	klog.V(8).Infof("applying mark check %q: %s", policyName, policyChain.Name)
	return n.updateRule(&nftables.Rule{
		Table:    policyChain.Table,
		Chain:    policyChain,
		UserData: userDataComment(fmt.Sprintf("policy:%s ingress[%d] return", policyName, index)),
		Exprs: []expr.Any{
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
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictReturn},
		}}, n.nft.AddRule)
}

func getSetName(str string) string {
	return strings.ReplaceAll(str, "-", "_")
}

// Drop remaining traffic that did not match any policy
func (n *nftState) applyDropRemaining(chain *nftables.Chain) error {
	return n.updateRule(&nftables.Rule{
		Table:    chain.Table,
		Chain:    chain,
		UserData: userDataComment("drop remaining"),
		Exprs: []expr.Any{
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	}, n.nft.AddRule)
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

func (n *nftState) applyPrefixes(chain *nftables.Chain, policyName string, peer multiv1beta1.MultiNetworkPolicyPeer, peerIndex int, prefixes, exceptPrefixes []nftables.SetElement, isV6 bool) error {

	protocol := protoIPv4
	keyType := nftables.TypeIPAddr
	payloadLen := uint32(net.IPv4len)
	if isV6 {
		protocol = protoIPv6
		keyType = nftables.TypeIP6Addr
		payloadLen = uint32(net.IPv6len)
	}

	if len(prefixes) > 0 {
		offset := IPv4OffSet
		if isV6 {
			offset = IPv6OffSet
		}
		if !isIngressChain(chain) {
			if !isV6 {
				offset += net.IPv4len
			} else {
				offset += net.IPv6len
			}
		}
		if len(exceptPrefixes) > 0 {
			setName := fmt.Sprintf("%s_%s_%s_%s_%d", chain.Name, peerIPBlockExceptPrefix, protocol, getAddressSuffix(chain), peerIndex)
			ruleComment := fmt.Sprintf("%s policy:%s excepts-for:%s", chain.Name, policyName, peer.IPBlock.CIDR)

			exceptSet := &nftables.Set{
				Table:    chain.Table,
				Name:     setName,
				Counter:  true,
				KeyType:  keyType,
				Interval: true,
			}

			if err := n.updateSet(exceptSet, exceptPrefixes); err != nil {
				return fmt.Errorf("failed to update set: %w", err)
			}

			if err := n.updateRule(&nftables.Rule{
				Table:    chain.Table,
				Chain:    chain,
				UserData: userDataComment(ruleComment),
				Exprs: []expr.Any{
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       offset,
						Len:          payloadLen,
					},
					&expr.Lookup{
						SetName:        exceptSet.Name,
						SetID:          exceptSet.ID,
						SourceRegister: 1,
					},
					&expr.Counter{},
					&expr.Verdict{
						Kind: expr.VerdictDrop,
					},
				},
			}, n.nft.AddRule); err != nil {
				return err
			}
		}

		prefixesSet := &nftables.Set{
			Table:    chain.Table,
			Name:     fmt.Sprintf("%s_%s_%s_%s_%d", chain.Name, peerIPBlockPrefix, protocol, getAddressSuffix(chain), peerIndex),
			Constant: true,
			Counter:  true,
			KeyType:  keyType,
			Interval: true,
		}

		if err := n.updateSet(prefixesSet, prefixes); err != nil {
			return fmt.Errorf("failed to update set: %w", err)
		}

		if err := n.updateRule(&nftables.Rule{
			Table:    chain.Table,
			Chain:    chain,
			UserData: userDataComment(fmt.Sprintf("%s accept policy:%s cidr:%s", chain.Name, policyName, peer.IPBlock.CIDR)),
			Exprs: []expr.Any{
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       offset,
					Len:          payloadLen,
				},
				&expr.Lookup{
					SetName:        prefixesSet.Name,
					SetID:          prefixesSet.ID,
					SourceRegister: 1,
				},
				&expr.Counter{},
				&expr.Verdict{
					Kind: expr.VerdictAccept,
				},
			},
		}, n.nft.AddRule); err != nil {
			return err
		}
	}

	return nil
}

func (n *nftState) applyPolicyPeersRulesIPBlock(chain *nftables.Chain, policyName string, peer multiv1beta1.MultiNetworkPolicyPeer, peerIndex int) error {
	v4ExceptPrefixes, v6ExceptPrefixes, err := getPrefixesAsSetInterval(peer.IPBlock.Except)
	if err != nil {
		return fmt.Errorf("failed to get except prefix sets of prefixes [%s]: %w", peer.IPBlock.Except, err)
	}
	v4Prefixes, v6Prefixes, err := getPrefixesAsSetInterval([]string{peer.IPBlock.CIDR})
	if err != nil {
		return fmt.Errorf("failed to get prefix sets of prefixes [%s]: %w", peer.IPBlock.CIDR, err)
	}

	if err := n.applyPrefixes(chain, policyName, peer, peerIndex, v4Prefixes, v4ExceptPrefixes, false); err != nil {
		return fmt.Errorf("failed to apply %s prefixes for policy %q: %w", protoIPv4, policyName, err)
	}

	if err := n.applyPrefixes(chain, policyName, peer, peerIndex, v6Prefixes, v6ExceptPrefixes, true); err != nil {
		return fmt.Errorf("failed to apply %s prefixes for policy %q: %w", protoIPv6, policyName, err)
	}

	return nil
}

func (n *nftState) applyPolicyPeersRulesSelector(s *Server, chain *nftables.Chain, policyName string, peer multiv1beta1.MultiNetworkPolicyPeer,
	podInfo *controllers.PodInfo, policyNetworks []string, peerIndex int) error {
	klog.V(8).Infof("applying peers rules with pod selector: %s", peer.PodSelector.String())
	podSelector, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
	if err != nil {
		return fmt.Errorf("pod selector: %w", err)
	}

	pods, err := s.podLister.Pods(metav1.NamespaceAll).List(podSelector)
	if err != nil {
		return fmt.Errorf("pod list failed: %w", err)
	}

	var nsSelector labels.Selector
	if peer.NamespaceSelector != nil {
		klog.V(8).Infof("applying peers rules with namespace selector: %s", peer.NamespaceSelector.String())
		var err error
		nsSelector, err = metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
		if err != nil {
			return fmt.Errorf("namespace selector: %w", err)
		}
	}
	s.namespaceMap.Update(s.nsChanges)

	var podIntfIPs []string
	podIntfsIPsMap := make(map[string]any)
	for _, sPod := range pods {
		nsLabels, err := s.namespaceMap.GetNamespaceInfo(sPod.Namespace)
		if err != nil {
			klog.Errorf("cannot get namespace info: %v %v", sPod.Name, err)
			continue
		}
		if nsSelector != nil && !nsSelector.Matches(labels.Set(nsLabels.Labels)) {
			continue
		}
		s.podMap.Update(s.podChanges)
		sPodinfo, err := s.podMap.GetPodInfo(sPod)
		if err != nil {
			klog.Errorf("cannot get %s/%s podInfo: %v", sPod.Namespace, sPod.Name, err)
			continue
		}

		for _, podIntf := range podInfo.Interfaces {
			if !podIntf.CheckPolicyNetwork(policyNetworks) {
				continue
			}
			for _, sPodIntf := range sPodinfo.Interfaces {
				if !sPodIntf.CheckPolicyNetwork(policyNetworks) {
					continue
				}

				for _, ip := range podIntf.IPs {
					podIntfsIPsMap[ip] = nil
				}

				for _, ip := range sPodIntf.IPs {
					podIntfsIPsMap[ip] = nil
				}

				for ip := range podIntfsIPsMap {
					podIntfIPs = append(podIntfIPs, ip)
				}
			}
		}
	}

	if err := n.addIPRules(podIntfIPs, chain, policyName, peer, peerIndex); err != nil {
		klog.Errorf("failed to add IP rules %v", err)
	}

	return nil
}

func (n *nftState) addIPRule(addrs []string, chain *nftables.Chain, policyName string, peer multiv1beta1.MultiNetworkPolicyPeer,
	peerIndex int) error {

	if len(addrs) < 1 {
		return nil
	}

	offset := IPv4OffSet
	payloadLen := uint32(net.IPv4len)
	keyType := nftables.TypeIPAddr
	protocol := protoIPv4
	if net.ParseIP(addrs[0]).To4() == nil {
		offset = IPv6OffSet
		payloadLen = uint32(net.IPv6len)
		keyType = nftables.TypeIP6Addr
		protocol = protoIPv6
	}

	if !isIngressChain(chain) {
		offset += payloadLen
	}

	selectorHash, err := hash(peer.PodSelector.String())
	if err != nil {
		return fmt.Errorf("failed to hash pod selector %q: %w", peer.PodSelector.String(), err)
	}

	ipSet := &nftables.Set{
		Name:    fmt.Sprintf("%s_%s_%d_%s_%s", policyName, getAddressSuffix(chain), peerIndex, protocol, selectorHash),
		Table:   chain.Table,
		KeyType: keyType,
	}

	ipSetElements := []nftables.SetElement{}
	for _, addr := range addrs {
		parsedIP := net.ParseIP(addr).To4()
		if parsedIP == nil {
			parsedIP = net.ParseIP(addr).To16()
		}
		ipSetElements = append(ipSetElements, nftables.SetElement{
			Key: []byte(parsedIP),
		})
	}

	if err := n.updateSet(ipSet, ipSetElements); err != nil {
		return err
	}

	return n.updateRule(&nftables.Rule{
		Table:    chain.Table,
		Chain:    chain,
		UserData: userDataComment(fmt.Sprintf("policy:%s selector-for:%s %s", policyName, selectorHash, protocol)),
		Exprs: []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       offset,
				Len:          payloadLen,
			},
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        ipSet.Name,
				SetID:          ipSet.ID,
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	}, n.nft.AddRule)
}

func (n *nftState) addIPRules(addrs []string, chain *nftables.Chain, policyName string, peer multiv1beta1.MultiNetworkPolicyPeer,
	peerIndex int) error {

	var v4Addrs, v6Addrs []string
	for _, addr := range addrs {
		ipAddr, err := netip.ParseAddr(addr)
		if err != nil {
			return fmt.Errorf("failed to parse address %q", addr)
		}
		if ipAddr.Is6() {
			v6Addrs = append(v6Addrs, addr)
		} else {
			v4Addrs = append(v4Addrs, addr)
		}
	}

	if err := n.addIPRule(v4Addrs, chain, policyName, peer, peerIndex); err != nil {
		return fmt.Errorf("failed to add IPv4 rules: %w", err)
	}

	if err := n.addIPRule(v6Addrs, chain, policyName, peer, peerIndex); err != nil {
		return fmt.Errorf("failed to add IPv6 rules: %w", err)
	}

	return nil
}

func (n *nftState) applyPolicyPeersRules(s *Server, chain *nftables.Chain, policyName string, peers []multiv1beta1.MultiNetworkPolicyPeer,
	podInfo *controllers.PodInfo, policyNetworks []string, peerIndex int) error {
	peersName := fmt.Sprintf("%s-%s-%d", chain.Name, peersChainSuffix, peerIndex)

	peersChain, err := n.addChain(&nftables.Chain{
		Name:  peersName,
		Table: chain.Table,
	})
	if err != nil {
		return fmt.Errorf("failed to create peers chain: %w", err)
	}

	if err := n.updateRule(&nftables.Rule{
		Table:    chain.Table,
		Chain:    chain,
		UserData: userDataComment(fmt.Sprintf("peers policy:%s, jump:%s", policyName, peersName)),
		Exprs: []expr.Any{
			&expr.Counter{},
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: peersChain.Name,
			},
		}}, n.nft.AddRule); err != nil {
		return err
	}
	// sync podmap before calculating rules
	s.podMap.Update(s.podChanges)
	for index, peer := range peers {
		if peer.IPBlock != nil {
			if err := n.applyPolicyPeersRulesIPBlock(peersChain, policyName, peer, index); err != nil {
				klog.Errorf("failed to apply IPBlock rules: %v", err)
			}
			continue
		}
		if peer.PodSelector != nil || peer.NamespaceSelector != nil {
			if err := n.applyPolicyPeersRulesSelector(s, peersChain, policyName, peer, podInfo, policyNetworks, index); err != nil {
				klog.Errorf("failed to apply selector rules: %v", err)
			}
			continue
		}
		klog.Errorf("unknown rule: %+v", peer)
	}

	if len(peers) == 0 {
		// if no ports are specified, accept all ports
		if err := n.updateRule(&nftables.Rule{
			Table:    chain.Table,
			Chain:    peersChain,
			UserData: userDataComment(fmt.Sprintf("policy:%s no peers skipped accept all", policyName)),
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
			}}, n.nft.AddRule); err != nil {
			return err
		}

	}
	_ = peersChain
	return nil
}

func (n *nftState) findRule(rule *nftables.Rule) (*nftables.Rule, error) {
	rules, err := n.nft.GetRules(rule.Table, rule.Chain)
	if err != nil {
		return nil, fmt.Errorf("failed to list rules in table %q, chain %q: %w", rule.Table.Name, rule.Chain.Name, err)
	}

	var existing *nftables.Rule
	cnt := 0
	for _, r := range rules {
		if ruleEqual(rule, r) {
			existing = r
			cnt++
		}
	}

	if cnt == 0 {
		return nil, nil
	}

	if cnt > 1 {
		comment, ok := userdata.GetString(rule.UserData, userdata.TypeComment)
		if !ok {
			klog.Warningf("failed to get comment for rule %d in table %q, chain %q", rule.Handle, rule.Table.Name, rule.Chain.Name)
		} else {
			klog.Warningf("too many rules (%d) for rule %q in table %q, chain %q", cnt, comment, rule.Table.Name, rule.Chain.Name)
		}
	}

	return existing, nil
}

func (n *nftState) getInetSet(chain *nftables.Chain, portsName, suffix string) *nftables.Set {
	return &nftables.Set{
		Table:    chain.Table,
		Name:     fmt.Sprintf("%s_%s", getSetName(portsName), suffix),
		Constant: true,
		Counter:  true,
		KeyType:  nftables.TypeInetService,
		Interval: true,
	}
}

func (n *nftState) applyProtoPortsRules(chain *nftables.Chain, policyName string, set *nftables.Set, unixProto []byte) error {
	return n.updateRule(&nftables.Rule{
		Table:    chain.Table,
		Chain:    chain,
		UserData: userDataComment(fmt.Sprintf("policy:%s set:%s", policyName, set.Name)),
		Exprs: []expr.Any{
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
			&expr.Counter{},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	}, n.nft.AddRule)
}

func (n *nftState) applyPolicyPortsRules(chain *nftables.Chain, policyName string, ports []multiv1beta1.MultiNetworkPolicyPort, portIndex int) error {
	portsName := fmt.Sprintf("%s-%s-%d", chain.Name, portsChainSuffix, portIndex)
	// create ports chain
	portChain, err := n.addChain(&nftables.Chain{
		Name:  portsName,
		Table: chain.Table,
	})
	if err != nil {
		return fmt.Errorf("failed to create ports chain: %w", err)
	}

	klog.V(8).Infof("applying port rules for policy %q in the chain %q", policyName, portChain.Name)
	if err := n.updateRule(&nftables.Rule{
		Table:    chain.Table,
		Chain:    chain,
		UserData: userDataComment(fmt.Sprintf("port rules policy:%s, name:%s", policyName, portsName)),
		Exprs: []expr.Any{
			&expr.Counter{},
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: portChain.Name,
			},
		}}, n.nft.AddRule); err != nil {
		return err
	}

	portsTCP := []nftables.SetElement{}
	portsUDP := []nftables.SetElement{}
	portsSCTP := []nftables.SetElement{}
	// validate ports and protocols
	for _, port := range ports {
		var portElements []nftables.SetElement

		if port.Port == nil && port.Protocol != nil {
			port.Port = &intstr.IntOrString{Type: intstr.Int, IntVal: 1}
			port.EndPort = new(int32)
			*port.EndPort = math.MaxUint16
		}

		// validate port range
		if port.Port != nil {
			if port.Port.IntValue() < 1 || port.Port.IntValue() > math.MaxUint16 {
				return fmt.Errorf("port %d out of range, must be between 1 and %d", port.Port.IntValue(), math.MaxUint16)
			}
			portElements = append(portElements, nftables.SetElement{
				Key: binaryutil.BigEndian.PutUint16(uint16(port.Port.IntValue())),
			})
			if port.EndPort != nil && *port.EndPort > int32(port.Port.IntValue()) {
				if *port.EndPort < 1 || *port.EndPort > 65535 {
					return fmt.Errorf("port %d out of range, must be between 1 and %d", port.Port.IntValue(), math.MaxUint16)
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

		if port.Protocol != nil {
			switch *port.Protocol {
			case v1.ProtocolUDP:
				portsUDP = append(portsUDP, portElements...)
			case v1.ProtocolSCTP:
				portsSCTP = append(portsSCTP, portElements...)
			default:
				portsTCP = append(portsTCP, portElements...)
			}
		} else {
			portsTCP = append(portsTCP, portElements...)
		}

	}
	if len(portsTCP) > 0 {
		suffix, unixFlag := getProtocolInfo(v1.ProtocolTCP)
		tcpSet := n.getInetSet(chain, portsName, suffix)
		if err := n.updateSet(tcpSet, portsTCP); err != nil {
			return err
		}
		if err := n.applyProtoPortsRules(portChain, policyName, tcpSet, unixFlag); err != nil {
			return fmt.Errorf("failed to apply tcp port rules for set %q: %w", tcpSet.Name, err)
		}
	}
	if len(portsUDP) > 0 {
		suffix, unixFlag := getProtocolInfo(v1.ProtocolUDP)
		udpSet := n.getInetSet(chain, portsName, suffix)
		if err := n.updateSet(udpSet, portsUDP); err != nil {
			return err
		}
		if err := n.applyProtoPortsRules(portChain, policyName, udpSet, unixFlag); err != nil {
			return fmt.Errorf("failed to apply udp port rules for set %q: %w", udpSet.Name, err)
		}
	}
	if len(portsSCTP) > 0 {
		suffix, unixFlag := getProtocolInfo(v1.ProtocolSCTP)
		sctpSet := n.getInetSet(chain, portsName, suffix)
		if err := n.updateSet(sctpSet, portsSCTP); err != nil {
			return err
		}
		if err := n.applyProtoPortsRules(portChain, policyName, sctpSet, unixFlag); err != nil {
			return fmt.Errorf("failed to apply sctp port rules for set %q: %w", sctpSet.Name, err)
		}
	}

	if len(ports) == 0 || (len(portsTCP) == 0 && len(portsUDP) == 0 && len(portsSCTP) == 0) {
		// if no ports are specified, accept all ports
		if err := n.updateRule(&nftables.Rule{
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
			}}, n.nft.AddRule); err != nil {
			return err
		}
	}
	return nil
}

// s *Server, podInfo *controllers.PodInfo, pIndex, iIndex int, from []multiv1beta1.MultiNetworkPolicyPeer, policyNetworks []string
func (n *nftState) applyPodRules(s *Server, chain *nftables.Chain, podInfo *controllers.PodInfo, idx int, policy *multiv1beta1.MultiNetworkPolicy, policyNetworks []string) error {
	// add chain inet filter <chainName>-<idx>
	policyChain, err := n.addChain(&nftables.Chain{
		Name:  fmt.Sprintf("%s-%d", chain.Name, idx),
		Table: n.filter,
	})
	if err != nil {
		return fmt.Errorf("failed to create policy chain: %w", err)
	}
	for _, podIntf := range podInfo.Interfaces {
		if podIntf.CheckPolicyNetwork(policyNetworks) {
			if err := n.applyPodInterfaceRules(chain, policyChain, policy, podIntf); err != nil {
				return fmt.Errorf("failed to apply pod interface rules for policy %q: %v", policyNamespacedName(policy), err)
			}
		}
	}
	if isIngressChain(chain) {
		for index, ingress := range policy.Spec.Ingress {
			if err := n.applyMarkReset(policyChain, policyNamespacedName(policy), index); err != nil {
				return fmt.Errorf("failed to apply ingress mark reset for policy %q: %w", policyNamespacedName(policy), err)
			}
			if err := n.applyPolicyPortsRules(policyChain, policyNamespacedName(policy), ingress.Ports, index); err != nil {
				return fmt.Errorf("failed to apply ingress ports for policy %q: %w", policyNamespacedName(policy), err)
			}
			if err := n.applyPolicyPeersRules(s, policyChain, policyNamespacedName(policy), ingress.From, podInfo, policyNetworks, index); err != nil {
				return fmt.Errorf("failed to apply ingress address rules for policy %q: %w", policyNamespacedName(policy), err)
			}
			if err := n.applyMarkCheck(policyChain, policyNamespacedName(policy), index); err != nil {
				return fmt.Errorf("failed to apply egress mark check for policy %q: %w", policyNamespacedName(policy), err)
			}
		}
	} else {
		for index, egress := range policy.Spec.Egress {
			if err := n.applyMarkReset(policyChain, policy.Name, index); err != nil {
				return fmt.Errorf("failed to apply egress mark reset for policy %q: %w", policyNamespacedName(policy), err)
			}
			if err := n.applyPolicyPortsRules(policyChain, policyNamespacedName(policy), egress.Ports, index); err != nil {
				return fmt.Errorf("failed to apply egress ports for policy %q: %w", policyNamespacedName(policy), err)
			}
			if err := n.applyPolicyPeersRules(s, policyChain, policyNamespacedName(policy), egress.To, podInfo, policyNetworks, index); err != nil {
				return fmt.Errorf("failed to apply egress address rules for policy %q: %w", policyNamespacedName(policy), err)
			}
			if err := n.applyMarkCheck(policyChain, policyNamespacedName(policy), index); err != nil {
				return fmt.Errorf("failed to apply egress mark check for policy %q: %w", policyNamespacedName(policy), err)
			}
		}
	}
	return nil
}

func (n *nftState) addChain(chain *nftables.Chain) (*nftables.Chain, error) {
	if len(chain.Name) > 31 {
		var err error
		chain.Name, err = hash(chain.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to hash chain name %q: %w", chain.Name, err)
		}

	}
	existingChain, err := n.nft.ListChain(chain.Table, chain.Name)
	var c *nftables.Chain
	if (err != nil && errors.Is(err, os.ErrNotExist)) || existingChain == nil {
		klog.V(8).Infof("adding chain %q", chain.Name)
		c = n.nft.AddChain(chain)
	} else if err != nil {
		return nil, fmt.Errorf("failed to configure chain %q in table %q: %w", chain.Name, chain.Table.Name, err)
	} else {
		c = existingChain
	}

	n.chains[chainID(c)] = c
	return c, nil
}

func chainID(c *nftables.Chain) string {
	return fmt.Sprintf("%s-%s", c.Table.Name, c.Name)
}

func (n *nftState) cleanup() error {
	defer func() {
		n.rules = make(map[string]*nftables.Rule)
		n.sets = make(map[string]*nftables.Set)
		n.chains = make(map[string]*nftables.Chain)
	}()

	if err := n.cleanupRules(n.filter); err != nil {
		return fmt.Errorf("failed to cleanup %q table: %w", n.filter.Name, err)
	}

	if err := n.cleanupRules(n.nat); err != nil {
		return fmt.Errorf("failed to cleanup %q table: %w", n.nat.Name, err)
	}

	if err := n.cleanupChains(); err != nil {
		return fmt.Errorf("failed to cleanup chains: %w", err)
	}

	return nil
}

func (n *nftState) cleanupRules(table *nftables.Table) error {
	chains, err := n.nft.ListChainsOfTableFamily(table.Family)
	if err != nil {
		return fmt.Errorf("failed to list chains: %w", err)
	}

	performFlush := false

	for _, chain := range chains {
		if chain.Table.Name == table.Name {
			rules, err := n.nft.GetRules(table, chain)
			if err != nil {
				return fmt.Errorf("failed to list rules for table %q, chain %q: %w", table.Name, chain.Name, err)
			}
			for _, rule := range rules {
				key, err := hash(rule)
				if err != nil {
					klog.Warning("failed to get key for rule: %w", err)
				}
				if _, exists := n.rules[key]; !exists {
					comment, _ := userdata.GetString(rule.UserData, userdata.TypeComment)
					klog.V(8).Infof("deleting rule %q in chain %q", comment, rule.Chain.Name)
					err = n.nft.DelRule(rule)
					if err != nil {
						klog.Errorf("failed to delete rule %q in chain %q: %v", comment, rule.Chain.Name, err)
						continue
					}
					performFlush = true
				}
			}
		}
	}

	sets, _ := n.nft.GetSets(table)
	for _, set := range sets {
		if _, exists := n.sets[fmt.Sprintf("%s-%s", set.Table.Name, set.Name)]; !exists && !set.Anonymous {
			klog.V(8).Infof("deleting set %q in table %q", set.Name, set.Table.Name)
			n.nft.DelSet(set)
			performFlush = true
		}
	}

	if performFlush {
		if err := n.nft.Flush(); err != nil {
			return fmt.Errorf("failed to flush rules/sets cleanup: %w", err)
		}
	}

	return nil
}

func (n *nftState) cleanupChains() error {
	chains, err := n.nft.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return fmt.Errorf("failed to list chains: %w", err)
	}

	performFlush := false
	for _, chain := range chains {
		rules, err := n.nft.GetRules(chain.Table, chain)
		if err != nil {
			return fmt.Errorf("failed to get rules for table %q, chain %q: %w", chain.Table.Name, chain.Name, err)
		}
		if _, used := n.chains[chainID(chain)]; !used && len(rules) < 1 {
			klog.V(8).Infof("deleting chain %q in table %q", chain.Name, chain.Table.Name)
			n.nft.DelChain(chain)
			performFlush = true
		}
	}

	if performFlush {
		if err := n.nft.Flush(); err != nil {
			return fmt.Errorf("failed to flush chains cleanup: %w", err)
		}
	}

	return nil
}
