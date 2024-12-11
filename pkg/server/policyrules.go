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
	"os"
	"strings"

	"github.com/k8snetworkplumbingwg/multi-networkpolicy-iptables/pkg/controllers"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
)

// PolicyNetworkAnnotation is annotation for multiNetworkPolicy,
// to specify which networks(i.e. net-attach-def) are the targets
// of the policy
const PolicyNetworkAnnotation = "k8s.v1.cni.cncf.io/policy-for"

/*
// GetChainLines parses a table's iptables-save data to find chains in the table.
// It returns a map of iptables.Chain to []byte where the []byte is the chain line
// from save (with counters etc.).
// Note that to avoid allocations memory is SHARED with save.
func GetChainLines(table Table, save []byte) map[Chain][]byte {
*/
type iptableBuffer struct {
	currentFilter map[utiliptables.Chain]struct{}
	currentChain  map[utiliptables.Chain]bool
	activeChain   map[utiliptables.Chain]bool
	policyCommon  *bytes.Buffer
	policyIndex   *bytes.Buffer
	ingressPorts  *bytes.Buffer
	ingressFrom   *bytes.Buffer
	egressPorts   *bytes.Buffer
	egressTo      *bytes.Buffer
	filterChains  *bytes.Buffer
	filterRules   *bytes.Buffer
	isIPv6        bool
}

func newIptableBuffer() *iptableBuffer {
	buf := &iptableBuffer{
		currentFilter: make(map[utiliptables.Chain]struct{}),
		policyCommon:  bytes.NewBuffer(nil),
		policyIndex:   bytes.NewBuffer(nil),
		ingressPorts:  bytes.NewBuffer(nil),
		ingressFrom:   bytes.NewBuffer(nil),
		egressPorts:   bytes.NewBuffer(nil),
		egressTo:      bytes.NewBuffer(nil),
		filterChains:  bytes.NewBuffer(nil),
		filterRules:   bytes.NewBuffer(nil),
		currentChain:  map[utiliptables.Chain]bool{},
		activeChain:   map[utiliptables.Chain]bool{},
	}
	return buf
}

func (ipt *iptableBuffer) Init(iptables utiliptables.Interface) {
	ipt.isIPv6 = iptables.IsIPv6()

	tmpbuf := bytes.NewBuffer(nil)
	tmpbuf.Reset()
	err := iptables.SaveInto(utiliptables.TableFilter, tmpbuf)
	if err != nil {
		klog.Errorf("failed to get iptable filter: %v", err)
		return
	}
	//ipt.currentFilter = utiliptables.GetChainLines(utiliptables.TableFilter, tmpbuf.Bytes())
	ipt.currentFilter = utiliptables.GetChainsFromTable(tmpbuf.Bytes())
	for k := range ipt.currentFilter {
		if strings.HasPrefix(string(k), "MULTI-") {
			ipt.currentChain[k] = true
		}
	}

	ipt.filterRules.Reset()
	ipt.filterChains.Reset()
	writeLine(ipt.filterChains, "*filter")

	// Make sure we keep stats for the top-level chains, if they existed
	// (which most should have because we created them above).
	for _, chainName := range []utiliptables.Chain{ingressChain, ingressCommonChain, egressChain, egressCommonChain} {
		ipt.activeChain[chainName] = true
		if _, ok := ipt.currentFilter[chainName]; ok {
			writeBytesLine(ipt.filterChains, fmt.Sprintf(":%s - [0:0]", chainName))
		} else {
			writeLine(ipt.filterChains, utiliptables.MakeChainLine(chainName))
		}
	}
}

// Reset clears iptableBuffer
func (ipt *iptableBuffer) Reset() {
	ipt.policyCommon.Reset()
	ipt.policyIndex.Reset()
	ipt.ingressPorts.Reset()
	ipt.ingressFrom.Reset()
	ipt.egressPorts.Reset()
	ipt.egressTo.Reset()
}

func (ipt *iptableBuffer) FinalizeRules() {
	for k := range ipt.activeChain {
		delete(ipt.currentChain, k)
	}
	for chainName := range ipt.currentChain {
		if _, ok := ipt.currentFilter[chainName]; ok {
			writeBytesLine(ipt.filterChains, fmt.Sprintf(":%s - [0:0]", chainName))
		}
		writeLine(ipt.policyIndex, "-X", string(chainName))
	}
	ipt.filterRules.Write(ipt.filterChains.Bytes())
	ipt.filterRules.Write(ipt.policyCommon.Bytes())
	ipt.filterRules.Write(ipt.policyIndex.Bytes())
	ipt.filterRules.Write(ipt.ingressPorts.Bytes())
	ipt.filterRules.Write(ipt.ingressFrom.Bytes())
	ipt.filterRules.Write(ipt.egressPorts.Bytes())
	ipt.filterRules.Write(ipt.egressTo.Bytes())
	writeLine(ipt.filterRules, "COMMIT")
}

func (ipt *iptableBuffer) SaveRules(path string) error {
	file, err := os.Create(path)
	defer file.Close()
	if err != nil {
		return err
	}
	//_, err = ipt.filterRules.WriteTo(file)
	fmt.Fprintf(file, "%s", ipt.filterRules.String())
	return err
}

func (ipt *iptableBuffer) SyncRules(iptables utiliptables.Interface) error {
	if klog.V(4) {
		klog.Infof("SyncRules\n%s\n", ipt.filterRules.String())
	}
	return iptables.RestoreAll(ipt.filterRules.Bytes(), utiliptables.NoFlushTables, utiliptables.RestoreCounters)
}

func (ipt *iptableBuffer) IsUsed() bool {
	return (len(ipt.activeChain) != 0)
}

func (ipt *iptableBuffer) CreateFilterChain(chainName string) {
	ipt.activeChain[utiliptables.Chain(chainName)] = true
	// Create chain if not exists
	if _, ok := ipt.currentFilter[utiliptables.Chain(chainName)]; ok {
		writeBytesLine(ipt.filterChains, fmt.Sprintf(":%s - [0:0]", chainName))
	} else {
		writeLine(ipt.filterChains, utiliptables.MakeChainLine(utiliptables.Chain(chainName)))
	}
}

func (ipt *iptableBuffer) renderIngressCommon(s *Server) {
	// Add jump from MULTI-INGRESS
	writeLine(ipt.policyIndex, "-A", ingressChain, "-j", ingressCommonChain)

	if ipt.isIPv6 {
		if s.Options.acceptICMPv6 {
			// Allow incoming ICMPv6 traffic
			writeLine(ipt.policyCommon, "-A", ingressCommonChain, "-p icmpv6 -j ACCEPT")
		}

		// add source prefix whitelist
		if len(s.Options.allowIPv6SrcPrefix) != 0 {
			for _, addr := range s.Options.allowIPv6SrcPrefix {
				writeLine(ipt.policyCommon, "-A", ingressCommonChain,
					"-s", strings.TrimSpace(addr), "-j ACCEPT")
			}
		}

		// add destination prefix whitelist
		if len(s.Options.allowIPv6DstPrefix) != 0 {
			for _, addr := range s.Options.allowIPv6DstPrefix {
				writeLine(ipt.policyCommon, "-A", ingressCommonChain,
					"-d", strings.TrimSpace(addr), "-j ACCEPT")
			}
		}

		// add custom rules
		if s.Options.customIPv6IngressRule != nil {
			for _, rule := range s.Options.customIPv6IngressRule {
				writeLine(ipt.policyCommon, "-A", ingressCommonChain, rule)
			}
		}
	} else { // IPv4
		if s.Options.acceptICMP {
			// Allow incoming ICMPv6 traffic to let Neighbor Discovery Protocol work (RFC4861)
			writeLine(ipt.policyCommon, "-A", ingressCommonChain, "-p icmp -j ACCEPT")
		}

		// add custom rules
		if s.Options.customIPv4IngressRule != nil {
			for _, rule := range s.Options.customIPv4IngressRule {
				writeLine(ipt.policyCommon, "-A", ingressCommonChain, rule)
			}
		}
	}
	writeLine(ipt.policyCommon, "-A", ingressCommonChain, "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
}

func (ipt *iptableBuffer) renderIngress(s *Server, podInfo *controllers.PodInfo, idx int, policy *multiv1beta1.MultiNetworkPolicy, policyNetworks []string) {
	chainName := fmt.Sprintf("MULTI-%d-INGRESS", idx)
	ipt.CreateFilterChain(chainName)

	for _, podIntf := range podInfo.Interfaces {
		if podIntf.CheckPolicyNetwork(policyNetworks) {
			comment := fmt.Sprintf("\"policy:%s net-attach-def:%s\"", policy.Name, podIntf.NetattachName)
			writeLine(ipt.policyIndex, "-A", ingressChain,
				"-m", "comment", "--comment", comment, "-i", podIntf.InterfaceName,
				"-j", chainName)
			writeLine(ipt.policyIndex, "-A", ingressChain,
				"-m", "mark", "--mark", "0x30000/0x30000", "-j", "RETURN")
		}
	}

	for n, ingress := range policy.Spec.Ingress {
		writeLine(ipt.policyIndex, "-A", chainName,
			"-j", "MARK", "--set-xmark 0x0/0x30000")
		ipt.renderIngressPorts(s, podInfo, idx, n, ingress.Ports, policyNetworks)
		ipt.renderIngressFrom(s, podInfo, idx, n, ingress.From, policyNetworks)
		writeLine(ipt.policyIndex, "-A", chainName, "-m", "mark", "--mark", "0x30000/0x30000", "-j", "RETURN")
	}
}

func (ipt *iptableBuffer) renderIngressPorts(_ *Server, podInfo *controllers.PodInfo, pIndex, iIndex int, ports []multiv1beta1.MultiNetworkPolicyPort, policyNetworks []string) {
	chainName := fmt.Sprintf("MULTI-%d-INGRESS-%d-PORTS", pIndex, iIndex)
	ipt.CreateFilterChain(chainName)

	// Add jump from MULTI-INGRESS
	writeLine(ipt.policyIndex, "-A", fmt.Sprintf("MULTI-%d-INGRESS", pIndex), "-j", chainName)

	validPorts := 0
	for _, port := range ports {
		proto := renderProtocol(port.Protocol)

		for _, podIntf := range podInfo.Interfaces {
			if !podIntf.CheckPolicyNetwork(policyNetworks) {
				continue
			}
			writeLine(ipt.ingressPorts, "-A", chainName,
				"-i", podIntf.InterfaceName,
				"-m", proto, "-p", proto, "--dport", port.Port.String(),
				"-j", "MARK", "--set-xmark", "0x10000/0x10000")
			validPorts++
		}
	}

	// Add skip rule if no ports
	if len(ports) == 0 || validPorts == 0 {
		writeLine(ipt.ingressPorts, "-A", chainName,
			"-m", "comment", "--comment", "\"no ingress ports, skipped\"",
			"-j", "MARK", "--set-xmark", "0x10000/0x10000")
	}
	return
}

func (ipt *iptableBuffer) renderIngressFrom(s *Server, podInfo *controllers.PodInfo, pIndex, iIndex int, from []multiv1beta1.MultiNetworkPolicyPeer, policyNetworks []string) {
	chainName := fmt.Sprintf("MULTI-%d-INGRESS-%d-FROM", pIndex, iIndex)
	ipt.CreateFilterChain(chainName)

	// Add jump from MULTI-INGRESS
	writeLine(ipt.policyIndex, "-A", fmt.Sprintf("MULTI-%d-INGRESS", pIndex), "-j", chainName)

	s.podMap.Update(s.podChanges)
	for _, peer := range from {
		if peer.PodSelector != nil || peer.NamespaceSelector != nil {
			podSelectorMap, err := metav1.LabelSelectorAsMap(peer.PodSelector)
			if err != nil {
				klog.Errorf("pod selector: %v", err)
				continue
			}
			podLabelSelector := labels.Set(podSelectorMap).AsSelectorPreValidated()
			pods, err := s.podLister.Pods(metav1.NamespaceAll).List(podLabelSelector)
			if err != nil {
				klog.Errorf("pod list failed:%v", err)
				continue
			}

			var nsSelector labels.Selector
			if peer.NamespaceSelector != nil {
				nsSelectorMap, err := metav1.LabelSelectorAsMap(peer.NamespaceSelector)
				if err != nil {
					klog.Errorf("namespace selector: %v", err)
					continue
				}
				nsSelector = labels.Set(nsSelectorMap).AsSelectorPreValidated()
			}
			s.namespaceMap.Update(s.nsChanges)

			for _, sPod := range pods {
				nsLabels, err := s.namespaceMap.GetNamespaceInfo(sPod.Namespace)
				if err != nil {
					klog.Errorf("cannot get namespace info: %v %v", sPod.ObjectMeta.Name, err)
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
						for _, ip := range sPodIntf.IPs {
							if ipt.isIPFamilyCompatible(ip) {
								writeLine(ipt.ingressFrom, "-A", chainName,
									"-i", podIntf.InterfaceName, "-s", ip,
									"-j", "MARK", "--set-xmark", "0x20000/0x20000")
							}
						}
						// ingress should accept reverse path
						for _, ip := range podIntf.IPs {
							if ipt.isIPFamilyCompatible(ip) {
								writeLine(ipt.ingressFrom, "-A", chainName,
									"-i", podIntf.InterfaceName, "-s", ip,
									"-j", "MARK", "--set-xmark", "0x20000/0x20000")
							}
						}
					}
				}
			}
		} else if peer.IPBlock != nil {
			for _, except := range peer.IPBlock.Except {
				for _, podIntf := range podInfo.Interfaces {
					if !podIntf.CheckPolicyNetwork(policyNetworks) {
						continue
					}
					if ipt.isIPFamilyCompatible(except) {
						writeLine(ipt.ingressFrom, "-A", chainName,
							"-i", podIntf.InterfaceName, "-s", except, "-j", "DROP")
					}
				}
			}
			for _, podIntf := range podInfo.Interfaces {
				if !podIntf.CheckPolicyNetwork(policyNetworks) {
					continue
				}
				if ipt.isIPFamilyCompatible(peer.IPBlock.CIDR) {
					writeLine(ipt.ingressFrom, "-A", chainName,
						"-i", podIntf.InterfaceName, "-s", peer.IPBlock.CIDR,
						"-j", "MARK", "--set-xmark", "0x20000/0x20000")
				}
			}
			for _, podIntf := range podInfo.Interfaces {
				if !podIntf.CheckPolicyNetwork(policyNetworks) {
					continue
				}
				for _, ip := range podIntf.IPs {
					if ipt.isIPFamilyCompatible(ip) {
						writeLine(ipt.ingressFrom, "-A", chainName,
							"-i", podIntf.InterfaceName, "-s", ip,
							"-j", "MARK", "--set-xmark", "0x20000/0x20000")
					}
				}
			}
		} else {
			klog.Errorf("unknown rule")
		}
	}

	// Add skip rule if no froms
	if len(from) == 0 {
		writeLine(ipt.ingressFrom, "-A", chainName,
			"-m", "comment", "--comment", "\"no ingress from, skipped\"",
			"-j", "MARK", "--set-xmark", "0x20000/0x20000")
	}
	return
}

func (ipt *iptableBuffer) renderEgressCommon(s *Server) {
	// Add jump from MULTI-EGRESS
	writeLine(ipt.policyIndex, "-A", egressChain, "-j", egressCommonChain)
	if ipt.isIPv6 {
		if s.Options.acceptICMPv6 {
			// Allow outgoing ICMPv6 traffic
			writeLine(ipt.policyCommon, "-A", egressCommonChain, "-p icmpv6 -j ACCEPT")
		}

		// add source prefix whitelist
		if s.Options.allowIPv6SrcPrefix != nil {
			for _, addr := range s.Options.allowIPv6SrcPrefix {
				writeLine(ipt.policyCommon, "-A", egressCommonChain,
					"-s", strings.TrimSpace(addr), "-j ACCEPT")
			}
		}

		// add destination prefix whitelist
		if s.Options.allowIPv6DstPrefix != nil {
			for _, addr := range s.Options.allowIPv6DstPrefix {
				writeLine(ipt.policyCommon, "-A", egressCommonChain,
					"-d", strings.TrimSpace(addr), "-j ACCEPT")
			}
		}

		// add custom rules
		if s.Options.customIPv6EgressRule != nil {
			for _, rule := range s.Options.customIPv6EgressRule {
				writeLine(ipt.policyCommon, "-A", egressCommonChain, rule)
			}
		}
	} else { // IPv4
		if s.Options.acceptICMP {
			// Allow outgoing ICMP traffic
			writeLine(ipt.policyCommon, "-A", egressCommonChain, "-p icmp -j ACCEPT")
		}

		// add custom rules
		if s.Options.customIPv4EgressRule != nil {
			for _, rule := range s.Options.customIPv4EgressRule {
				writeLine(ipt.policyCommon, "-A", egressCommonChain, rule)
			}
		}
	}

	writeLine(ipt.policyCommon, "-A", egressCommonChain, "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
}

func (ipt *iptableBuffer) renderEgress(s *Server, podInfo *controllers.PodInfo, idx int, policy *multiv1beta1.MultiNetworkPolicy, policyNetworks []string) {
	chainName := fmt.Sprintf("MULTI-%d-EGRESS", idx)
	ipt.CreateFilterChain(chainName)

	for _, podIntf := range podInfo.Interfaces {
		if podIntf.CheckPolicyNetwork(policyNetworks) {
			comment := fmt.Sprintf("\"policy:%s net-attach-def:%s\"", policy.Name, podIntf.NetattachName)
			writeLine(ipt.policyIndex, "-A", egressChain,
				"-m", "comment", "--comment", comment, "-o", podIntf.InterfaceName,
				"-j", chainName)
			writeLine(ipt.policyIndex, "-A", egressChain,
				"-m", "mark", "--mark", "0x30000/0x30000", "-j", "RETURN")
		}
	}

	for n, egress := range policy.Spec.Egress {
		writeLine(ipt.policyIndex, "-A", chainName, "-j", "MARK", "--set-xmark 0x0/0x30000")
		ipt.renderEgressPorts(s, podInfo, idx, n, egress.Ports, policyNetworks)
		ipt.renderEgressTo(s, podInfo, idx, n, egress.To, policyNetworks)
		writeLine(ipt.policyIndex, "-A", chainName, "-m", "mark", "--mark", "0x30000/0x30000", "-j", "RETURN")
	}
}

func (ipt *iptableBuffer) renderEgressPorts(_ *Server, podInfo *controllers.PodInfo, pIndex, iIndex int, ports []multiv1beta1.MultiNetworkPolicyPort, policyNetworks []string) {
	chainName := fmt.Sprintf("MULTI-%d-EGRESS-%d-PORTS", pIndex, iIndex)
	ipt.CreateFilterChain(chainName)

	// Add jump from MULTI-EGRESS
	writeLine(ipt.policyIndex, "-A", fmt.Sprintf("MULTI-%d-EGRESS", pIndex), "-j", chainName)

	validPorts := 0
	for _, port := range ports {
		proto := renderProtocol(port.Protocol)

		for _, podIntf := range podInfo.Interfaces {
			if !podIntf.CheckPolicyNetwork(policyNetworks) {
				continue
			}
			writeLine(ipt.egressPorts, "-A", chainName,
				"-o", podIntf.InterfaceName,
				"-m", proto, "-p", proto, "--dport", port.Port.String(),
				"-j", "MARK", "--set-xmark", "0x10000/0x10000")
			validPorts++
		}
	}

	// Add skip rules if no ports
	if len(ports) == 0 || validPorts == 0 {
		writeLine(ipt.egressPorts, "-A", chainName,
			"-m", "comment", "--comment", "\"no egress ports, skipped\"",
			"-j", "MARK", "--set-xmark", "0x10000/0x10000")
	}
	return
}

func (ipt *iptableBuffer) renderEgressTo(s *Server, podInfo *controllers.PodInfo, pIndex, iIndex int, to []multiv1beta1.MultiNetworkPolicyPeer, policyNetworks []string) {
	chainName := fmt.Sprintf("MULTI-%d-EGRESS-%d-TO", pIndex, iIndex)
	ipt.CreateFilterChain(chainName)

	// Add jump from MULTI-EGRESS
	writeLine(ipt.policyIndex, "-A", fmt.Sprintf("MULTI-%d-EGRESS", pIndex), "-j", chainName)

	s.podMap.Update(s.podChanges)
	for _, peer := range to {
		if peer.PodSelector != nil || peer.NamespaceSelector != nil {
			podSelectorMap, err := metav1.LabelSelectorAsMap(peer.PodSelector)
			if err != nil {
				klog.Errorf("pod selector: %v", err)
				continue
			}
			podLabelSelector := labels.Set(podSelectorMap).AsSelectorPreValidated()
			pods, err := s.podLister.Pods(metav1.NamespaceAll).List(podLabelSelector)
			if err != nil {
				klog.Errorf("pod list failed:%v", err)
				continue
			}

			var nsSelector labels.Selector
			if peer.NamespaceSelector != nil {
				nsSelectorMap, err := metav1.LabelSelectorAsMap(peer.NamespaceSelector)
				if err != nil {
					klog.Errorf("namespace selector: %v", err)
					continue
				}
				nsSelector = labels.Set(nsSelectorMap).AsSelectorPreValidated()
			}
			s.namespaceMap.Update(s.nsChanges)
			s.podMap.Update(s.podChanges)

			for _, sPod := range pods {
				nsLabels, err := s.namespaceMap.GetNamespaceInfo(sPod.Namespace)
				if err != nil {
					klog.Errorf("cannot get namespace info: %v", err)
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
						for _, ip := range sPodIntf.IPs {
							if ipt.isIPFamilyCompatible(ip) {
								writeLine(ipt.egressTo, "-A", chainName,
									"-o", podIntf.InterfaceName, "-d", ip,
									"-j", "MARK", "--set-xmark", "0x20000/0x20000")
							}
						}
						// egress should accept reverse path
						for _, ip := range podIntf.IPs {
							if ipt.isIPFamilyCompatible(ip) {
								writeLine(ipt.egressTo, "-A", chainName,
									"-o", podIntf.InterfaceName, "-d", ip,
									"-j", "MARK", "--set-xmark", "0x20000/0x20000")
							}
						}
					}
				}
			}
		} else if peer.IPBlock != nil {
			for _, except := range peer.IPBlock.Except {
				for _, multi := range podInfo.Interfaces {
					if !multi.CheckPolicyNetwork(policyNetworks) {
						continue
					}
					if ipt.isIPFamilyCompatible(except) {
						writeLine(ipt.egressTo, "-A", chainName,
							"-o", multi.InterfaceName, "-d", except, "-j", "DROP")
					}
				}
			}
			for _, podIntf := range podInfo.Interfaces {
				if !podIntf.CheckPolicyNetwork(policyNetworks) {
					continue
				}
				if ipt.isIPFamilyCompatible(peer.IPBlock.CIDR) {
					writeLine(ipt.egressTo, "-A", chainName,
						"-o", podIntf.InterfaceName, "-d", peer.IPBlock.CIDR,
						"-j", "MARK", "--set-xmark", "0x20000/0x20000")
				}
			}
			// egress should accept reverse path
			for _, podIntf := range podInfo.Interfaces {
				if !podIntf.CheckPolicyNetwork(policyNetworks) {
					continue
				}
				for _, ip := range podIntf.IPs {
					if ipt.isIPFamilyCompatible(ip) {
						writeLine(ipt.egressTo, "-A", chainName,
							"-o", podIntf.InterfaceName, "-d", ip,
							"-j", "MARK", "--set-xmark", "0x20000/0x20000")
					}
				}
			}
		} else {
			klog.Errorf("unknown rule")
		}
	}

	// Add skip rules if no to
	if len(to) == 0 {
		writeLine(ipt.egressTo, "-A", chainName,
			"-m", "comment", "--comment", "\"no egress to, skipped\"",
			"-j", "MARK", "--set-xmark", "0x20000/0x20000")
	}
	return
}

func (ipt *iptableBuffer) isIPFamilyCompatible(ip string) bool {
	if ipt.isIPv6 && isAddressIPv6(ip) {
		return true
	}

	if !ipt.isIPv6 && isAddressIPv4(ip) {
		return true
	}

	return false
}

// Join all words with spaces, terminate with newline and write to buf.
func writeLine(buf *bytes.Buffer, words ...string) {
	// We avoid strings.Join for performance reasons.
	for i := range words {
		buf.WriteString(words[i])
		if i < len(words)-1 {
			buf.WriteByte(' ')
		} else {
			buf.WriteByte('\n')
		}
	}
}

func writeBytesLine(buf *bytes.Buffer, str string) {
	buf.Write([]byte(str))
	buf.WriteByte('\n')
}

func renderProtocol(proto *v1.Protocol) string {
	p := v1.ProtocolTCP
	if proto != nil {
		p = *proto
	}

	return strings.ToLower(string(p))
}

func isAddressIPv6(ip string) bool {
	return strings.Contains(ip, ":")
}

func isAddressIPv4(ip string) bool {
	return strings.Contains(ip, ".")
}
