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
	"bufio"
	"flag"
	"net"
	"os"
	"strings"

	"github.com/k8snetworkplumbingwg/multi-networkpolicy-iptables/pkg/controllers"
	"github.com/spf13/pflag"

	"k8s.io/klog"
	utilnode "k8s.io/kubernetes/pkg/util/node"
)

// Options stores option for the command
type Options struct {
	// kubeconfig is the path to a KubeConfig file.
	Kubeconfig string
	// master is used to override the kubeconfig's URL to the apiserver
	master                    string
	hostnameOverride          string
	hostPrefix                string
	containerRuntime          controllers.RuntimeKind
	containerRuntimeEndpoint  string
	networkPlugins            []string
	podIptables               string
	syncPeriod                int
	acceptICMPv6              bool
	acceptICMP                bool
	allowIPv6SrcPrefixText    string
	allowIPv6DstPrefixText    string
	customIPv4IngressRuleFile string
	customIPv4EgressRuleFile  string
	customIPv6IngressRuleFile string
	customIPv6EgressRuleFile  string

	// updated by command line parsing
	allowIPv6SrcPrefix    []string
	allowIPv6DstPrefix    []string
	customIPv4IngressRule []string
	customIPv4EgressRule  []string
	customIPv6IngressRule []string
	customIPv6EgressRule  []string
	// stopCh is used to stop the command
	stopCh chan struct{}
}

// AddFlags adds command line flags into command
func (o *Options) AddFlags(fs *pflag.FlagSet) {
	klog.InitFlags(nil)
	fs.SortFlags = false
	fs.Var(&o.containerRuntime, "container-runtime", "Container runtime using for the cluster. Possible values: 'cri'. ")
	fs.StringVar(&o.containerRuntimeEndpoint, "container-runtime-endpoint", o.containerRuntimeEndpoint, "Path to cri socket.")
	fs.StringVar(&o.Kubeconfig, "kubeconfig", o.Kubeconfig, "Path to kubeconfig file with authorization information (the master location is set by the master flag).")
	fs.StringVar(&o.master, "master", o.master, "The address of the Kubernetes API server (overrides any value in kubeconfig)")
	fs.StringVar(&o.hostnameOverride, "hostname-override", o.hostnameOverride, "If non-empty, will use this string as identification instead of the actual hostname.")
	fs.StringVar(&o.hostPrefix, "host-prefix", o.hostPrefix, "If non-empty, will use this string as prefix for host filesystem.")
	fs.StringSliceVar(&o.networkPlugins, "network-plugins", []string{"macvlan"}, "List of network plugins to be be considered for network policies.")
	fs.StringVar(&o.podIptables, "pod-iptables", o.podIptables, "If non-empty, will use this path to store pod's iptables for troubleshooting helper.")
	fs.IntVar(&o.syncPeriod, "sync-period", defaultSyncPeriod, "sync period for multi-networkpolicy syncRunner")
	fs.BoolVar(&o.acceptICMP, "accept-icmp", false, "accept all ICMP traffic")
	fs.BoolVar(&o.acceptICMPv6, "accept-icmpv6", false, "accept all ICMPv6 traffic")
	fs.StringVar(&o.allowIPv6SrcPrefixText, "allow-ipv6-src-prefix", "", "Accept source IPv6 prefix list, comma separated (e.g. \"fe80::/10\")")
	fs.StringVar(&o.allowIPv6DstPrefixText, "allow-ipv6-dst-prefix", "", "Accept destination IPv6 prefix list, comma separated (e.g. \"fe80:/10,ff00::/8\")")
	fs.StringVar(&o.customIPv4IngressRuleFile, "custom-v4-ingress-rule-file", "", "custom rule file for IPv4 ingress")
	fs.StringVar(&o.customIPv4EgressRuleFile, "custom-v4-egress-rule-file", "", "custom rule file for IPv4 egress")
	fs.StringVar(&o.customIPv6IngressRuleFile, "custom-v6-ingress-rule-file", "", "custom rule file for IPv6 ingress")
	fs.StringVar(&o.customIPv6EgressRuleFile, "custom-v6-egress-rule-file", "", "custom rule file for IPv6 egress")
	fs.AddGoFlagSet(flag.CommandLine)
}

func parseCustomRuleFile(filename string, rules *[]string) error {
	if filename != "" {
		*rules = []string{}
		fp, err := os.Open(filename)
		if err != nil {
			return err
		}
		defer fp.Close()

		scanner := bufio.NewScanner(fp)
		for scanner.Scan() {
			rule := scanner.Text()
			if strings.HasPrefix(rule, "#") { // skip rule begin with '#'
				continue
			}
			*rules = append(*rules, rule)
		}

		if err := scanner.Err(); err != nil {
			return err
		}
	}
	return nil
}

func parseIPPrefixText(prefixText string, prefixList *[]string) error {
	if prefixText != "" {
		*prefixList = []string{}
		for _, addrRaw := range strings.Split(prefixText, ",") {
			addr := strings.TrimSpace(addrRaw)
			_, _, err := net.ParseCIDR(addr)
			if err != nil {
				return err
			}
			*prefixList = append(*prefixList, addr)
		}
	}
	return nil
}

// Validate checks several options and fill processed value
func (o *Options) Validate() error {

	// Validate IPv6 source prefix list
	if err := parseIPPrefixText(o.allowIPv6SrcPrefixText, &o.allowIPv6SrcPrefix); err != nil {
		return err
	}

	// Validate IPv6 destination prefix list
	if err := parseIPPrefixText(o.allowIPv6DstPrefixText, &o.allowIPv6DstPrefix); err != nil {
		return err
	}

	// Validate v4 ingress rules
	if err := parseCustomRuleFile(o.customIPv4IngressRuleFile, &o.customIPv4IngressRule); err != nil {
		return err
	}

	// Validate v4 engress rules
	if err := parseCustomRuleFile(o.customIPv4EgressRuleFile, &o.customIPv4EgressRule); err != nil {
		return err
	}

	// Validate v6 ingress rules
	if err := parseCustomRuleFile(o.customIPv6IngressRuleFile, &o.customIPv6IngressRule); err != nil {
		return err
	}

	// Validate v6 engress rules
	if err := parseCustomRuleFile(o.customIPv6EgressRuleFile, &o.customIPv6EgressRule); err != nil {
		return err
	}

	return nil
}

// Run invokes server
func (o *Options) Run() error {
	server, err := NewServer(o)
	if err != nil {
		return err
	}

	hostname, err := utilnode.GetHostname(o.hostnameOverride)
	if err != nil {
		return err
	}
	klog.Infof("hostname: %v", hostname)
	klog.Infof("container-runtime: %v", o.containerRuntime)

	// validate option and update it (check v6prefix list)
	err = o.Validate()
	if err != nil {
		return err
	}

	server.Run(hostname, o.stopCh)

	return nil
}

// Stop halts the command
func (o *Options) Stop() {
	o.stopCh <- struct{}{}
}

// NewOptions initializes Options
func NewOptions() *Options {
	return &Options{
		containerRuntime: controllers.Cri,
		stopCh:           make(chan struct{}),
	}
}
