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
	"sync"
	"sync/atomic"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"

	"github.com/k8snetworkplumbingwg/multi-networkpolicy-iptables/pkg/controllers"
	multiutils "github.com/k8snetworkplumbingwg/multi-networkpolicy-iptables/pkg/utils"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	multiclient "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/client/clientset/versioned"
	multiinformer "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/client/informers/externalversions"
	multilisterv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/client/listers/k8s.cni.cncf.io/v1beta1"
	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netdefclient "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned"
	netdefinformerv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/informers/externalversions"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog"
	api "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/util/async"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	utilnode "k8s.io/kubernetes/pkg/util/node"
	"k8s.io/utils/exec"
)

const defaultSyncPeriod = 30

// Server structure defines data for server
type Server struct {
	podChanges          *controllers.PodChangeTracker
	policyChanges       *controllers.PolicyChangeTracker
	netdefChanges       *controllers.NetDefChangeTracker
	nsChanges           *controllers.NamespaceChangeTracker
	mu                  sync.Mutex // protects the following fields
	podMap              controllers.PodMap
	policyMap           controllers.PolicyMap
	namespaceMap        controllers.NamespaceMap
	Client              clientset.Interface
	Hostname            string
	hostPrefix          string
	NetworkPolicyClient multiclient.Interface
	NetDefClient        netdefclient.Interface
	Broadcaster         record.EventBroadcaster
	Recorder            record.EventRecorder
	Options             *Options
	ConfigSyncPeriod    time.Duration
	NodeRef             *v1.ObjectReference
	ip4Tables           utiliptables.Interface
	ip6Tables           utiliptables.Interface

	initialized int32

	podSynced    bool
	policySynced bool
	netdefSynced bool
	nsSynced     bool

	podLister    corelisters.PodLister
	policyLister multilisterv1beta1.MultiNetworkPolicyLister

	syncRunner       *async.BoundedFrequencyRunner
	syncRunnerStopCh chan struct{}
}

// RunPodConfig ...
func (s *Server) RunPodConfig() {
	klog.Infof("Starting pod config")
	informerFactory := informers.NewSharedInformerFactoryWithOptions(s.Client, s.ConfigSyncPeriod)
	s.podLister = informerFactory.Core().V1().Pods().Lister()

	podConfig := controllers.NewPodConfig(informerFactory.Core().V1().Pods(), s.ConfigSyncPeriod)
	podConfig.RegisterEventHandler(s)
	go podConfig.Run(wait.NeverStop)
	informerFactory.Start(wait.NeverStop)
	s.SyncLoop()
}

// Run ...
func (s *Server) Run(hostname string, stopCh chan struct{}) {
	if s.Broadcaster != nil {
		s.Broadcaster.StartRecordingToSink(
			&v1core.EventSinkImpl{Interface: s.Client.CoreV1().Events("")})
	}

	informerFactory := informers.NewSharedInformerFactoryWithOptions(s.Client, s.ConfigSyncPeriod)
	nsConfig := controllers.NewNamespaceConfig(informerFactory.Core().V1().Namespaces(), s.ConfigSyncPeriod)
	nsConfig.RegisterEventHandler(s)
	go nsConfig.Run(wait.NeverStop)
	informerFactory.Start(wait.NeverStop)

	policyInformerFactory := multiinformer.NewSharedInformerFactoryWithOptions(
		s.NetworkPolicyClient, s.ConfigSyncPeriod)
	s.policyLister = policyInformerFactory.K8sCniCncfIo().V1beta1().MultiNetworkPolicies().Lister()

	policyConfig := controllers.NewNetworkPolicyConfig(
		policyInformerFactory.K8sCniCncfIo().V1beta1().MultiNetworkPolicies(), s.ConfigSyncPeriod)
	policyConfig.RegisterEventHandler(s)
	go policyConfig.Run(wait.NeverStop)
	policyInformerFactory.Start(wait.NeverStop)

	netdefInformarFactory := netdefinformerv1.NewSharedInformerFactoryWithOptions(
		s.NetDefClient, s.ConfigSyncPeriod)
	netdefConfig := controllers.NewNetDefConfig(
		netdefInformarFactory.K8sCniCncfIo().V1().NetworkAttachmentDefinitions(), s.ConfigSyncPeriod)
	netdefConfig.RegisterEventHandler(s)
	go netdefConfig.Run(wait.NeverStop)
	netdefInformarFactory.Start(wait.NeverStop)

	s.birthCry()

	// Wait for stop signal
	<-stopCh

	// Stop the sync runner loop
	s.syncRunnerStopCh <- struct{}{}

	// Delete all iptables by running the `syncMultiPolicy` with no MultiNetworkPolicies
	s.policyMap = nil
	s.syncMultiPolicy()
}

func (s *Server) setInitialized(value bool) {
	var initialized int32
	if value {
		initialized = 1
	}
	atomic.StoreInt32(&s.initialized, initialized)
}

func (s *Server) isInitialized() bool {
	return atomic.LoadInt32(&s.initialized) > 0
}

func (s *Server) birthCry() {
	klog.Infof("Starting network-policy-node")
	s.Recorder.Eventf(s.NodeRef, api.EventTypeNormal, "Starting", "Starting network-policy-node.")
}

// SyncLoop ...
func (s *Server) SyncLoop() {
	s.syncRunner.Loop(s.syncRunnerStopCh)
}

// NewServer ...
func NewServer(o *Options) (*Server, error) {
	var kubeConfig *rest.Config
	var err error
	if len(o.Kubeconfig) == 0 {
		klog.Info("Neither kubeconfig file nor master URL was specified. Falling back to in-cluster config.")
		kubeConfig, err = rest.InClusterConfig()
	} else {
		kubeConfig, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&clientcmd.ClientConfigLoadingRules{ExplicitPath: o.Kubeconfig},
			&clientcmd.ConfigOverrides{ClusterInfo: clientcmdapi.Cluster{Server: o.master}},
		).ClientConfig()
	}
	if err != nil {
		return nil, fmt.Errorf("server creation failed for kubeconfig [%s] master URL [%s]: %w", o.Kubeconfig, o.master, err)
	}

	if o.podIptables != "" {
		// cleanup current pod iptables directory if it exists
		if _, err := os.Stat(o.podIptables); err == nil || !os.IsNotExist(err) {
			err = os.RemoveAll(o.podIptables)
			if err != nil {
				return nil, fmt.Errorf("server creation failed while deleting pod iptables directory [%s]: %w", o.podIptables, err)
			}
		}
		// create pod iptables directory
		err = os.Mkdir(o.podIptables, 0700)
		if err != nil {
			return nil, fmt.Errorf("server creation failed while creating pod iptables directory [%s]: %w", o.podIptables, err)
		}
	}

	client, err := clientset.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("server creation failed while creating clientset for kubeconfig [%s]: %w", kubeConfig, err)
	}

	networkPolicyClient, err := multiclient.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("server creation failed while multi network policy creating clientset for kubeconfig [%s]: %w", kubeConfig, err)
	}

	netdefClient, err := netdefclient.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("server creation failed while creating net-attach-def clientset for kubeconfig [%s]: %w", kubeConfig, err)
	}

	hostname, err := utilnode.GetHostname(o.hostnameOverride)
	if err != nil {
		return nil, fmt.Errorf("server creation failed while getting hostname with override [%s]: %w", o.hostnameOverride, err)
	}

	eventBroadcaster := record.NewBroadcaster()
	recorder := eventBroadcaster.NewRecorder(
		scheme.Scheme,
		v1.EventSource{Component: "multi-networkpolicy-node", Host: hostname})

	nodeRef := &v1.ObjectReference{
		Kind:      "Node",
		Name:      hostname,
		UID:       types.UID(hostname),
		Namespace: "",
	}

	syncPeriod := time.Duration(o.syncPeriod) * time.Second
	minSyncPeriod := 0 * time.Second
	burstSyncs := 2

	policyChanges := controllers.NewPolicyChangeTracker()
	if policyChanges == nil {
		return nil, fmt.Errorf("cannot create policy change tracker")
	}
	netdefChanges := controllers.NewNetDefChangeTracker()
	if netdefChanges == nil {
		return nil, fmt.Errorf("cannot create net-attach-def change tracker")
	}
	nsChanges := controllers.NewNamespaceChangeTracker()
	if nsChanges == nil {
		return nil, fmt.Errorf("cannot create namespace change tracker")
	}
	podChanges := controllers.NewPodChangeTracker(o.containerRuntime, o.containerRuntimeEndpoint, hostname, o.hostPrefix, o.networkPlugins, netdefChanges)
	if podChanges == nil {
		return nil, fmt.Errorf("cannot create pod change tracker")
	}

	server := &Server{
		Options:             o,
		Client:              client,
		Hostname:            hostname,
		hostPrefix:          o.hostPrefix,
		NetworkPolicyClient: networkPolicyClient,
		NetDefClient:        netdefClient,
		Broadcaster:         eventBroadcaster,
		Recorder:            recorder,
		ConfigSyncPeriod:    15 * time.Minute,
		NodeRef:             nodeRef,
		ip4Tables:           utiliptables.New(exec.New(), utiliptables.ProtocolIPv4),
		ip6Tables:           utiliptables.New(exec.New(), utiliptables.ProtocolIPv6),

		policyChanges: policyChanges,
		podChanges:    podChanges,
		netdefChanges: netdefChanges,
		nsChanges:     nsChanges,
		podMap:        make(controllers.PodMap),
		policyMap:     make(controllers.PolicyMap),
		namespaceMap:  make(controllers.NamespaceMap),
	}
	server.syncRunner = async.NewBoundedFrequencyRunner(
		"sync-runner", server.syncMultiPolicy, minSyncPeriod, syncPeriod, burstSyncs)
	server.syncRunnerStopCh = make(chan struct{})
	return server, nil
}

// Sync ...
func (s *Server) Sync() {
	klog.V(4).Infof("Sync Done!")
	if s.syncRunner != nil {
		s.syncRunner.Run()
	}
}

// AllSynced ...
func (s *Server) AllSynced() bool {
	return (s.policySynced == true && s.netdefSynced == true && s.nsSynced == true)
}

// OnPodAdd ...
func (s *Server) OnPodAdd(pod *v1.Pod) {
	klog.V(4).Infof("OnPodUpdate")
	s.OnPodUpdate(nil, pod)
}

// OnPodUpdate ...
func (s *Server) OnPodUpdate(oldPod, pod *v1.Pod) {
	klog.V(4).Infof("OnPodUpdate %s -> %s", podNamespacedName(oldPod), podNamespacedName(pod))
	if s.podChanges.Update(oldPod, pod) && s.podSynced {
		s.Sync()
	}
}

// OnPodDelete ...
func (s *Server) OnPodDelete(pod *v1.Pod) {
	klog.V(4).Infof("OnPodDelete")
	s.OnPodUpdate(pod, nil)
	if multiutils.CheckNodeNameIdentical(s.Hostname, pod.Spec.NodeName) {
		podIptables := fmt.Sprintf("%s/%s", s.Options.podIptables, pod.UID)
		if _, err := os.Stat(podIptables); err == nil {
			err := os.RemoveAll(podIptables)
			if err != nil {
				klog.Errorf("cannot remove pod dir(%s): %v", podIptables, err)
			}
		}
	}
}

// OnPodSynced ...
func (s *Server) OnPodSynced() {
	klog.Infof("OnPodSynced")
	s.mu.Lock()
	s.podSynced = true
	s.setInitialized(s.podSynced)
	s.mu.Unlock()

	s.Sync()
}

// OnPolicyAdd ...
func (s *Server) OnPolicyAdd(policy *multiv1beta1.MultiNetworkPolicy) {
	klog.V(4).Infof("OnPolicyAdd")
	s.OnPolicyUpdate(nil, policy)
}

// OnPolicyUpdate ...
func (s *Server) OnPolicyUpdate(oldPolicy, policy *multiv1beta1.MultiNetworkPolicy) {
	klog.V(4).Infof("OnPolicyUpdate %s -> %s", policyNamespacedName(oldPolicy), policyNamespacedName(policy))
	if s.policyChanges.Update(oldPolicy, policy) && s.isInitialized() {
		s.Sync()
	}
}

// OnPolicyDelete ...
func (s *Server) OnPolicyDelete(policy *multiv1beta1.MultiNetworkPolicy) {
	klog.V(4).Infof("OnPolicyDelete")
	s.OnPolicyUpdate(policy, nil)
}

// OnPolicySynced ...
func (s *Server) OnPolicySynced() {
	klog.Infof("OnPolicySynced")
	s.mu.Lock()
	s.policySynced = true
	s.setInitialized(s.policySynced)
	s.mu.Unlock()

	if s.AllSynced() {
		s.RunPodConfig()
	}
}

// OnNetDefAdd ...
func (s *Server) OnNetDefAdd(net *netdefv1.NetworkAttachmentDefinition) {
	klog.V(4).Infof("OnNetDefAdd")
	s.OnNetDefUpdate(nil, net)
}

// OnNetDefUpdate ...
func (s *Server) OnNetDefUpdate(oldNet, net *netdefv1.NetworkAttachmentDefinition) {
	klog.V(4).Infof("OnNetDefUpdate %s -> %s", nadNamespacedName(oldNet), nadNamespacedName(net))
	if s.netdefChanges.Update(oldNet, net) && s.isInitialized() {
		s.Sync()
	}
}

// OnNetDefDelete ...
func (s *Server) OnNetDefDelete(net *netdefv1.NetworkAttachmentDefinition) {
	klog.V(4).Infof("OnNetDefDelete")
	s.OnNetDefUpdate(net, nil)
}

// OnNetDefSynced ...
func (s *Server) OnNetDefSynced() {
	klog.Infof("OnNetDefSynced")
	s.mu.Lock()
	s.netdefSynced = true
	s.setInitialized(s.netdefSynced)
	s.mu.Unlock()

	if s.AllSynced() {
		s.RunPodConfig()
	}
}

// OnNamespaceAdd ...
func (s *Server) OnNamespaceAdd(ns *v1.Namespace) {
	klog.V(4).Infof("OnNamespaceAdd")
	s.OnNamespaceUpdate(nil, ns)
}

// OnNamespaceUpdate ...
func (s *Server) OnNamespaceUpdate(oldNamespace, ns *v1.Namespace) {
	klog.V(4).Infof("OnNamespaceUpdate: %s -> %s", namespaceName(oldNamespace), namespaceName(ns))
	if s.nsChanges.Update(oldNamespace, ns) && s.isInitialized() {
		s.Sync()
	}
}

// OnNamespaceDelete ...
func (s *Server) OnNamespaceDelete(ns *v1.Namespace) {
	klog.V(4).Infof("OnNamespaceDelete")
	s.OnNamespaceUpdate(ns, nil)
}

// OnNamespaceSynced ...
func (s *Server) OnNamespaceSynced() {
	klog.Infof("OnNamespaceSynced")
	s.mu.Lock()
	s.nsSynced = true
	s.setInitialized(s.nsSynced)
	s.mu.Unlock()

	if s.AllSynced() {
		s.RunPodConfig()
	}
}

func (s *Server) syncMultiPolicy() {
	klog.V(4).Infof("syncMultiPolicy")
	s.namespaceMap.Update(s.nsChanges)
	s.podMap.Update(s.podChanges)
	s.policyMap.Update(s.policyChanges)

	pods, err := s.podLister.Pods(metav1.NamespaceAll).List(labels.Everything())
	if err != nil {
		klog.Errorf("failed to get pods: %v", err)
	}
	for _, p := range pods {
		s.podMap.Update(s.podChanges)
		if !controllers.IsMultiNetworkpolicyTarget(p) {
			klog.V(8).Infof("SKIP SYNC %s/%s", p.Namespace, p.Name)
			continue
		}
		klog.V(8).Infof("SYNC %s/%s", p.Namespace, p.Name)
		if multiutils.CheckNodeNameIdentical(s.Hostname, p.Spec.NodeName) {
			s.podMap.Update(s.podChanges)
			podInfo, err := s.podMap.GetPodInfo(p)
			if err != nil {
				klog.Errorf("cannot get %s/%s podInfo: %v", p.Namespace, p.Name, err)
				continue
			}
			if len(podInfo.Interfaces) == 0 {
				klog.V(8).Infof("skipped due to no interfaces")
				continue
			}
			netnsPath := podInfo.NetNSPath
			if s.hostPrefix != "" {
				netnsPath = fmt.Sprintf("%s/%s", s.hostPrefix, netnsPath)
			}

			netns, err := ns.GetNS(netnsPath)
			if err != nil {
				klog.Errorf("cannot get pod (%s/%s:%s) netns: %v", p.Namespace, p.Name, p.Status.Phase, err)
				continue
			}

			klog.V(8).Infof("pod: %s/%s %s", p.Namespace, p.Name, netnsPath)
			_ = netns.Do(func(_ ns.NetNS) error {
				err := s.generatePolicyRulesForPod(p, podInfo)
				return err
			})
		} else {
			klog.V(8).Infof("SYNC %s/%s: skipped", p.Namespace, p.Name)
		}
	}
}

func (s *Server) backupIptablesRules(pod *v1.Pod, suffix string, iptables utiliptables.Interface) error {
	// skip it if no podiptables option
	if s.Options.podIptables == "" {
		return nil
	}

	podIptables := fmt.Sprintf("%s/%s", s.Options.podIptables, pod.UID)
	// create directory for pod if not exist
	if _, err := os.Stat(podIptables); os.IsNotExist(err) {
		err := os.Mkdir(podIptables, 0700)
		if err != nil {
			klog.Errorf("cannot create pod dir (%s): %v", podIptables, err)
			return err
		}
	}
	fileExt := "iptables"
	if iptables.IsIPv6() {
		fileExt = "ip6tables"
	}
	file, err := os.Create(fmt.Sprintf("%s/%s.%s", podIptables, suffix, fileExt))
	defer file.Close()
	var buffer bytes.Buffer

	// store iptable result to file
	//XXX: need error handling? (see kube-proxy)
	err = iptables.SaveInto(utiliptables.TableMangle, &buffer)
	err = iptables.SaveInto(utiliptables.TableFilter, &buffer)
	err = iptables.SaveInto(utiliptables.TableNAT, &buffer)
	_, err = buffer.WriteTo(file)

	return err
}

const (
	ingressChain       = "MULTI-INGRESS"
	egressChain        = "MULTI-EGRESS"
	ingressCommonChain = "MULTI-INGRESS-COMMON"
	egressCommonChain  = "MULTI-EGRESS-COMMON"
)

func (s *Server) generatePolicyRulesForPod(pod *v1.Pod, podInfo *controllers.PodInfo) error {
	err := s.generatePolicyRulesForPodAndFamily(pod, podInfo, s.ip4Tables)
	if err != nil {
		return fmt.Errorf("can't generate iptables for pod [%s]: %w", podNamespacedName(pod), err)
	}

	err = s.generatePolicyRulesForPodAndFamily(pod, podInfo, s.ip6Tables)
	if err != nil {
		return fmt.Errorf("can't generate ip6tables for pod [%s]: %w", podNamespacedName(pod), err)
	}

	return nil
}

func (s *Server) generatePolicyRulesForPodAndFamily(pod *v1.Pod, podInfo *controllers.PodInfo, iptables utiliptables.Interface) error {
	klog.V(8).Infof("Generate rules for Pod: %v/%v\n", podInfo.Namespace, podInfo.Name)
	// -t filter -N MULTI-INGRESS # ensure chain
	iptables.EnsureChain(utiliptables.TableFilter, ingressChain)
	// -t filter -N MULTI-EGRESS # ensure chain
	iptables.EnsureChain(utiliptables.TableFilter, egressChain)
	// -t filter -N MULTI-INGRESS-COMMON # ensure chain
	iptables.EnsureChain(utiliptables.TableFilter, ingressCommonChain)
	// -t filter -N MULTI-EGRESS-COMMON # ensure chain
	iptables.EnsureChain(utiliptables.TableFilter, egressCommonChain)

	for _, multiIF := range podInfo.Interfaces {
		//    -A INPUT -j MULTI-INGRESS # ensure rules
		iptables.EnsureRule(
			utiliptables.Prepend, utiliptables.TableFilter, "INPUT", "-i", multiIF.InterfaceName, "-j", ingressChain)
		//    -A OUTPUT -j MULTI-EGRESS # ensure rules
		iptables.EnsureRule(
			utiliptables.Prepend, utiliptables.TableFilter, "OUTPUT", "-o", multiIF.InterfaceName, "-j", egressChain)
		//    -A PREROUTING -i net1 -j RETURN # ensure rules
		iptables.EnsureRule(
			utiliptables.Prepend, utiliptables.TableNAT, "PREROUTING", "-i", multiIF.InterfaceName, "-j", "RETURN")
	}
	//    -A MULTI-INGRESS -j MULTI-INGRESS-COMMON # ensure rules
	iptables.EnsureRule(
		utiliptables.Prepend, utiliptables.TableFilter, ingressChain, "-j", ingressCommonChain)
	//    -A MULTI-EGRESS -j MULTI-EGRESS-COMMON # ensure rules
	iptables.EnsureRule(
		utiliptables.Prepend, utiliptables.TableFilter, egressChain, "-j", egressCommonChain)

	iptableBuffer := newIptableBuffer()
	iptableBuffer.Init(iptables)
	iptableBuffer.Reset()

	idx := 0
	ingressRendered := 0
	egressRendered := 0
	for _, p := range s.policyMap {
		policy := p.Policy
		if policy.GetNamespace() != pod.Namespace {
			continue
		}
		if policy.Spec.PodSelector.Size() != 0 {
			policyMap, err := metav1.LabelSelectorAsMap(&policy.Spec.PodSelector)
			if err != nil {
				klog.Errorf("bad label selector for policy [%s]: %v", policyNamespacedName(policy), err)
				continue
			}
			policyPodSelector := labels.Set(policyMap).AsSelectorPreValidated()
			if !policyPodSelector.Matches(labels.Set(pod.Labels)) {
				continue
			}
		}

		var ingressEnable, egressEnable bool
		if len(policy.Spec.PolicyTypes) == 0 {
			ingressEnable = true
			egressEnable = true
		} else {
			for _, v := range policy.Spec.PolicyTypes {
				if strings.EqualFold(string(v), string(multiv1beta1.PolicyTypeIngress)) {
					ingressEnable = true
				} else if strings.EqualFold(string(v), string(multiv1beta1.PolicyTypeEgress)) {
					egressEnable = true
				}
			}
		}
		klog.V(8).Infof("ingress/egress = %v/%v\n", ingressEnable, egressEnable)

		policyNetworksAnnot, ok := policy.GetAnnotations()[PolicyNetworkAnnotation]
		if !ok {
			continue
		}
		policyNetworksAnnot = strings.ReplaceAll(policyNetworksAnnot, " ", "")
		policyNetworks := strings.Split(policyNetworksAnnot, ",")
		for pidx, networkName := range policyNetworks {
			// fill namespace
			if strings.IndexAny(networkName, "/") == -1 {
				policyNetworks[pidx] = fmt.Sprintf("%s/%s", policy.GetNamespace(), networkName)
			}
		}

		if podInfo.CheckPolicyNetwork(policyNetworks) {
			if ingressEnable {
				iptableBuffer.renderIngressCommon(s)
				iptableBuffer.renderIngress(s, podInfo, idx, policy, policyNetworks)
				ingressRendered++
			}
			if egressEnable {
				iptableBuffer.renderEgressCommon(s)
				iptableBuffer.renderEgress(s, podInfo, idx, policy, policyNetworks)
				egressRendered++
			}
			idx++
		}
	}
	if ingressRendered != 0 {
		writeLine(iptableBuffer.policyIndex, "-A", "MULTI-INGRESS", "-j", "DROP")
	}
	if egressRendered != 0 {
		writeLine(iptableBuffer.policyIndex, "-A", "MULTI-EGRESS", "-j", "DROP")
	}

	if !iptableBuffer.IsUsed() {
		iptableBuffer.Init(iptables)
	}

	iptableBuffer.FinalizeRules()

	/* store generated iptables rules if podIptables is enabled */
	if s.Options.podIptables != "" {
		if iptables.IsIPv6() {
			filePath := fmt.Sprintf("%s/%s/networkpolicy.ip6tables", s.Options.podIptables, pod.UID)
			iptableBuffer.SaveRules(filePath)
		} else {
			filePath := fmt.Sprintf("%s/%s/networkpolicy.iptables", s.Options.podIptables, pod.UID)
			iptableBuffer.SaveRules(filePath)
		}
	}

	if err := iptableBuffer.SyncRules(iptables); err != nil {
		klog.Errorf("sync rules failed for pod [%s]: %v", podNamespacedName(pod), err)
		return err
	}

	s.backupIptablesRules(pod, "current", iptables)

	return nil
}

func podNamespacedName(o *v1.Pod) string {
	if o == nil {
		return "<nil>"
	}
	return o.GetNamespace() + "/" + o.GetName()
}

func namespaceName(o *v1.Namespace) string {
	if o == nil {
		return "<nil>"
	}
	return o.GetName()
}

func policyNamespacedName(o *multiv1beta1.MultiNetworkPolicy) string {
	if o == nil {
		return "<nil>"
	}
	return o.GetNamespace() + "/" + o.GetName()
}

func nadNamespacedName(o *netdefv1.NetworkAttachmentDefinition) string {
	if o == nil {
		return "<nil>"
	}
	return o.GetNamespace() + "/" + o.GetName()
}
