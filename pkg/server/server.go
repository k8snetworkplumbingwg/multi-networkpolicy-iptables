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
	"fmt"
	"os"
	"slices"
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

	nftables "github.com/google/nftables"
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
	nodeutil "k8s.io/component-helpers/node/util"
	"k8s.io/klog"
	api "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/util/async"
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

type internalPolicy struct {
	policy         *multiv1beta1.MultiNetworkPolicy
	policyNetworks []string
}

func CompareInternalPolicy(a, b internalPolicy) int {
	return strings.Compare(fmt.Sprintf("%s/%s", a.policy.GetNamespace(), a.policy.GetName()), fmt.Sprintf("%s/%s", b.policy.GetNamespace(), b.policy.GetName()))
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
func (s *Server) Run(_ string, stopCh chan struct{}) {
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

	hostname, err := nodeutil.GetHostname(o.hostnameOverride)
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
	return (s.policySynced && s.netdefSynced && s.nsSynced)
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
			// implement netfilter logic here
			netns, err := ns.GetNS(netnsPath)
			if err != nil {
				klog.Errorf("cannot get pod (%s/%s:%s) netns (%s): %v", p.Namespace, p.Name, p.Status.Phase, netnsPath, err)
				continue
			}
			defer func() {
				err := netns.Close()
				if err != nil {
					klog.Errorf("cannot close pod (%s/%s:%s) netns (%s): %v", p.Namespace, p.Name, p.Status.Phase, netnsPath, err)
				}
			}()

			klog.V(8).Infof("pod: %s/%s %s", p.Namespace, p.Name, netnsPath)
			err = s.applyPolicyRulesForPod(p, podInfo, netns)
			if err != nil {
				klog.Errorf("can't apply netfilter rules for pod [%s]: %v", podNamespacedName(p), err)
			}
		} else {
			klog.V(8).Infof("SYNC %s/%s: skipped", p.Namespace, p.Name)
		}
	}
}

func (s *Server) applyPolicyRulesForPod(pod *v1.Pod, podInfo *controllers.PodInfo, netNs ns.NetNS) error {
	nft, err := nftables.New(nftables.WithNetNSFd(int(netNs.Fd())), nftables.AsLasting())
	var closeErr error
	defer func() {
		if err := nft.CloseLasting(); err != nil {
			closeErr = fmt.Errorf("closing lasting netlink connection failed for pod [%s]: %w", podNamespacedName(pod), err)
		}
	}()
	if err != nil {
		return fmt.Errorf("failed to open nftables: %v", err)
	}
	err = s.applyPolicyRulesForPodAndFamily(pod, podInfo, nft)
	if err != nil {
		return fmt.Errorf("can't apply nftables inet rules for pod [%s]: %w", podNamespacedName(pod), err)
	}
	return closeErr
}

func (s *Server) applyPolicyRulesForPodAndFamily(pod *v1.Pod, podInfo *controllers.PodInfo, nft *nftables.Conn) error {
	klog.V(4).Infof("Generate rules for Pod: [%s]\n", podNamespacedName(pod))

	// nft add table inet filter
	nftState, err := bootstrapNetfilterRules(nft, podInfo)
	if err != nil {
		return fmt.Errorf("bootstrap netfilter rules failed for pod [%s]: %w", podNamespacedName(pod), err)
	}
	if nftState == nil {
		return fmt.Errorf("bootstrap netfilter rules returned nil state for pod [%s]", podNamespacedName(pod))
	}

	var ingressPolicies []internalPolicy
	var egressPolicies []internalPolicy

	for _, p := range s.policyMap {
		policy := p.Policy
		if policy.GetNamespace() != pod.Namespace {
			continue
		}
		if policy.Spec.PodSelector.Size() != 0 {
			policyPodSelector, err := metav1.LabelSelectorAsSelector(&policy.Spec.PodSelector)
			if err != nil {
				klog.Errorf("bad label selector for policy [%s]: %v", policyNamespacedName(policy), err)
				continue
			}
			if !policyPodSelector.Matches(labels.Set(pod.Labels)) {
				continue
			}
		}

		ingressEnable, egressEnable := getEnabledPolicyTypes(policy)
		klog.V(8).Infof("ingress/egress = %v/%v\n", ingressEnable, egressEnable)

		policyNetworksAnnot, ok := policy.GetAnnotations()[PolicyNetworkAnnotation]
		if !ok {
			continue
		}
		policyNetworksAnnot = strings.ReplaceAll(policyNetworksAnnot, " ", "")
		policyNetworks := strings.Split(policyNetworksAnnot, ",")
		for pidx, networkName := range policyNetworks {
			// fill namespace
			if !strings.ContainsAny(networkName, "/") {
				policyNetworks[pidx] = fmt.Sprintf("%s/%s", policy.GetNamespace(), networkName)
			}
		}
		slices.Sort(policyNetworks)

		if podInfo.CheckPolicyNetwork(policyNetworks) {
			if ingressEnable {
				ingressPolicies = append(ingressPolicies, internalPolicy{
					policy:         policy,
					policyNetworks: policyNetworks,
				})
			}
			if egressEnable {
				egressPolicies = append(egressPolicies, internalPolicy{
					policy:         policy,
					policyNetworks: policyNetworks,
				})
			}
		}
	}

	err = nftState.applyCommonChainRules(s)
	if err != nil {
		return fmt.Errorf("failed to apply common chain rules for pod [%s]: %w", podNamespacedName(pod), err)
	}

	// Stable sort by policy name
	slices.SortFunc(ingressPolicies, func(a, b internalPolicy) int {
		return strings.Compare(fmt.Sprintf("%s/%s", a.policy.GetNamespace(), a.policy.GetName()), fmt.Sprintf("%s/%s", b.policy.GetNamespace(), b.policy.GetName()))
	})
	slices.SortFunc(egressPolicies, func(a, b internalPolicy) int {
		return strings.Compare(fmt.Sprintf("%s/%s", a.policy.GetNamespace(), a.policy.GetName()), fmt.Sprintf("%s/%s", b.policy.GetNamespace(), b.policy.GetName()))
	})

	if len(ingressPolicies) > 0 {
		for idx, policy := range ingressPolicies {
			if err := nftState.applyPodRules(s, nftState.ingressChain, podInfo, idx, policy.policy, policy.policyNetworks); err != nil {
				klog.Errorf("failed to apply pod ingress rules: %v", err)
			}
		}
		if err := nftState.applyGeneralMarkCheck(nftState.ingressChain); err != nil {
			return fmt.Errorf("failed to apply mark check rule in chain %q: %w", nftState.ingressChain.Name, err)
		}
		if err := nftState.applyDropRemaining(nftState.ingressChain); err != nil {
			klog.Errorf("failed to apply drop remaining ingress rules: %v", err)
		}
	}

	if len(egressPolicies) > 0 {
		for idx, policy := range egressPolicies {
			if err := nftState.applyPodRules(s, nftState.egressChain, podInfo, idx, policy.policy, policy.policyNetworks); err != nil {
				klog.Errorf("failed to apply pod egress rules: %v", err)
			}
		}
		if err := nftState.applyGeneralMarkCheck(nftState.egressChain); err != nil {
			return fmt.Errorf("failed to apply mark check rule in chain %q: %w", nftState.egressChain.Name, err)
		}
		if err := nftState.applyDropRemaining(nftState.egressChain); err != nil {
			klog.Errorf("failed to apply drop remaining egress rules: %v", err)
		}
	}
	if err := nftState.nft.Flush(); err != nil {
		return fmt.Errorf("nft flush failed for pod [%s]: %w", podNamespacedName(pod), err)
	}

	if err := nftState.cleanup(); err != nil {
		return fmt.Errorf("failed to cleanup nft: %w", err)
	}

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

func getEnabledPolicyTypes(policy *multiv1beta1.MultiNetworkPolicy) (bool, bool) {
	var ingressEnable, egressEnable bool
	if len(policy.Spec.PolicyTypes) > 0 {
		for _, v := range policy.Spec.PolicyTypes {
			if strings.EqualFold(string(v), string(multiv1beta1.PolicyTypeIngress)) {
				ingressEnable = true
			} else if strings.EqualFold(string(v), string(multiv1beta1.PolicyTypeEgress)) {
				egressEnable = true
			}
		}
		return ingressEnable, egressEnable
	}

	return len(policy.Spec.Ingress) > 0, len(policy.Spec.Egress) > 0
}
