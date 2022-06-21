package reachmatcher

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strings"

	nadv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/onsi/gomega/format"
	"github.com/onsi/gomega/types"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/utils/pointer"
)

// Port5555 is the port number 5555
var Port5555 intstr.IntOrString = intstr.FromInt(5555)

// Port6666 is the port number 6666
var Port6666 intstr.IntOrString = intstr.FromInt(6666)

// ProtoTCP is the TCP protocol
var ProtoTCP corev1.Protocol = corev1.ProtocolTCP

// ProtoUDP is the UDP protocol
var ProtoUDP corev1.Protocol = corev1.ProtocolUDP

// ProtoSCTP is the SCTP (Stream Control Transmission Protocol) protocol
var ProtoSCTP corev1.Protocol = corev1.ProtocolSCTP

const (
	netcatImage        = "quay.io/openshift-kni/cnf-tests:4.11"
	debugIPTablesImage = "ghcr.io/k8snetworkplumbingwg/multi-networkpolicy-iptables:snapshot-amd64"
)

var (
	restConfig   *rest.Config
	k8sClientSet *kubernetes.Clientset
)

// SetRestConfig configures the package to use the given APIserver rest configuration. The configuration
// is used by the ReachMatcher to test if a client pod can connect to a netcat server.
func SetRestConfig(c *rest.Config) error {
	restConfig = c

	var err error
	k8sClientSet, err = kubernetes.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("can't create k8s  client for reachmatcher: [%w]", err)
	}

	return nil
}

// AddTCPNetcatServerToPod adds a container to the pod with a TCP netcat server that are suitable to be used with ReachMatcher.
func AddTCPNetcatServerToPod(pod *corev1.Pod, port intstr.IntOrString) *corev1.Pod {
	// --keep-open parameters helps to use the same server for multiple tests. Incoming messages
	// are forwarder to pod logs (stdout/stderr) and they are used to validate connectivity (see `canSendTraffic``)
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{
		Name:            "netcat-tcp-server-" + port.String(),
		Image:           netcatImage,
		Command:         []string{"nc", "-vv", "--keep-open", "--listen", port.String()},
		SecurityContext: &corev1.SecurityContext{Privileged: pointer.BoolPtr(true)}})

	return pod
}

// AddUDPNetcatServerToPod adds a container to the pod with a UDP netcat server that are suitable to be used with ReachMatcher.
func AddUDPNetcatServerToPod(pod *corev1.Pod, port intstr.IntOrString) *corev1.Pod {
	// UDP servers support --keep-open only with --sh-exec option, and to get the incoming messages
	// to logs they are needed to be sent to stderr, as stdout is redirected back to the client
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{
		Name:            "netcat-udp-server-" + port.String(),
		Image:           netcatImage,
		Command:         []string{"nc", "-vv", "--udp", "--keep-open", "--sh-exec", "/bin/cat >&2", "--listen", port.String()},
		SecurityContext: &corev1.SecurityContext{Privileged: pointer.BoolPtr(true)}})

	return pod
}

// AddSCTPNetcatServerToPod adds a container to the pod with a SCTP netcat server that are suitable to be used with ReachMatcher.
func AddSCTPNetcatServerToPod(pod *corev1.Pod, port intstr.IntOrString) *corev1.Pod {
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{
		Name:            "netcat-sctp-server-" + port.String(),
		Image:           netcatImage,
		Command:         []string{"nc", "-vv", "--sctp", "--keep-open", "--sh-exec", "/bin/cat >&2", "--listen", port.String()},
		SecurityContext: &corev1.SecurityContext{Privileged: pointer.BoolPtr(true)}})

	return pod
}

// AddIPTableDebugContainer adds a container that polls iptables information and print them to stdout
func AddIPTableDebugContainer(pod *corev1.Pod) *corev1.Pod {
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{
		Name:            "debug-iptables",
		Image:           debugIPTablesImage,
		Command:         []string{"sh", "-c", "while true; do iptables -L -v -n; sleep 10; done"},
		SecurityContext: &corev1.SecurityContext{Privileged: pointer.BoolPtr(true)}})

	return pod
}

// ReachMatcher allows making assertion on pod connectivity using netcat servers and clients
type ReachMatcher struct {
	destinationPod     *corev1.Pod
	destinationPort    string
	destinationAddress string
	protocol           corev1.Protocol
	ipFamily           corev1.IPFamily
}

// ReachOpt describe a function that applies to a ReachMatcher
type ReachOpt func(*ReachMatcher)

// Reach creates a new ReachMatcher with a destination pod and a list of options.
func Reach(destinationPod *corev1.Pod, opts ...ReachOpt) types.GomegaMatcher {
	ret := &ReachMatcher{
		destinationPod:  destinationPod,
		destinationPort: Port5555.String(),
		protocol:        corev1.ProtocolTCP,
		ipFamily:        corev1.IPv4Protocol,
	}

	for _, opt := range opts {
		opt(ret)
	}

	ret.destinationAddress = getMultusNicIP(ret.destinationPod, ret.ipFamily)

	return ret
}

// OnPort specifies the destination port to be used in the matcher.
func OnPort(port intstr.IntOrString) ReachOpt {
	return func(s *ReachMatcher) {
		s.destinationPort = port.String()
	}
}

// ViaTCP specifies that the TCP protocol must be used to check the connectivity.
var ViaTCP ReachOpt = func(s *ReachMatcher) {
	s.protocol = corev1.ProtocolTCP
}

// ViaUDP specifies that the UDP protocol must be used to check the connectivity.
var ViaUDP ReachOpt = func(s *ReachMatcher) {
	s.protocol = corev1.ProtocolUDP
}

// ViaSCTP specifies that the SCTP protocol must be used to check the connectivity.
var ViaSCTP ReachOpt = func(s *ReachMatcher) {
	s.protocol = corev1.ProtocolSCTP
}

// ViaIPv4 specifies to use v4 as IP family.
var ViaIPv4 ReachOpt = func(s *ReachMatcher) {
	s.ipFamily = corev1.IPv4Protocol
}

// ViaIPv6 specifies to use v6 as IP family.
var ViaIPv6 ReachOpt = func(s *ReachMatcher) {
	s.ipFamily = corev1.IPv6Protocol
}

// Match checks if the actual meets the Reach condition.
func (m *ReachMatcher) Match(actual interface{}) (bool, error) {
	sourcePod, ok := actual.(*corev1.Pod)
	if !ok {
		return false, fmt.Errorf("ReachMatcher must be passed an *Pod. Got\n%s", format.Object(actual, 1))
	}

	return canSendTraffic(sourcePod, m.destinationPod, m.destinationPort, m.ipFamily, m.protocol)
}

// FailureMessage builds the message to show in case of assertion failure
func (m *ReachMatcher) FailureMessage(actual interface{}) string {
	sourcePod, ok := actual.(*corev1.Pod)
	if !ok {
		return "ReachMatcher should be used against v1.Pod objects"
	}

	return fmt.Sprintf(`pod [%s/%s %s] is not reachable by pod [%s/%s] on port[%s:%s], but it should be.
Server iptables:
%s
-----
Client iptables:
%s`,
		m.destinationPod.Namespace, m.destinationPod.Name, m.destinationAddress,
		sourcePod.Namespace, sourcePod.Name,
		m.protocol, m.destinationPort,
		getIPTables(m.destinationPod),
		getIPTables(sourcePod),
	)
}

// NegatedFailureMessage builds the message to show in case of negated assertion failure
func (m *ReachMatcher) NegatedFailureMessage(actual interface{}) string {
	sourcePod, ok := actual.(*corev1.Pod)
	if !ok {
		return "ReachMatcher should be used against v1.Pod objects"
	}

	return fmt.Sprintf(`pod [%s/%s %s] is reachable by pod [%s/%s] on port[%s:%s], but it shouldn't be.
Server iptables:
%s
-----
Client iptables:
%s`,
		m.destinationPod.Namespace, m.destinationPod.Name, m.destinationAddress,
		sourcePod.Namespace, sourcePod.Name,
		m.protocol, m.destinationPort,
		getIPTables(m.destinationPod),
		getIPTables(sourcePod),
	)
}

func canSendTraffic(sourcePod, destinationPod *corev1.Pod, destinationPort string, ipFamily corev1.IPFamily, protocol corev1.Protocol) (bool, error) {
	destinationIP := getMultusNicIP(destinationPod, ipFamily)

	protocolArg := ""
	if protocol == corev1.ProtocolUDP {
		protocolArg = "--udp"
	}

	if protocol == corev1.ProtocolSCTP {
		protocolArg = "--sctp"
	}

	saltString := fmt.Sprintf("%d", rand.Intn(1000000)+1000000)

	containerName, err := findContainerNameByImage(sourcePod, netcatImage)
	if err != nil {
		return false, fmt.Errorf("can't check connectivity from source pod [%s]: %w", sourcePod.Name, err)
	}

	output, err := execCommandInPod(
		*sourcePod,
		containerName,
		[]string{
			"bash", "-c",
			fmt.Sprintf("echo '%s (%s/%s)-%s:%s%s' | nc -w 1 %s %s %s",
				saltString,
				sourcePod.Namespace, sourcePod.Name,
				destinationIP,
				destinationPort,
				protocol,
				protocolArg,
				destinationIP,
				destinationPort,
			),
		})

	if err != nil {
		if doesErrorMeanNoConnectivity(output.String(), protocol) {
			return false, nil
		}

		return false, fmt.Errorf("can't connect pods [%s] -> [%s]: %w\nServer iptables\n%s\n---\nClient iptables\n%s",
			sourcePod.Name, destinationPod.Name, err, getIPTables(destinationPod), getIPTables(sourcePod))
	}

	destinationContainerName := fmt.Sprintf("netcat-%s-server-%s", strings.ToLower(string(protocol)), destinationPort)
	destinationLogs, err := getLogsForContainer(
		destinationPod,
		destinationContainerName,
	)
	if err != nil {
		return false, fmt.Errorf("can't get destination pod logs [%s/%s]: %w ", destinationPod.Name, destinationContainerName, err)
	}

	if strings.Contains(destinationLogs, saltString) {
		return true, nil
	}
	return false, nil
}

func doesErrorMeanNoConnectivity(commandOutput string, protocol corev1.Protocol) bool {
	switch protocol {
	case corev1.ProtocolTCP:
		if strings.Contains(commandOutput, "Ncat: Connection timed out") {
			// Timeout error is symptom of no connection
			return true
		}
	case corev1.ProtocolSCTP:
		if strings.Contains(commandOutput, "Ncat: Connection timed out") {
			// Timeout error is symptom of no connection
			return true
		}
	case corev1.ProtocolUDP:
		if strings.Contains(commandOutput, "Ncat: Connection refused") {
			return true
		}
	}

	return false
}
func getIPTables(pod *corev1.Pod) string {
	containerName, err := findContainerNameByImage(pod, debugIPTablesImage)
	if err != nil {
		return " can't get iptables information: " + err.Error()
	}

	output, err := execCommandInPod(*pod, containerName, []string{"iptables", "-L", "-v", "-n"})
	if err != nil {
		return "<err: " + err.Error() + ">"
	}

	return output.String()
}

func getMultusNicIP(pod *corev1.Pod, ipFamily corev1.IPFamily) string {
	ips, err := getNicIPs(pod, "net1")
	if err != nil {
		return "<err: " + err.Error() + ">"
	}

	if len(ips) == 0 {
		return "<no IPs>"
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)

		if ipFamily == corev1.IPv4Protocol && ip.To4() != nil {
			return ipStr
		}

		if ipFamily == corev1.IPv6Protocol && ip.To4() == nil {
			return ipStr
		}
	}

	return "<no IP for " + string(ipFamily) + ">"
}

func getNicIPs(pod *corev1.Pod, ifcName string) ([]string, error) {

	networksStatus, ok := pod.ObjectMeta.Annotations["k8s.v1.cni.cncf.io/networks-status"]
	if !ok {
		return nil, fmt.Errorf("cannot get networks status from pod [%s] annotation [k8s.v1.cni.cncf.io/networks-status]", pod.Name)
	}

	var nets []nadv1.NetworkStatus
	err := json.Unmarshal([]byte(networksStatus), &nets)
	if err != nil {
		return nil, err
	}

	for _, net := range nets {
		if net.Interface != ifcName {
			continue
		}
		return net.IPs, nil
	}

	return nil, fmt.Errorf("no IP addresses found for interface [%s], pod [%s]", ifcName, pod.Name)
}

func execCommandInPod(pod corev1.Pod, containerName string, command []string) (bytes.Buffer, error) {
	var buf bytes.Buffer
	req := k8sClientSet.CoreV1().RESTClient().
		Post().
		Namespace(pod.Namespace).
		Resource("pods").
		Name(pod.Name).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: containerName,
			Command:   command,
			Stdin:     false,
			Stdout:    true,
			Stderr:    true,
			TTY:       true,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(restConfig, "POST", req.URL())
	if err != nil {
		return buf, fmt.Errorf("cannot create SPDY executor for req %s: %w", req.URL().String(), err)
	}

	err = exec.Stream(remotecommand.StreamOptions{
		Stdout: &buf,
		Stderr: os.Stderr,
		Tty:    true,
	})
	if err != nil {
		return buf, fmt.Errorf("remote command %v error [%w]. output [%s]", command, err, buf.String())
	}

	return buf, nil
}

func getLogsForContainer(p *corev1.Pod, containerName string) (string, error) {
	req := k8sClientSet.CoreV1().Pods(p.Namespace).GetLogs(p.Name, &corev1.PodLogOptions{Container: containerName})
	log, err := req.Stream(context.Background())
	if err != nil {
		return "", fmt.Errorf("cannot get logs for pod %s: %w", p.Name, err)
	}
	defer log.Close()

	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, log)

	if err != nil {
		return "", fmt.Errorf("cannot copy logs to buffer for pod %s: %w", p.Name, err)
	}

	return buf.String(), nil
}

func findContainerNameByImage(pod *corev1.Pod, image string) (string, error) {
	for _, c := range pod.Spec.Containers {
		if c.Image == image {
			return c.Name, nil
		}
	}

	return "", fmt.Errorf("can't find container with image [%s] in pod [%s]", image, pod.Name)
}
