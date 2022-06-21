package test

import (
	"flag"
	"os"
	"testing"

	multinetpolicyclientv1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/client/clientset/versioned/typed/k8s.cni.cncf.io/v1beta1"
	netdefclientv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/typed/k8s.cni.cncf.io/v1"

	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type ClientSet struct {
	coreclient.CoreV1Interface
	multinetpolicyclientv1.K8sCniCncfIoV1beta1Interface
	netdefclientv1.K8sCniCncfIoV1Interface
}

var (
	cs         *ClientSet
	restConfig *restclient.Config
)

var runE2ETests = flag.Bool("e2e", false, "Run the E2E testsuite")

func TestSuite(t *testing.T) {

	if !*runE2ETests {
		t.Skip("skipping end to end tests")
	}

	var err error
	restConfig, err = clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	if err != nil {
		t.Fatalf("Failed to init kubernetes client, KUBECONFIG=[%s] environment variable: %s", os.Getenv("KUBECONFIG"), err.Error())
	}

	cs = &ClientSet{}
	cs.CoreV1Interface = coreclient.NewForConfigOrDie(restConfig)
	cs.K8sCniCncfIoV1beta1Interface = multinetpolicyclientv1.NewForConfigOrDie(restConfig)
	cs.K8sCniCncfIoV1Interface = netdefclientv1.NewForConfigOrDie(restConfig)

	RegisterFailHandler(Fail)
	RunSpecs(t, "Multus Network Policies Suite")
}
