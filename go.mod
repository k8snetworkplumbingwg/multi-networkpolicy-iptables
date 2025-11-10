module github.com/k8snetworkplumbingwg/multi-networkpolicy-iptables

go 1.24.0

require (
	github.com/containernetworking/cni v0.8.1
	github.com/containernetworking/plugins v0.8.6
	github.com/k8snetworkplumbingwg/multi-networkpolicy v1.0.1
	github.com/k8snetworkplumbingwg/network-attachment-definition-client v0.0.0-20200528071255-22c819bc6e7e
	github.com/onsi/ginkgo v1.16.4
	github.com/onsi/gomega v1.35.1
	github.com/spf13/cobra v1.9.1
	github.com/spf13/pflag v1.0.6
	google.golang.org/grpc v1.72.1
	k8s.io/api v0.34.1
	k8s.io/apimachinery v0.34.1
	k8s.io/client-go v0.34.1
	k8s.io/component-helpers v0.34.1
	k8s.io/cri-api v0.34.1
	k8s.io/klog v1.0.0
	k8s.io/kubernetes v1.34.1
	k8s.io/utils v0.0.0-20250604170112-4c0f3b243397
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/cyphar/filepath-securejoin v0.4.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/emicklei/go-restful/v3 v3.12.2 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-openapi/jsonpointer v0.21.0 // indirect
	github.com/go-openapi/jsonreference v0.20.2 // indirect
	github.com/go-openapi/swag v0.23.0 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/gnostic-models v0.7.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/moby/sys/mountinfo v0.7.2 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/nxadm/tail v1.4.8 // indirect
	github.com/opencontainers/cgroups v0.0.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_golang v1.22.0 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.62.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.opentelemetry.io/otel v1.35.0 // indirect
	go.opentelemetry.io/otel/trace v1.35.0 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/oauth2 v0.27.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
	golang.org/x/term v0.30.0 // indirect
	golang.org/x/text v0.23.0 // indirect
	golang.org/x/time v0.9.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250303144028-a0af3efb3deb // indirect
	google.golang.org/protobuf v1.36.5 // indirect
	gopkg.in/evanphx/json-patch.v4 v4.12.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/apiextensions-apiserver v0.34.1 // indirect
	k8s.io/apiserver v0.34.1 // indirect
	k8s.io/component-base v0.34.1 // indirect
	k8s.io/controller-manager v0.0.0 // indirect
	k8s.io/klog/v2 v2.130.1 // indirect
	k8s.io/kube-openapi v0.0.0-20250710124328-f3f2b991d03b // indirect
	sigs.k8s.io/json v0.0.0-20241014173422-cfa47c3a1cc8 // indirect
	sigs.k8s.io/randfill v1.0.0 // indirect
	sigs.k8s.io/structured-merge-diff/v6 v6.3.0 // indirect
	sigs.k8s.io/yaml v1.6.0 // indirect
)

replace (
	github.com/gogo/protobuf => github.com/gogo/protobuf v1.3.2
	golang.org/x/net => golang.org/x/net v0.17.0
	golang.org/x/text => golang.org/x/text v0.3.8
	k8s.io/api => k8s.io/api v0.34.1
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.34.1
	k8s.io/apimachinery => k8s.io/apimachinery v0.34.1
	k8s.io/apiserver => k8s.io/apiserver v0.34.1
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.34.1
	k8s.io/client-go => k8s.io/client-go v0.34.1
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.34.1
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.34.1
	k8s.io/code-generator => k8s.io/code-generator v0.34.1
	k8s.io/component-base => k8s.io/component-base v0.34.1
	k8s.io/component-helpers => k8s.io/component-helpers v0.34.1
	k8s.io/controller-manager => k8s.io/controller-manager v0.34.1
	k8s.io/cri-api => k8s.io/cri-api v0.34.1
	k8s.io/cri-client => k8s.io/cri-client v0.34.0
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.34.1
	k8s.io/dynamic-resource-allocation => k8s.io/dynamic-resource-allocation v0.34.1
	k8s.io/endpointslice => k8s.io/endpointslice v0.34.1
	k8s.io/kms => k8s.io/kms v0.34.1
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.34.1
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.34.1
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.34.1
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.34.1
	k8s.io/kubectl => k8s.io/kubectl v0.34.1
	k8s.io/kubelet => k8s.io/kubelet v0.34.1
	k8s.io/kubernetes => k8s.io/kubernetes v1.34.1
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.34.1
	k8s.io/metrics => k8s.io/metrics v0.34.1
	k8s.io/mount-utils => k8s.io/mount-utils v0.34.1
	k8s.io/pod-security-admission => k8s.io/pod-security-admission v0.34.1
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.34.1
)
