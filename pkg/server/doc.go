// Copyright (c) 2021 Multus Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package server is the package that contains server functions.
package server

const (
	ingressChain = "multi-ingress"
	egressChain  = "multi-egress"

	// PortsChainSuffix is the suffix for the ports chains
	portsChainSuffix = "ports"

	// peersChainSuffix is the suffix for the peers chains
	peersChainSuffix = "peers"

	common                   = "common"
	destinationAddressSuffix = "daddrs"
	sourceAddressSuffix      = "saddrs"
	podInterfacesName        = "pod_interfaces"
	PolicyNetworkAnnotation  = "k8s.v1.cni.cncf.io/policy-for"
)
