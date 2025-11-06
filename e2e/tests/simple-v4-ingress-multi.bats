#!/usr/bin/env bats

# Note:
# These test cases, simple, will create simple (one policy for ingress) and test the 
# traffic policying by ncat (nc) command. In addition, these cases also verifies that
# simple iptables generation check by iptables-save and pod-iptable in multi-networkpolicy pod.

setup() {
	cd $BATS_TEST_DIRNAME
	load "common"
	server_net1=$(get_net1_ip "test-simple-v4-ingress-multi" "pod-server")
	client_a_net1=$(get_net1_ip "test-simple-v4-ingress-multi" "pod-client-a")
	client_b_net1=$(get_net1_ip "test-simple-v4-ingress-multi" "pod-client-b")

	server_net2=$(get_net2_ip "test-simple-v4-ingress-multi" "pod-server")
	client_a_net2=$(get_net2_ip "test-simple-v4-ingress-multi" "pod-client-a")
	client_b_net2=$(get_net2_ip "test-simple-v4-ingress-multi" "pod-client-b")
}

@test "setup simple test environments" {
	# create test manifests
	kubectl create -f simple-v4-ingress-multi.yml

	# verify all pods are available
	run kubectl -n test-simple-v4-ingress-multi wait --for=condition=ready -l app=test-simple-v4-ingress-multi pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]

	# wait for sync
	sleep 10
}

@test "check generated nft rules" {
	# check pod-server has multi-networkpolicy iptables rules for ingress
	run kubectl -n test-simple-v4-ingress-multi exec pod-server -- sh -c "nft list ruleset | grep multi-ingress-0"
	[ "$status" -eq  "0" ]
	# check pod-client-a has NO multi-networkpolicy iptables rules for ingress
	run kubectl -n test-simple-v4-ingress-multi exec pod-client-a -- sh -c "nft list ruleset | grep multi-ingress-0"
	[ "$status" -eq  "1" ]
	# check pod-client-b has NO multi-networkpolicy iptables rules for ingress
	run kubectl -n test-simple-v4-ingress-multi exec pod-client-b -- sh -c "nft list ruleset | grep multi-ingress-0"
	[ "$status" -eq  "1" ]

	run kubectl -n test-simple-v4-ingress-multi exec pod-server -- sh -c "nft list ruleset | grep multi-ingress-1"
	[ "$status" -eq  "0" ]
	# check pod-client-a has NO multi-networkpolicy iptables rules for ingress
	run kubectl -n test-simple-v4-ingress-multi exec pod-client-a -- sh -c "nft list ruleset | grep multi-ingress-1"
	[ "$status" -eq  "1" ]
	# check pod-client-b has NO multi-networkpolicy iptables rules for ingress
	run kubectl -n test-simple-v4-ingress-multi exec pod-client-b -- sh -c "nft list ruleset | grep multi-ingress-1"
	[ "$status" -eq  "1" ]
}

### test net1

@test "test-simple-v4-ingress-multi check server -> client-a on net1" {
	# nc should succeed from server to client-a by no policy definition for direction (egress for pod-server)
	run kubectl -n test-simple-v4-ingress-multi exec pod-server -- sh -c "echo x | nc -w 1 ${client_a_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "test-simple-v4-ingress-multi check server -> client-b on net1" {
	# nc should succeed from server to client-b by no policy definition for direction (egress for pod-server)
	run kubectl -n test-simple-v4-ingress-multi exec pod-server -- sh -c "echo x | nc -w 1 ${client_b_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "test-simple-v4-ingress-multi check client-a -> server on net1" {
	# nc should succeed from client-a to server by policy
	run kubectl -n test-simple-v4-ingress-multi exec pod-client-a -- sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "test-simple-v4-ingress-multi check client-b -> server on net1" {
	# nc should NOT succeed from client-b to server by policy
	run kubectl -n test-simple-v4-ingress-multi exec pod-client-b -- sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq  "1" ]
}

### test net2

@test "test-simple-v4-ingress-multi check server -> client-a on net2" {
	# nc should succeed from server to client-a by no policy definition for direction (egress for pod-server)
	run kubectl -n test-simple-v4-ingress-multi exec pod-server -- sh -c "echo x | nc -w 1 ${client_a_net2} 5555"
	[ "$status" -eq  "0" ]
}

@test "test-simple-v4-ingress-multi check server -> client-b on net2" {
	# nc should succeed from server to client-b by no policy definition for direction (egress for pod-server)
	run kubectl -n test-simple-v4-ingress-multi exec pod-server -- sh -c "echo x | nc -w 1 ${client_b_net2} 5555"
	[ "$status" -eq  "0" ]
}

@test "test-simple-v4-ingress-multi check client-a -> server on net2" {
	# nc should NOT succeed from client-a to server by policy
	run kubectl -n test-simple-v4-ingress-multi exec pod-client-a -- sh -c "echo x | nc -w 1 ${server_net2} 5555"
	[ "$status" -eq  "1" ]
}

@test "test-simple-v4-ingress-multi check client-b -> server on net2" {
	# nc should succeed from client-b to server by policy
	run kubectl -n test-simple-v4-ingress-multi exec pod-client-b -- sh -c "echo x | nc -w 1 ${server_net2} 5555"
	[ "$status" -eq  "0" ]
}


@test "disable multi-networkpolicy and check iptables rules" {
 	# disable multi-networkpolicy pods by adding invalid nodeSelector
	kubectl -n kube-system patch daemonsets multi-networkpolicy-ds-amd64 -p '{"spec": {"template": {"spec": {"nodeSelector": {"non-existing": "true"}}}}}'
	# check multi-networkpolicy pod is deleted
	kubectl -n kube-system wait --for=delete -l app=multi-networkpolicy pod --timeout=${kubewait_timeout}

	# check nft rules in pod-server
	run kubectl -n test-simple-v4-ingress-multi exec pod-server -it -- sh -c "nft list ruleset | grep multi-ingress-0"
	[ "$status" -eq  "1" ]
	run kubectl -n test-simple-v4-ingress-multi exec pod-server -it -- sh -c "nft list ruleset | grep multi-ingress-1"
	[ "$status" -eq  "1" ]

	# enable multi-networkpolicy again
	kubectl -n kube-system patch daemonsets multi-networkpolicy-ds-amd64 --type json -p='[{"op": "remove", "path": "/spec/template/spec/nodeSelector/non-existing"}]'
	sleep 5
	kubectl -n kube-system wait --for=condition=ready -l app=multi-networkpolicy pod --timeout=${kubewait_timeout}
}

@test "cleanup environments" {
	# remove test manifests
	kubectl delete -f simple-v4-ingress-multi.yml
	run kubectl -n test-simple-v4-ingress-multi wait --for=delete -l app=test-simple-v4-ingress-multi pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]
}
