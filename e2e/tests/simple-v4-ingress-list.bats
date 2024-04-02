#!/usr/bin/env bats

# Note:
# These test cases, simple, will create simple (one policy for ingress) and test the 
# traffic policying by ncat (nc) command. In addition, these cases also verifies that
# simple iptables generation check by iptables-save and pod-iptable in multi-networkpolicy pod.

setup() {
	cd $BATS_TEST_DIRNAME
	load "common"
	server_net1=$(get_net1_ip "test-simple-v4-ingress-list" "pod-server")
	client_a_net1=$(get_net1_ip "test-simple-v4-ingress-list" "pod-client-a")
	client_b_net1=$(get_net1_ip "test-simple-v4-ingress-list" "pod-client-b")
	client_c_net1=$(get_net1_ip "test-simple-v4-ingress-list" "pod-client-c")
}

@test "setup simple test environments" {
	# create test manifests
	kubectl create -f simple-v4-ingress-list.yml

	# verify all pods are available
	run kubectl -n test-simple-v4-ingress-list wait --for=condition=ready -l app=test-simple-v4-ingress-list pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]

	# wait for sync
	sleep 5
}

@test "test-simple-v4-ingress-list check client-a -> server" {
	# nc should succeed from client-a to server by policy
	run kubectl -n test-simple-v4-ingress-list exec pod-client-a -- sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "test-simple-v4-ingress-list check client-b -> server" {
	# nc should NOT succeed from client-b to server by policy
	run kubectl -n test-simple-v4-ingress-list exec pod-client-b -- sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq  "1" ]
}

@test "test-simple-v4-ingress-list check client-c -> server" {
	# nc should succeed from client-c to server by policy
	run kubectl -n test-simple-v4-ingress-list exec pod-client-c -- sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "test-simple-v4-ingress-list check server -> client-a" {
	# nc should succeed from server to client-a by no policy definition for direction (egress for pod-server)
	run kubectl -n test-simple-v4-ingress-list exec pod-server -- sh -c "echo x | nc -w 1 ${client_a_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "test-simple-v4-ingress-list check server -> client-b" {
	# nc should succeed from server to client-b by no policy definition for direction (egress for pod-server)
	run kubectl -n test-simple-v4-ingress-list exec pod-server -- sh -c "echo x | nc -w 1 ${client_b_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "test-simple-v4-ingress-list check server -> client-c" {
	# nc should succeed from server to client-c by no policy definition for direction (egress for pod-server)
	run kubectl -n test-simple-v4-ingress-list exec pod-server -- sh -c "echo x | nc -w 1 ${client_c_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "cleanup environments" {
	# remove test manifests
	kubectl delete -f simple-v4-ingress-list.yml
	run kubectl -n test-simple-v4-ingress-list wait --for=delete -l app=test-simple-v4-ingress-list pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]
}
