#!/usr/bin/env bats

# Note:
# These test cases, simple, will create simple (one policy for ingress) and test the 
# traffic policying by ncat (nc) command. In addition, these cases also verifies that
# simple iptables generation check by iptables-save and pod-iptable in multi-networkpolicy pod.

setup() {
	cd $BATS_TEST_DIRNAME
	load "common"
	pod_a_net1=$(get_net1_ip "test-protocol-only-ports" "pod-a")
	pod_b_net1=$(get_net1_ip "test-protocol-only-ports" "pod-b")
}

@test "setup environments" {
	# create test manifests
	kubectl create -f protocol-only-ports.yml

	# verify all pods are available
	run kubectl -n test-protocol-only-ports wait --for=condition=ready -l app=test-protocol-only-ports pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]

	sleep 3
}

@test "test-protocol-only-ports check pod-a -> pod-b TCP" {
	# nc should succeed from client-a to server by policy
	run kubectl -n test-protocol-only-ports exec pod-a -- sh -c "echo x | nc -w 1 ${pod_b_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "test-protocol-only-ports check pod-a -> pod-b UDP" {
	# nc should succeed from client-a to server by policy
	run kubectl -n test-protocol-only-ports exec pod-a -- sh -c "echo x | nc --udp -w 1 ${pod_b_net1} 6666"
	[ "$status" -eq  "1" ]
}

@test "test-protocol-only-ports check pod-b -> pod-a TCP" {
	# nc should succeed from client-a to server by policy
	run kubectl -n test-protocol-only-ports exec pod-b -- sh -c "echo x | nc -w 1 ${pod_a_net1} 5555"
	[ "$status" -eq  "1" ]
}

@test "test-protocol-only-ports check pod-b -> pod-a UDP" {
	# nc should succeed from client-a to server by policy
	run kubectl -n test-protocol-only-ports exec pod-b -- sh -c "echo x | nc --udp -w 1 ${pod_a_net1} 6666"
	[ "$status" -eq  "0" ]
}

@test "cleanup environments" {
	# remove test manifests
	kubectl delete -f protocol-only-ports.yml
	run kubectl -n test-protocol-only-ports wait --for=delete -l app=test-protocol-only-ports pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]
}
