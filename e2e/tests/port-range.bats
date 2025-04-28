#!/usr/bin/env bats

setup() {
	cd $BATS_TEST_DIRNAME
	load "common"
	pod_a_net1=$(get_net1_ip "test-port-range" "pod-a")
	pod_b_net1=$(get_net1_ip "test-port-range" "pod-b")
}

@test "setup environments" {
	# create test manifests
	kubectl create -f port-range.yml

	# verify all pods are available
	run kubectl -n test-port-range wait --for=condition=ready -l app=test-port-range pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]

	sleep 3
}

@test "test-port-range check pod-a -> pod-b 5555 OK" {
	# nc should succeed from client-a to server by policy
	run kubectl -n test-port-range exec pod-a -- sh -c "echo x | nc -w 1 ${pod_b_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "test-port-range check pod-a -> pod-b 6666 KO" {
	# nc should succeed from client-a to server by policy
	run kubectl -n test-port-range exec pod-a -- sh -c "echo x | nc -w 1 ${pod_b_net1} 6666"
	[ "$status" -eq  "1" ]
}

@test "test-port-range check pod-b -> pod-a 5555 KO" {
	# nc should succeed from client-a to server by policy
	run kubectl -n test-port-range exec pod-b -- sh -c "echo x | nc -w 1 ${pod_a_net1} 5555"
	[ "$status" -eq  "1" ]
}

@test "test-port-range check pod-b -> pod-a 6666 OK" {
	# nc should succeed from client-a to server by policy
	run kubectl -n test-port-range exec pod-b -- sh -c "echo x | nc -w 1 ${pod_a_net1} 6666"
	[ "$status" -eq  "0" ]
}

@test "cleanup environments" {
	# remove test manifests
	kubectl delete -f port-range.yml
	run kubectl -n test-port-range wait --for=delete -l app=test-port-range pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]
}
