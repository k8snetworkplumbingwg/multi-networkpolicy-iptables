#!/usr/bin/env bats

setup() {
	cd $BATS_TEST_DIRNAME
	load "common"
	pod_a_net1=$(get_net1_ip "bond-testing" "pod-a")
	pod_b_net1=$(get_net1_ip "bond-testing" "pod-b")
	pod_c_net1=$(get_net1_ip "bond-testing" "pod-c")
}

@test "setup resources" {
	# create test manifests
	kubectl create -f bond-cni.yml

	# verify all pods are available
	run kubectl -n bond-testing wait --for=condition=ready -l app=bond-testing pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]

	# wait for sync
	sleep 5
}

@test "bond-testing check pod-b -> pod-a" {
	run kubectl -n bond-testing exec pod-b -- sh -c "echo x | nc -w 1 ${pod_a_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "bond-testing check pod-c -> pod-a" {
	run kubectl -n bond-testing exec pod-c -- sh -c "echo x | nc -w 1 ${pod_a_net1} 5555"
	[ "$status" -eq  "1" ]
}

@test "bond-testing check pod-a -> pod-b" {
	run kubectl -n bond-testing exec pod-a -- sh -c "echo x | nc -w 1 ${pod_b_net1} 5555"
	[ "$status" -eq  "1" ]
}

@test "bond-testing check pod-a -> pod-c" {
	run kubectl -n bond-testing exec pod-a -- sh -c "echo x | nc -w 1 ${pod_c_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "cleanup environments" {
	# remove test manifests
	kubectl delete -f bond-cni.yml
	run kubectl -n bond-testing wait --for=delete -l app=bond-testing pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]

	sleep 5
}
