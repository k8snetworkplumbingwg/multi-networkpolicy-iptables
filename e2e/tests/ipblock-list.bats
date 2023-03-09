#!/usr/bin/env bats

# Note:
# These test cases, stacked, will create stacked policy rules in one multi-networkpolicy and test the
# traffic policying by ncat (nc) command.

setup() {
	cd $BATS_TEST_DIRNAME
	load "common"

	server_net1=$(get_net1_ip "test-ipblock-list" "pod-server")
	client_a_net1=$(get_net1_ip "test-ipblock-list" "pod-client-a")
	client_b_net1=$(get_net1_ip "test-ipblock-list" "pod-client-b")
	client_c_net1=$(get_net1_ip "test-ipblock-list" "pod-client-c")
}

@test "setup ipblock-list test environments" {
	kubectl create -f ipblock-list.yml
	run kubectl -n test-ipblock-list wait --for=condition=ready -l app=test-ipblock-list pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]
}

@test "test-ipblock-list check client-a" {
	run kubectl -n test-ipblock-list exec pod-client-a -- sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "test-ipblock-list check client-b" {
	run kubectl -n test-ipblock-list exec pod-client-b -- sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "test-ipblock-list check client-c" {
	run kubectl -n test-ipblock-list exec pod-client-c -- sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq  "1" ]
}

@test "cleanup environments" {
	kubectl delete -f ipblock-list.yml
	run kubectl -n test-ipblock-list wait --for=delete -l app=test-ipblock-list pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]
}
