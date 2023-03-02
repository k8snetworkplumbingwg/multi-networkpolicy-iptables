#!/usr/bin/env bats

# Note:
# These test cases, stacked, will create stacked policy rules in one multi-networkpolicy and test the
# traffic policying by ncat (nc) command.

setup() {
	cd $BATS_TEST_DIRNAME
	load "common"

	server_net1=$(get_net1_ip "test-ipblock-stacked" "pod-server")
	client_a_net1=$(get_net1_ip "test-ipblock-stacked" "pod-client-a")
	client_b_net1=$(get_net1_ip "test-ipblock-stacked" "pod-client-b")
	client_c_net1=$(get_net1_ip "test-ipblock-stacked" "pod-client-c")
}

@test "setup stacked test environments" {
	kubectl create -f ipblock-stacked.yml
	run kubectl -n test-ipblock-stacked wait --for=condition=ready -l app=test-ipblock-stacked pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]
}

@test "check generated iptables rules" {
	# wait for sync
	sleep 3
        run kubectl -n test-ipblock-stacked exec pod-server -it -- sh -c "iptables-save | grep MULTI-0-INGRESS"
	[ "$status" -eq  "0" ]
        run kubectl -n test-ipblock-stacked exec pod-client-a -it -- sh -c "iptables-save | grep MULTI-0-INGRESS"
	[ "$status" -eq  "1" ]
        run kubectl -n test-ipblock-stacked exec pod-client-b -it -- sh -c "iptables-save | grep MULTI-0-INGRESS"
	[ "$status" -eq  "1" ]
        run kubectl -n test-ipblock-stacked exec pod-client-c -it -- sh -c "iptables-save | grep MULTI-0-INGRESS"
	[ "$status" -eq  "1" ]
}

@test "test-ipblock-status check client-a" {
	run kubectl -n test-ipblock-stacked exec pod-client-a -- sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "test-ipblock-stacked check client-b" {
	run kubectl -n test-ipblock-stacked exec pod-client-b -- sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "test-ipblock-stacked check client-c" {
	run kubectl -n test-ipblock-stacked exec pod-client-c -- sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq  "1" ]
}

@test "cleanup environments" {
	kubectl delete -f ipblock-stacked.yml
	run kubectl -n test-ipblock-stacked wait --for=delete -l app=test-ipblock-stacked pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]
}
