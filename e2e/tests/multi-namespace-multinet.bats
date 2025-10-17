#!/usr/bin/env bats

# Note:
# This test case creates two namespaces, each with a different NetworkAttachmentDefinition
# and two pods per namespace. It tests that MultiNetworkPolicy works correctly across
# different namespaces with different network configurations.

setup() {
	cd $BATS_TEST_DIRNAME
	load "common"
	pod_a1_net1=$(get_net1_ip "test-namespace-a" "pod-a-1")
	pod_a2_net1=$(get_net1_ip "test-namespace-a" "pod-a-2")

	pod_b1_net1=$(get_net1_ip "test-namespace-b" "pod-b-1")
	pod_b2_net1=$(get_net1_ip "test-namespace-b" "pod-b-2")
	
}

@test "setup multi-namespace test environments" {
	# create test manifests
	kubectl create -f multi-namespace-multinet.yml

	# verify all pods in namespace A are available
	run kubectl -n test-namespace-a wait --all --for=condition=ready pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]
	
	# verify all pods in namespace B are available
	run kubectl -n test-namespace-b wait --all --for=condition=ready pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]

	# wait for the iptables to be synced
	sleep 3
}

@test "Allowed connectivity" {
	run kubectl -n test-namespace-b exec pod-b-1 -- sh -c "echo x | nc -w 1 ${pod_a1_net1} 5555"
	[ "$status" -eq  "0" ]

	run kubectl -n test-namespace-a exec pod-a-1 -- sh -c "echo x | nc -w 1 ${pod_b2_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "Denied connectivity" {
	run kubectl -n test-namespace-a exec pod-a-1 -- sh -c "echo x | nc -w 1 ${pod_a2_net1} 5555"
	[ "$status" -eq  "1" ]
	
	run kubectl -n test-namespace-a exec pod-a-1 -- sh -c "echo x | nc -w 1 ${pod_b1_net1} 5555"
	[ "$status" -eq  "1" ]

	run kubectl -n test-namespace-b exec pod-a-2 -- sh -c "echo x | nc -w 1 ${pod_a1_net1} 5555"
	[ "$status" -eq  "1" ]

	run kubectl -n test-namespace-b exec pod-b-2 -- sh -c "echo x | nc -w 1 ${pod_a1_net1} 5555"
	[ "$status" -eq  "1" ]
}

@test "Allowed by policy absence" {
	run kubectl -n test-namespace-a exec pod-a-2 -- sh -c "echo x | nc -w 1 ${pod_b1_net1} 5555"
	[ "$status" -eq  "0" ]

	run kubectl -n test-namespace-b exec pod-b-1 -- sh -c "echo x | nc -w 1 ${pod_a2_net1} 5555"
	[ "$status" -eq  "0" ]

	run kubectl -n test-namespace-a exec pod-a-2 -- sh -c "echo x | nc -w 1 ${pod_b2_net1} 5555"
	[ "$status" -eq  "0" ]

	run kubectl -n test-namespace-b exec pod-b-1 -- sh -c "echo x | nc -w 1 ${pod_b2_net1} 5555"
	[ "$status" -eq  "0" ]

	run kubectl -n test-namespace-b exec pod-b-1 -- sh -c "echo x | nc -w 1 ${pod_b2_net1} 5555"
	[ "$status" -eq  "0" ]

	run kubectl -n test-namespace-b exec pod-b-2 -- sh -c "echo x | nc -w 1 ${pod_b1_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "cleanup environments" {
	# remove test manifests
	kubectl delete -f multi-namespace-multinet.yml
	run kubectl -n test-namespace-a wait --all --for=delete pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]
	run kubectl -n test-namespace-b wait --all --for=delete pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]

	sleep 5
}
