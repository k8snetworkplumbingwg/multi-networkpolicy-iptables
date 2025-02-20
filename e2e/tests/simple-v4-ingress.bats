#!/usr/bin/env bats

# Note:
# These test cases, simple, will create simple (one policy for ingress) and test the 
# traffic policying by ncat (nc) command. In addition, these cases also verifies that
# simple iptables generation check by iptables-save and pod-iptable in multi-networkpolicy pod.

setup() {
	cd $BATS_TEST_DIRNAME
	load "common"
	server_net1=$(get_net1_ip "test-simple-v4-ingress" "pod-server")
	client_a_net1=$(get_net1_ip "test-simple-v4-ingress" "pod-client-a")
	client_b_net1=$(get_net1_ip "test-simple-v4-ingress" "pod-client-b")
}

@test "setup simple test environments" {
	# create test manifests
	kubectl create -f simple-v4-ingress.yml

	# verify all pods are available
	run kubectl -n test-simple-v4-ingress wait --for=condition=ready -l app=test-simple-v4-ingress pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]
}

@test "check generated iptables rules" {
	# wait for sync
	sleep 5
	# check pod-server has multi-networkpolicy iptables rules for ingress
        run kubectl -n test-simple-v4-ingress exec pod-server -- sh -c "iptables-save | grep MULTI-0-INGRESS"
	[ "$status" -eq  "0" ]
	# check pod-client-a has NO multi-networkpolicy iptables rules for ingress
        run kubectl -n test-simple-v4-ingress exec pod-client-a -- sh -c "iptables-save | grep MULTI-0-INGRESS"
	[ "$status" -eq  "1" ]
	# check pod-client-b has NO multi-networkpolicy iptables rules for ingress
        run kubectl -n test-simple-v4-ingress exec pod-client-b -- sh -c "iptables-save | grep MULTI-0-INGRESS"
	[ "$status" -eq  "1" ]
}

@test "test-simple-v4-ingress check client-a -> server" {
	# nc should succeed from client-a to server by policy
	run kubectl -n test-simple-v4-ingress exec pod-client-a -- sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "test-simple-v4-ingress check client-b -> server" {
	# nc should NOT succeed from client-b to server by policy
	run kubectl -n test-simple-v4-ingress exec pod-client-b -- sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq  "1" ]
}

@test "test-simple-v4-ingress check server -> client-a" {
	# nc should succeed from server to client-a by no policy definition for direction (egress for pod-server)
	run kubectl -n test-simple-v4-ingress exec pod-server -- sh -c "echo x | nc -w 1 ${client_a_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "test-simple-v4-ingress check server -> client-b" {
	# nc should succeed from server to client-b by no policy definition for direction (egress for pod-server)
	run kubectl -n test-simple-v4-ingress exec pod-server -- sh -c "echo x | nc -w 1 ${client_b_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "disable multi-networkpolicy and check iptables rules" {
 	# disable multi-networkpolicy pods by adding invalid nodeSelector
	kubectl -n kube-system patch daemonsets multi-networkpolicy-ds-amd64 -p '{"spec": {"template": {"spec": {"nodeSelector": {"non-existing": "true"}}}}}'
	# check multi-networkpolicy pod is deleted
	kubectl -n kube-system wait --for=delete -l app=multi-networkpolicy pod --timeout=${kubewait_timeout}

	# check iptable rules in pod-server
        run kubectl -n test-simple-v4-ingress exec pod-server -it -- sh -c "iptables-save | grep MULTI-0-INGRESS"
	[ "$status" -eq  "1" ]

	# enable multi-networkpolicy again
	kubectl -n kube-system patch daemonsets multi-networkpolicy-ds-amd64 --type json -p='[{"op": "remove", "path": "/spec/template/spec/nodeSelector/non-existing"}]'
	sleep 5
	kubectl -n kube-system wait --for=condition=ready -l app=multi-networkpolicy pod --timeout=${kubewait_timeout}
}

@test "cleanup environments" {
	# remove test manifests
	kubectl delete -f simple-v4-ingress.yml
	run kubectl -n test-simple-v4-ingress wait --for=delete -l app=test-simple-v4-ingress pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]
}
