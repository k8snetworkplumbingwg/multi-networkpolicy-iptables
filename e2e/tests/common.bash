# Common code for bats

kubewait_timeout=300s

get_net1_ip() {
	if [ "$#" == "2" ]; then
		echo $(kubectl exec -n $1 "$2" -- ip -j a show  | jq -r \
			 '.[]|select(.ifname =="net1")|.addr_info[]|select(.family=="inet").local')
	else
		echo "unknown ip $1"
	fi
}

get_net1_ip6() {
	if [ "$#" == "2" ]; then
		echo $(kubectl exec -n $1 "$2" -- ip -j a show  | jq -r \
			 '.[]|select(.ifname =="net1")|.addr_info[]|select(.family=="inet6" and .scope=="global").local')
	else
		echo "unknown ip $1"
	fi
}
