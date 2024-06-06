#!/usr/bin/bash

set -x

function assert_argument {
    if [ "$1" = "" ] ; then echo "Argument $2 is required" ; exit 1 ; fi
}

function generate_assert_fault_running_command {
    # $1    -   Interface
    echo "tc q | grep netem | grep $1 | grep loss"
}

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --loss-percent) LOSS="$2"; shift ;;
        --interface) INTERFACE="$2"; shift ;;
        --sources) SOURCES="$2"; shift ;;
        --region-name) REGION="$2"; shift ;;
        --assertion-script-path) ASSERTION_SCRIPT_PATH="$2"; shift ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

assert_argument "$LOSS" "--loss-percent";
assert_argument "$INTERFACE" "--interface";
assert_argument "$SOURCES" "--sources";
assert_argument "$REGION" "--region-name";
assert_argument "$ASSERTION_SCRIPT_PATH" "--assertion-script-path";

if [ "$(tc q | grep netem)" ] ; then
  echo "Cannot start fault. Qdisc 'netem' already exists."
  exit 16
fi

if ! [ "$( ip a ls "$INTERFACE" 2>/dev/null )" ] ; then
  echo "Interface $INTERFACE does not exist."
  exit 1
fi

IP_CIDR_REGEX="^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2][0-9]|[0-9]))$"
IP_REGEX="^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"

get_ips()
{
    # Returns if the input is a valid IP/CIDR string, empty otherwise
    local var_ip_cidr=$(grep -E "$IP_CIDR_REGEX" <<< "$1")
    [  -z "$var_ip_cidr" ] || { echo "$var_ip_cidr" ; return ;}

    # Returns if the input is a valid IP string, empty otherwise
    local var_ip=$(grep -E "$IP_REGEX" <<< "$1")
    [  -z "$var_ip" ] || { echo "$var_ip" ; return ;}


    # Returns IPs of the domain and force DNS resolution to that IP, empty otherwise
    # Since `dig` can return different IPs, we call it 10 times to maximize
    # the chances of covering as many IPs as possible for the provided domain
    local var_dns=()
    for i in $(seq 1 10)
    do
        dig_output=( $(dig +short $1 | grep -v '[[:alpha:]]') )
        var_dns=("${var_dns[@]}" "${dig_output[@]}")
    done
    var_unique_dns=( $(printf '%s\n' "${var_dns[@]}" | sort -u) )
    [  -z "$var_unique_dns" ] || { echo "${var_unique_dns[@]}" ; return ;}

    # Only accepting DYNAMODB and S3 from ip-range service
    if [[ "$1" =~ ^("DYNAMODB"|"S3")$ ]]; then
      # Return IPS of the Service, empty otherwise
      curl -s https://ip-ranges.amazonaws.com/ip-ranges.json --connect-timeout 5 | jq -r '.prefixes[] | select(.region=="'$REGION'") | select(.service=="'$1'") | .ip_prefix'
    fi
}

IP_ADDRESSES=()
for source in ${SOURCES//,/ }
do
    ips=$(get_ips "$source")
    if [ -n "$ips" ]; then
      for ip in ${ips[*]}
        do
        IP_ADDRESSES=("${IP_ADDRESSES[@]}" "${ip}")
      done
    else
        INVALID_SOURCE=("${INVALID_SOURCE[@]}" "${source}")
    fi
done

if [ -n "$INVALID_SOURCE" ]; then
  echo "Invalid sources (malformed service name, DNS or IP address): ${INVALID_SOURCE[*]}"
  exit 1
fi

tc qdisc add dev "$INTERFACE" root handle 1: prio priomap 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2
# Creates the qdisc in the band 0, but since all traffic goes to band 3, it does not affect it
tc qdisc add dev "$INTERFACE" parent 1:1 handle 10: netem loss "${LOSS}"%
for k in ${IP_ADDRESSES[*]}; do
    # Redirect the matching ip addresses to the band 0
    tc filter add dev "$INTERFACE" protocol ip parent 1:0 prio 1 u32 match ip dst "$k" flowid 1:1
done

# Generate assertion command
generate_assert_fault_running_command $INTERFACE > $ASSERTION_SCRIPT_PATH
chmod +x "$ASSERTION_SCRIPT_PATH"
