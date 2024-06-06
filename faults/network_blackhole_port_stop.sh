#!/usr/bin/bash

function assert_argument {
    if [ "$1" = "" ] ; then echo "Argument $2 is required" ; exit 1 ; fi
}

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --traffic-type) TRAFFIC="$2"; shift ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

assert_argument "$TRAFFIC" "--traffic-type";

echo "Rolling back..."

if [ "${TRAFFIC}" = "egress" ]; then
    CHAIN_NAME="fault-out"
    IPTABLES_DELETE="OUTPUT"
elif [ "${TRAFFIC}" = "ingress" ] ; then
    CHAIN_NAME="fault-in"
    IPTABLES_DELETE="INPUT"
fi

iptables -F "$CHAIN_NAME"
iptables -D "$IPTABLES_DELETE" -j "$CHAIN_NAME"
iptables -X "$CHAIN_NAME"
