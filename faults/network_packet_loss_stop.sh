#!/usr/bin/bash

set -x

function assert_argument {
    if [ "$1" = "" ] ; then echo "Argument $2 is required" ; exit 1 ; fi
}

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --interface) INTERFACE="$2"; shift ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

assert_argument "$INTERFACE" "--interface";

echo "Rolling back..."
tc qdisc del dev "$INTERFACE" parent 1:1 handle 10:
tc filter del dev "$INTERFACE" prio 1
tc qdisc del dev "$INTERFACE" root handle 1: prio
