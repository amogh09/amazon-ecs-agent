#!/usr/bin/bash
set -x

function assert_argument {
    if [ "$1" = "" ] ; then echo "Argument $2 is required" ; exit 1 ; fi
}

function generate_assert_fault_running_command {
    # $1    -   chain name
    # $2    -   protocol
    # $3    -   port
    echo "iptables -nL $1 | grep \"${2} dpt:$3\""
}

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --port) PORT="$2"; shift ;;
        --protocol) PROTOCOL="$2"; shift ;;
        --traffic-type) TRAFFIC="$2"; shift ;;
        --assertion-script-path) ASSERTION_SCRIPT_PATH="$2"; shift ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

assert_argument "$PORT" "--port";
assert_argument "$PROTOCOL" "--protocol";
assert_argument "$TRAFFIC" "--traffic-type";
assert_argument "$ASSERTION_SCRIPT_PATH" "--assertion-script-path";

if [ "${TRAFFIC}" = "egress" ]; then
    CHAIN_NAME="fault-out"
    IPTABLES_INSERT="OUTPUT"
elif [ "${TRAFFIC}" = "ingress" ]; then
    CHAIN_NAME="fault-in"
    IPTABLES_INSERT="INPUT"
fi

# Create new iptables chain
iptables -N "$CHAIN_NAME" || { echo iptables chain already exist, fault might be already running. Exiting... 1>&2 ; exit 16; }
# Block the requested port/protocol
iptables -A "$CHAIN_NAME" -p "${PROTOCOL}" --dport "${PORT}" -j DROP
iptables -I "$IPTABLES_INSERT" -j "$CHAIN_NAME"

# Generate assertion command
generate_assert_fault_running_command "$CHAIN_NAME" "$PROTOCOL" "$PORT" > "$ASSERTION_SCRIPT_PATH"
chmod +x "$ASSERTION_SCRIPT_PATH"
