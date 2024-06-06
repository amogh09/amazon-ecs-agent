// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//	http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package ecscni

import (
	"log"
	"os/exec"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netns"
)

func TestFaultInjection(t *testing.T) {
	log.Println("Test started")
	// Lock the OS Thread so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save the current network namespace
	origns, _ := netns.Get()
	defer func() {
		netns.Set(origns)
		origns.Close()
	}()
	log.Printf("Original NS: %s", origns.UniqueId())

	// netnsPath := fmt.Sprintf(NetnsFormat, "296163")
	netnsPath := "/proc/309124/ns/net"
	targetNS, err := netns.GetFromPath(netnsPath)
	require.NoError(t, err, "failed to find netns at path %s", netnsPath)
	defer targetNS.Close()

	err = netns.Set(targetNS)
	require.NoError(t, err)

	// cmd := exec.Command("../../faults/network_blackhole_port_start.sh",
	// 	"--port", "80",
	// 	"--protocol", "tcp",
	// 	"--traffic-type", "ingress",
	// 	"--assertion-script-path", "/tmp/assertion-script.sh",
	// )
	cmd := exec.Command("../../faults/network_blackhole_port_stop.sh",
		"--traffic-type", "ingress",
	)
	out, err := cmd.CombinedOutput()
	assert.NoError(t, err)
	log.Println("Output: ", string(out))
}
