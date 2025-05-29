//go:build linux
// +build linux

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

package netconfig

import (
	"fmt"
	"net"

	"github.com/aws/amazon-ecs-agent/ecs-agent/logger"
	"github.com/aws/amazon-ecs-agent/ecs-agent/logger/field"
	"github.com/aws/amazon-ecs-agent/ecs-agent/utils/netlinkwrapper"
	"github.com/aws/amazon-ecs-agent/ecs-agent/utils/netwrapper"

	"github.com/vishvananda/netlink"
)

type NetworkConfigClient struct {
	NetlinkClient netlinkwrapper.NetLink
	NetClient     netwrapper.Net
}

func NewNetworkConfigClient() *NetworkConfigClient {
	return &NetworkConfigClient{
		NetlinkClient: netlinkwrapper.New(),
		NetClient:     netwrapper.NewNet(),
	}
}

// DefaultNetInterfaceName returns the device name of the first default network interface
// available on the instance. If none exist, an empty string and nil will be returned.
func DefaultNetInterfaceName(netlinkClient netlinkwrapper.NetLink) (string, error) {
	routes, err := netlinkClient.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return "", err
	}

	// Iterate over all routes
	for _, route := range routes {
		logger.Debug("Found route", logger.Fields{"Route": route})
		if route.Gw == nil {
			// A default route has a gateway. If it doesn't, skip it.
			continue
		}

		if route.Dst == nil || route.Dst.String() == "0.0.0.0/0" || route.Dst.String() == "::/0" {
			// Get the link (interface) associated with the default route
			link, err := netlinkClient.LinkByIndex(route.LinkIndex)
			if err != nil {
				logger.Warn("Not able to get the associated network interface by the index", logger.Fields{
					field.Error: err,
					"LinkIndex": route.LinkIndex,
				})
			} else {
				logger.Debug("Found the associated network interface by the index", logger.Fields{
					"LinkName":  link.Attrs().Name,
					"LinkIndex": route.LinkIndex,
				})
				return link.Attrs().Name, nil
			}
		}
	}
	return "", nil
}

// GetInterfaceGlobalIPAddresses returns all global unicast IP addresses (IPv4 followed by IPv6)
// assigned to the given network interface. It excludes link-local, loopback, multicast,
// and unspecified addresses. Returns an empty list if no global unicast addresses are found,
// or an error if the interface cannot be accessed.
func GetInterfaceGlobalIPAddresses(nw netwrapper.Net, ifaceName string) ([]string, []string, error) {
	ipAddrs, err := getInterfaceIPAddrs(nw, ifaceName)
	if err != nil {
		return nil, nil, err
	}

	return stringifyIPAddrs(filterIPv4GlobalUnicast(ipAddrs)),
		stringifyIPAddrs(filterIPv6GlobalUnicast(ipAddrs)),
		nil
}

// filterIPv4GlobalUnicast filters Global Unicast IPv4 addresses.
func filterIPv4GlobalUnicast(ipAddrs []net.IP) []net.IP {
	var ipv4Addrs []net.IP
	for _, ipAddr := range ipAddrs {
		if isIPv4GlobalUnicast(ipAddr) {
			ipv4Addrs = append(ipv4Addrs, ipAddr)
		}
	}
	return ipv4Addrs
}

// filterIPv6GlobalUnicast filters Global Unicast IPv6 addresses.
func filterIPv6GlobalUnicast(ipAddrs []net.IP) []net.IP {
	var ipv6Addrs []net.IP
	for _, ipAddr := range ipAddrs {
		if isIPv6GlobalUnicast(ipAddr) {
			ipv6Addrs = append(ipv6Addrs, ipAddr)
		}
	}
	return ipv6Addrs
}

// isIPv4GlobalUnicast checks if the passed IP is an IPv4 Global Unicast address.
func isIPv4GlobalUnicast(ipAddr net.IP) bool {
	return ipAddr.IsGlobalUnicast() && ipAddr.To4() != nil
}

// isIPv6GlobalUnicast checks if the passed IP is an IPv6 Global Unicast address.
func isIPv6GlobalUnicast(ipAddr net.IP) bool {
	return ipAddr.IsGlobalUnicast() && ipAddr.To4() == nil
}

// getInterfaceIPAddrs returns all IP addresses associated with a network interface that has
// the provided name.
func getInterfaceIPAddrs(nw netwrapper.Net, interfaceName string) ([]net.IP, error) {
	iface, err := nw.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface by name '%s': %w", interfaceName, err)
	}

	allAddrs, err := nw.Addrs(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses for interface '%s': %w", interfaceName, err)
	}

	return filterIPAddrs(allAddrs), nil
}

// filterIPAddrs filters IP addresses from a list of network addresses.
func filterIPAddrs(addrs []net.Addr) []net.IP {
	var ips []net.IP
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ips = append(ips, ipNet.IP)
	}
	return ips
}

// stringifyIPAddrs stringifies a slice of IP addresses.
func stringifyIPAddrs(addrs []net.IP) []string {
	var strs []string
	for _, addr := range addrs {
		strs = append(strs, addr.String())
	}
	return strs
}
