//go:build linux && unit
// +build linux,unit

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
	"errors"
	"fmt"
	"net"
	"reflect"
	"testing"

	mock_netlinkwrapper "github.com/aws/amazon-ecs-agent/ecs-agent/utils/netlinkwrapper/mocks"
	mock_nw "github.com/aws/amazon-ecs-agent/ecs-agent/utils/netwrapper/mocks"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
)

func TestDefaultNetInterfaceName(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	_, allIpNet, err := net.ParseCIDR("0.0.0.0/0")
	assert.NoError(t, err)
	_, randomIpNet, err := net.ParseCIDR("192.168.1.0/24")
	assert.NoError(t, err)

	tcs := []struct {
		name                            string
		routes                          []netlink.Route
		link                            netlink.Link
		expectedDefaultNetInterfaceName string
		expectedErrMsg                  string
	}{
		{
			name: "no default route 1",
			routes: []netlink.Route{
				netlink.Route{
					Gw:        nil,
					Dst:       nil,
					LinkIndex: 0,
				},
			},
			link: &netlink.Device{
				LinkAttrs: netlink.LinkAttrs{
					Index: 0,
					Name:  "eni-0",
				},
			},
			expectedDefaultNetInterfaceName: "",
			expectedErrMsg:                  "",
		},
		{
			name: "no default route 2",
			routes: []netlink.Route{
				netlink.Route{
					Gw:        net.ParseIP("10.194.20.1"),
					Dst:       randomIpNet,
					LinkIndex: 0,
				},
			},
			link: &netlink.Device{
				LinkAttrs: netlink.LinkAttrs{
					Index: 0,
					Name:  "eni-0",
				},
			},
			expectedDefaultNetInterfaceName: "",
			expectedErrMsg:                  "",
		},
		{
			name: "one default route 1",
			routes: []netlink.Route{
				netlink.Route{
					Gw:        net.ParseIP("10.194.20.1"),
					Dst:       nil,
					LinkIndex: 0,
				},
			},
			link: &netlink.Device{
				LinkAttrs: netlink.LinkAttrs{
					Index: 0,
					Name:  "eni-0",
				},
			},
			expectedDefaultNetInterfaceName: "eni-0",
			expectedErrMsg:                  "",
		},
		{
			name: "one default route 2",
			routes: []netlink.Route{
				netlink.Route{
					Gw:        net.ParseIP("10.194.20.1"),
					Dst:       allIpNet,
					LinkIndex: 1,
				},
			},
			link: &netlink.Device{
				LinkAttrs: netlink.LinkAttrs{
					Index: 1,
					Name:  "eni-1",
				},
			},
			expectedDefaultNetInterfaceName: "eni-1",
			expectedErrMsg:                  "",
		},
		{
			name: "two default routes",
			routes: []netlink.Route{
				netlink.Route{
					Gw:        net.ParseIP("10.194.20.1"),
					Dst:       randomIpNet,
					LinkIndex: 0,
				},
				netlink.Route{
					Gw:        net.ParseIP("10.194.20.1"),
					Dst:       allIpNet,
					LinkIndex: 1,
				},
				netlink.Route{
					Gw:        net.ParseIP("10.194.20.1"),
					Dst:       nil,
					LinkIndex: 2,
				},
			},
			link: &netlink.Device{
				LinkAttrs: netlink.LinkAttrs{
					Index: 1,
					Name:  "eni-0",
				},
			},
			expectedDefaultNetInterfaceName: "eni-0",
			expectedErrMsg:                  "",
		},
	}

	for _, tc := range tcs {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			netLink := mock_netlinkwrapper.NewMockNetLink(ctrl)
			gomock.InOrder(
				netLink.EXPECT().RouteList(nil, netlink.FAMILY_ALL).Return(tc.routes, nil).AnyTimes(),
				netLink.EXPECT().LinkByIndex(tc.link.Attrs().Index).Return(tc.link, nil).AnyTimes(),
			)

			defaultNetInterfaceName, err := DefaultNetInterfaceName(netLink)
			errMsg := ""
			if err != nil {
				errMsg = err.Error()
			}

			assert.Equal(t, tc.expectedErrMsg, errMsg)
			assert.Equal(t, tc.expectedDefaultNetInterfaceName, defaultNetInterfaceName)
		})
	}
}

func TestGetInterfaceGlobalIPAddresses(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	tests := []struct {
		name              string
		addrs             []net.Addr
		ifaceErrMsg       string
		ifaceAddrErrMsg   string
		expectedIPv4Addrs []string
		expectedIPv6Addrs []string
		expectedErrMsg    string
	}{
		{
			name: "success with mixed IPs",
			addrs: []net.Addr{
				&net.IPNet{IP: net.ParseIP("192.168.1.100"), Mask: net.CIDRMask(24, 32)},
				&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
				&net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)},
				&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
				&net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
			},
			expectedIPv4Addrs: []string{"192.168.1.100"},
			expectedIPv6Addrs: []string{"2001:db8::1"},
			expectedErrMsg:    "",
		},
		{
			name:           "empty address list",
			addrs:          nil,
			expectedErrMsg: "",
		},
		{
			name:           "interface error",
			ifaceErrMsg:    "fail to get the interface",
			expectedErrMsg: fmt.Sprintf("failed to get interface by name 'test0': fail to get the interface"),
		},
		{
			name:            "addrs error",
			ifaceAddrErrMsg: "fail to get the IP address",
			expectedErrMsg:  fmt.Sprintf("failed to get addresses for interface 'test0': fail to get the IP address"),
		},
		{
			name: "invalid addr",
			addrs: []net.Addr{
				&net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 80},
			},
			expectedErrMsg: "",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			nw := mock_nw.NewMockNet(ctrl)
			if tc.ifaceErrMsg != "" {
				nw.EXPECT().InterfaceByName("test0").Return(nil, errors.New(tc.ifaceErrMsg))
			} else {
				nw.EXPECT().InterfaceByName("test0").Return(nil, nil)
				if tc.ifaceAddrErrMsg != "" {
					nw.EXPECT().Addrs(nil).Return(nil, errors.New(tc.ifaceAddrErrMsg))
				} else {
					nw.EXPECT().Addrs(nil).Return(tc.addrs, nil)
				}
			}

			ipv4Addrs, ipv6Addrs, err := GetInterfaceGlobalIPAddresses(nw, "test0")
			if err != nil {
				assert.EqualValues(t, tc.expectedErrMsg, err.Error())
				return
			}

			if !reflect.DeepEqual(ipv4Addrs, tc.expectedIPv4Addrs) {
				t.Errorf("GetInterfaceGlobalIPAddresses() = %v, want %v", ipv4Addrs, tc.expectedIPv4Addrs)
			}

			if !reflect.DeepEqual(ipv6Addrs, tc.expectedIPv6Addrs) {
				t.Errorf("GetInterfaceGlobalIPAddresses() = %v, want %v", ipv6Addrs, tc.expectedIPv6Addrs)
			}
		})
	}
}

func TestFilterIPAddrs(t *testing.T) {
	// Create test input with mixed address types
	addrs := []net.Addr{
		&net.IPNet{
			IP:   net.ParseIP("192.168.1.1"),
			Mask: net.CIDRMask(24, 32),
		},
		&net.IPNet{
			IP:   net.ParseIP("2001:db8::1"),
			Mask: net.CIDRMask(64, 128),
		},
		&net.UnixAddr{
			Name: "/tmp/test.sock",
			Net:  "unix",
		},
		&net.IPNet{
			IP:   net.ParseIP("10.0.0.1"),
			Mask: net.CIDRMask(24, 32),
		},
	}

	// Expected results
	expected := []net.IP{
		net.ParseIP("192.168.1.1"),
		net.ParseIP("2001:db8::1"),
		net.ParseIP("10.0.0.1"),
	}

	// Run test
	result := filterIPAddrs(addrs)
	assert.Equal(t, expected, result, "filtered IPs should match expected IPs")
}

func TestGetInterfaceIPAddrs(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	tests := []struct {
		name          string
		interfaceName string
		setupMock     func(*mock_nw.MockNet)
		expectedIPs   []net.IP
		expectedErr   string
	}{
		{
			name:          "successful IPv4 and IPv6",
			interfaceName: "eth0",
			setupMock: func(m *mock_nw.MockNet) {
				intf := &net.Interface{Name: "eth0"}
				addrs := []net.Addr{
					&net.IPNet{
						IP:   net.ParseIP("192.0.2.1"),
						Mask: net.CIDRMask(24, 32),
					},
					&net.IPNet{
						IP:   net.ParseIP("2001:db8::1"),
						Mask: net.CIDRMask(64, 128),
					},
				}

				m.EXPECT().InterfaceByName("eth0").Return(intf, nil)
				m.EXPECT().Addrs(intf).Return(addrs, nil)
			},
			expectedIPs: []net.IP{
				net.ParseIP("192.0.2.1"),
				net.ParseIP("2001:db8::1"),
			},
		},
		{
			name:          "error getting interface",
			interfaceName: "eth99",
			setupMock: func(m *mock_nw.MockNet) {
				m.EXPECT().InterfaceByName("eth99").Return(nil, assert.AnError)
			},
			expectedIPs: nil,
			expectedErr: fmt.Sprintf("failed to get interface by name 'eth99': %s", assert.AnError.Error()),
		},
		{
			name:          "error getting addresses",
			interfaceName: "eth0",
			setupMock: func(m *mock_nw.MockNet) {
				intf := &net.Interface{Name: "eth0"}
				m.EXPECT().InterfaceByName("eth0").Return(intf, nil)
				m.EXPECT().Addrs(intf).Return(nil, assert.AnError)
			},
			expectedIPs: nil,
			expectedErr: fmt.Sprintf("failed to get addresses for interface 'eth0': %s", assert.AnError.Error()),
		},
		{
			name:          "no addresses found",
			interfaceName: "eth0",
			setupMock: func(m *mock_nw.MockNet) {
				intf := &net.Interface{Name: "eth0"}
				m.EXPECT().InterfaceByName("eth0").Return(intf, nil)
				m.EXPECT().Addrs(intf).Return([]net.Addr{}, nil)
			},
			expectedIPs: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockNet := mock_nw.NewMockNet(ctrl)
			tt.setupMock(mockNet)

			ips, err := getInterfaceIPAddrs(mockNet, tt.interfaceName)

			if tt.expectedErr != "" {
				assert.EqualError(t, err, tt.expectedErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedIPs, ips)
			}
		})
	}
}

func TestIsIPv6GlobalUnicast(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{
			name:     "valid IPv6 global unicast",
			ip:       "2001:db8::1",
			expected: true,
		},
		{
			name:     "IPv6 link-local",
			ip:       "fe80::1",
			expected: false,
		},
		{
			name:     "IPv6 multicast",
			ip:       "ff00::1",
			expected: false,
		},
		{
			name:     "IPv6 loopback",
			ip:       "::1",
			expected: false,
		},
		{
			name:     "IPv4 address",
			ip:       "192.0.2.1",
			expected: false,
		},
		{
			name:     "IPv4-mapped IPv6 address",
			ip:       "::ffff:192.0.2.1",
			expected: false,
		},
		{
			name:     "unspecified address",
			ip:       "::",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := isIPv6GlobalUnicast(ip)
			assert.Equal(t, tt.expected, result, "IP: %s", tt.ip)
		})
	}
}

func TestIsIPv4GlobalUnicast(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{
			name:     "valid IPv4 global unicast",
			ip:       "1.2.3.4",
			expected: true,
		},
		{
			name:     "IPv4 private address",
			ip:       "10.0.0.1",
			expected: true, // private addresses are still global unicast
		},
		{
			name:     "IPv4 loopback",
			ip:       "127.0.0.1",
			expected: false,
		},
		{
			name:     "IPv4 link-local",
			ip:       "169.254.0.1",
			expected: false,
		},
		{
			name:     "IPv4 multicast",
			ip:       "224.0.0.1",
			expected: false,
		},
		{
			name:     "IPv6 global unicast",
			ip:       "2001:db8::1",
			expected: false,
		},
		{
			name:     "IPv4-mapped IPv6 address",
			ip:       "::ffff:192.0.2.1",
			expected: true, // these are treated as IPv4 addresses
		},
		{
			name:     "unspecified IPv4",
			ip:       "0.0.0.0",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := isIPv4GlobalUnicast(ip)
			assert.Equal(t, tt.expected, result, "IP: %s", tt.ip)
		})
	}
}

func TestStringifyIPAddrs(t *testing.T) {
	ips := []net.IP{
		net.ParseIP("1.2.3.4"),
		net.ParseIP("2001:db8::1"),
	}
	expected := []string{
		"1.2.3.4",
		"2001:db8::1",
	}

	result := stringifyIPAddrs(ips)
	assert.Equal(t, expected, result)
}
