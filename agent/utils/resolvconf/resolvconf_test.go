// go:build unit
//go:build unit
// +build unit

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

package resolvconf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetNameservers(t *testing.T) {
	tests := []struct {
		name       string
		resolvConf string
		ipVersion  IPVersion
		expected   []string
	}{
		{
			name: "single IPv4 nameserver",
			resolvConf: `nameserver 8.8.8.8
`,
			ipVersion: IPvAny,
			expected:  []string{"8.8.8.8"},
		},
		{
			name: "multiple IPv4 nameservers",
			resolvConf: `nameserver 8.8.8.8
nameserver 8.8.4.4
`,
			ipVersion: IPvAny,
			expected:  []string{"8.8.8.8", "8.8.4.4"},
		},
		{
			name: "single IPv6 nameserver",
			resolvConf: `nameserver 2001:4860:4860::8888
`,
			ipVersion: IPvAny,
			expected:  []string{"2001:4860:4860::8888"},
		},
		{
			name: "mixed IPv4 and IPv6 nameservers",
			resolvConf: `nameserver 8.8.8.8
nameserver 2001:4860:4860::8888
nameserver 8.8.4.4
`,
			ipVersion: IPvAny,
			expected:  []string{"8.8.8.8", "2001:4860:4860::8888", "8.8.4.4"},
		},
		{
			name: "IPv4 only filter",
			resolvConf: `nameserver 8.8.8.8
nameserver 2001:4860:4860::8888
nameserver 8.8.4.4
`,
			ipVersion: IPv4,
			expected:  []string{"8.8.8.8", "8.8.4.4"},
		},
		{
			name: "IPv6 only filter",
			resolvConf: `nameserver 8.8.8.8
nameserver 2001:4860:4860::8888
nameserver 2001:4860:4860::8844
`,
			ipVersion: IPv6,
			expected:  []string{"2001:4860:4860::8888", "2001:4860:4860::8844"},
		},
		{
			name: "with comments",
			resolvConf: `# This is a comment
nameserver 8.8.8.8 # Google DNS
nameserver 8.8.4.4
`,
			ipVersion: IPvAny,
			expected:  []string{"8.8.8.8", "8.8.4.4"},
		},
		{
			name: "with empty lines and whitespace",
			resolvConf: `

nameserver 8.8.8.8

nameserver    8.8.4.4
`,
			ipVersion: IPvAny,
			expected:  []string{"8.8.8.8", "8.8.4.4"},
		},
		{
			name: "with other resolv.conf entries",
			resolvConf: `domain example.com
search example.com
nameserver 8.8.8.8
options ndots:5
nameserver 8.8.4.4
`,
			ipVersion: IPvAny,
			expected:  []string{"8.8.8.8", "8.8.4.4"},
		},
		{
			name:       "empty resolv.conf",
			resolvConf: "",
			ipVersion:  IPvAny,
			expected:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetNameservers([]byte(tt.resolvConf), tt.ipVersion)
			assert.Equal(t, tt.expected, result, "nameservers should match expected values")
		})
	}
}
