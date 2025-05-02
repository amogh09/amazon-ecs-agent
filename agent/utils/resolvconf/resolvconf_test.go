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

func TestGetSearchDomains(t *testing.T) {
	tests := []struct {
		name       string
		resolvConf string
		expected   []string
	}{
		{
			name: "single search domain",
			resolvConf: `search example.com
`,
			expected: []string{"example.com"},
		},
		{
			name: "multiple search domains on single line",
			resolvConf: `search example.com example.org example.net
`,
			expected: []string{"example.com", "example.org", "example.net"},
		},
		{
			name: "multiple search lines - should use last one",
			resolvConf: `search example.com
search example.org example.net
`,
			expected: []string{"example.org", "example.net"},
		},
		{
			name: "with comments",
			resolvConf: `# This is a comment
search example.com example.org # Another comment
`,
			expected: []string{"example.com", "example.org"},
		},
		{
			name: "with other resolv.conf entries",
			resolvConf: `domain example.com
nameserver 8.8.8.8
search example.org example.net
options ndots:5
`,
			expected: []string{"example.org", "example.net"},
		},
		{
			name: "with extra whitespace",
			resolvConf: `search   example.com    example.org
`,
			expected: []string{"example.com", "example.org"},
		},
		{
			name:       "empty resolv.conf",
			resolvConf: "",
			expected:   nil,
		},
		{
			name: "no search domains",
			resolvConf: `nameserver 8.8.8.8
options ndots:5
`,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetSearchDomains([]byte(tt.resolvConf))
			assert.Equal(t, tt.expected, result, "search domains should match expected values")
		})
	}
}

func TestGetOptions(t *testing.T) {
	tests := []struct {
		name       string
		resolvConf string
		expected   []string
	}{
		{
			name: "single option",
			resolvConf: `options ndots:5
`,
			expected: []string{"ndots:5"},
		},
		{
			name: "multiple options on single line",
			resolvConf: `options ndots:5 timeout:3 attempts:2
`,
			expected: []string{"ndots:5", "timeout:3", "attempts:2"},
		},
		{
			name: "multiple option lines - should use last one",
			resolvConf: `options ndots:5
options timeout:3 attempts:2
`,
			expected: []string{"timeout:3", "attempts:2"},
		},
		{
			name: "with comments",
			resolvConf: `# This is a comment
options ndots:5 timeout:3 # Another comment
`,
			expected: []string{"ndots:5", "timeout:3"},
		},
		{
			name: "with other resolv.conf entries",
			resolvConf: `domain example.com
nameserver 8.8.8.8
search example.org
options ndots:5 timeout:3
`,
			expected: []string{"ndots:5", "timeout:3"},
		},
		{
			name: "with extra whitespace",
			resolvConf: `options   ndots:5    timeout:3
`,
			expected: []string{"ndots:5", "timeout:3"},
		},
		{
			name:       "empty resolv.conf",
			resolvConf: "",
			expected:   nil,
		},
		{
			name: "no options",
			resolvConf: `nameserver 8.8.8.8
search example.com
`,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetOptions([]byte(tt.resolvConf))
			assert.Equal(t, tt.expected, result, "options should match expected values")
		})
	}
}
