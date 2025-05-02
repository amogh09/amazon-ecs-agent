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

// Code in this package is taken from https://github.com/moby/moby/blob/v25.0.6/libnetwork/resolvconf/resolvconf.go

package resolvconf

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
)

const (
	// defaultPath is the default path to the resolv.conf that contains information to resolve DNS. See Path()
	defaultPath = "/host/etc/resolv.conf"
	// alternatePath is a path different from defaultPath, that may be used to resolve DNS. See Path().
	alternatePath = "/host/run/systemd/resolve/resolv.conf"
)

type IPVersion int

// constants for the IP address type
const (
	IPvAny IPVersion = iota // IPv4 and IPv6
	IPv4
	IPv6
)

const (
	ipv4NumBlock = `(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)`
	ipv4Address  = `(` + ipv4NumBlock + `\.){3}` + ipv4NumBlock

	// This is not an IPv6 address verifier as it will accept a super-set of IPv6, and also
	// will *not match* IPv4-Embedded IPv6 Addresses (RFC6052), but that and other variants
	// -- e.g. other link-local types -- either won't work in containers or are unnecessary.
	// For readability and sufficiency for Docker purposes this seemed more reasonable than a
	// 1000+ character regexp with exact and complete IPv6 validation
	ipv6Address = `([0-9A-Fa-f]{0,4}:){2,7}([0-9A-Fa-f]{0,4})(%\w+)?`
)

var (
	nsRegexp          = regexp.MustCompile(`^\s*nameserver\s*((` + ipv4Address + `)|(` + ipv6Address + `))\s*$`)
	nsIPv6Regexpmatch = regexp.MustCompile(`^\s*nameserver\s*((` + ipv6Address + `))\s*$`)
	nsIPv4Regexpmatch = regexp.MustCompile(`^\s*nameserver\s*((` + ipv4Address + `))\s*$`)
	searchRegexp      = regexp.MustCompile(`^\s*search\s*(([^\s]+\s*)*)$`)
	optionsRegexp     = regexp.MustCompile(`^\s*options\s*(([^\s]+\s*)*)$`)
)

type ResolvConf interface {
	GetNameServers(kind IPVersion) ([]string, error)
}

type resolvConf struct {
	detectSystemdResolvConfOnce sync.Once
	pathAfterSystemdDetection   string
}

func NewDefaultResolvConf() ResolvConf {
	return &resolvConf{
		detectSystemdResolvConfOnce: sync.Once{},
		pathAfterSystemdDetection:   defaultPath,
	}
}

// path returns the path to the resolv.conf file.
//
// When /etc/resolv.conf contains 127.0.0.53 as the only nameserver, then
// it is assumed systemd-resolved manages DNS. Because inside the container 127.0.0.53
// is not a valid DNS server, path() returns /run/systemd/resolve/resolv.conf
// which is the resolv.conf that systemd-resolved generates and manages.
// Otherwise path() returns /etc/resolv.conf.
//
// Errors are silenced as they will inevitably resurface at future open/read calls.
//
// More information at https://www.freedesktop.org/software/systemd/man/systemd-resolved.service.html#/etc/resolv.conf
func (rc *resolvConf) path() string {
	rc.detectSystemdResolvConfOnce.Do(func() {
		candidateResolvConf, err := os.ReadFile(defaultPath)
		if err != nil {
			// silencing error as it will resurface at next calls trying to read defaultPath
			return
		}
		ns := GetNameservers(candidateResolvConf, IPvAny)
		if len(ns) == 1 && ns[0] == "127.0.0.53" {
			rc.pathAfterSystemdDetection = alternatePath
		}
	})
	return rc.pathAfterSystemdDetection
}

func (rc *resolvConf) readResolvConf() ([]byte, error) {
	contents, err := os.ReadFile(rc.path())
	if err != nil {
		return nil, fmt.Errorf("failed to read resolv.conf: %w", err)
	}
	return contents, nil
}

func (rc *resolvConf) GetNameServers(kind IPVersion) ([]string, error) {
	contents, err := rc.readResolvConf()
	if err != nil {
		return nil, err
	}
	return GetNameservers(contents, kind), nil
}

// GetNameservers returns nameservers (if any) listed in /etc/resolv.conf
func GetNameservers(resolvConf []byte, kind IPVersion) []string {
	var nameservers []string
	for _, line := range getLines(resolvConf, []byte("#")) {
		var ns [][]byte
		if kind == IPvAny {
			ns = nsRegexp.FindSubmatch(line)
		} else if kind == IPv4 {
			ns = nsIPv4Regexpmatch.FindSubmatch(line)
		} else if kind == IPv6 {
			ns = nsIPv6Regexpmatch.FindSubmatch(line)
		}
		if len(ns) > 0 {
			nameservers = append(nameservers, string(ns[1]))
		}
	}
	return nameservers
}

// getLines parses input into lines and strips away comments.
func getLines(input []byte, commentMarker []byte) [][]byte {
	lines := bytes.Split(input, []byte("\n"))
	var output [][]byte
	for _, currentLine := range lines {
		commentIndex := bytes.Index(currentLine, commentMarker)
		if commentIndex == -1 {
			output = append(output, currentLine)
		} else {
			output = append(output, currentLine[:commentIndex])
		}
	}
	return output
}

// GetSearchDomains returns search domains (if any) listed in /etc/resolv.conf
// If more than one search line is encountered, only the contents of the last
// one is returned.
func GetSearchDomains(resolvConf []byte) []string {
	var domains []string
	for _, line := range getLines(resolvConf, []byte("#")) {
		match := searchRegexp.FindSubmatch(line)
		if match == nil {
			continue
		}
		domains = strings.Fields(string(match[1]))
	}
	return domains
}

// GetOptions returns options (if any) listed in /etc/resolv.conf
// If more than one options line is encountered, only the contents of the last
// one is returned.
func GetOptions(resolvConf []byte) []string {
	var options []string
	for _, line := range getLines(resolvConf, []byte("#")) {
		match := optionsRegexp.FindSubmatch(line)
		if match == nil {
			continue
		}
		options = strings.Fields(string(match[1]))
	}
	return options
}
