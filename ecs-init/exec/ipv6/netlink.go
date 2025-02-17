package ipv6

import (
	"fmt"

	"github.com/cihub/seelog"
	"github.com/vishvananda/netlink"
)

func CreateTMDSIPv6Interface() error {
	return createDummyInterfaceWithAddressNetlink("tmds", "fd00:ec5::254/64")
}

func createDummyInterfaceWithAddressNetlink(interfaceName string, ipv6Address string) error {
	seelog.Info("Creating TMDS IPv6 interface")
	// Check if interface already exists using netlink
	_, err := netlink.LinkByName(interfaceName)
	if err == nil {
		fmt.Printf("Interface '%s' already exists. Returning early.\n", interfaceName)
		return nil // Return nil to indicate early return due to existing interface.
	}
	if _, ok := err.(netlink.LinkNotFoundError); !ok {
		return fmt.Errorf("error checking for existing interface: %w", err) // Return other errors during lookup
	}

	// Interface does not exist, proceed to create it

	// Create a new dummy link
	dummy := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: interfaceName,
		},
	}
	if err := netlink.LinkAdd(dummy); err != nil {
		return fmt.Errorf("failed to create dummy interface: %w", err)
	}

	// Assign IPv6 address to the interface
	addr, err := netlink.ParseAddr(ipv6Address)
	if err != nil {
		// Cleanup: Delete the interface if address parsing fails (optional, but good practice even if no explicit cleanup in prompt)
		netlink.LinkDel(dummy) // Ignoring error during deletion for simplicity per prompt.
		return fmt.Errorf("failed to parse IPv6 address: %w", err)
	}

	if err := netlink.AddrAdd(dummy, addr); err != nil {
		// Cleanup: Delete the interface if address assignment fails
		netlink.LinkDel(dummy) // Ignoring error during deletion for simplicity per prompt.
		return fmt.Errorf("failed to assign IPv6 address: %w", err)
	}

	// Bring the interface UP using netlink
	if err := netlink.LinkSetUp(dummy); err != nil {
		netlink.LinkDel(dummy) // Optional: delete if bringing up fails
		return fmt.Errorf("failed to bring interface '%s' up using netlink: %w", interfaceName, err)
	}

	return nil
}
