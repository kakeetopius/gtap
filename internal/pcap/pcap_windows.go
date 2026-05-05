package pcap

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/kakeetopius/gtap/internal/tui"
)

// go: build windows

// On windows the pcap.FindAllDevs() returns a slice of structs of type pcap.Interface. But the name field in those structs is not the normal name of the interface for
// example "Wi-Fi" or "Ethernet 1", they are special strings that pcap uses internally. Therefore it is difficult to match such interface names like "Wi-Fi" by using
// just the pcap.Interface struct. But the net.Interface struct returned by net.Interfaces() does contain such names.
// Therefore these functions help to connect the two: pcap.Interface and net.Interface via the only common data that can be got from the two -> the ip addresses.
// This then will allow a user to specify an interface by it's usual name e.g. "Wi-Fi" but at the same time supply to pcap the name that it expects.

func setUpHandle(opts Options) (*pcap.Handle, error) {
	pcapIfaces, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	netIfaces, err := InterfaceSliceFromPcapInterfaceSlice(pcapIfaces)
	if err != nil {
		return nil, err
	}

	if len(netIfaces) < 1 {
		return nil, fmt.Errorf("could not find any network interfaces")
	}

	var ifaceToUse Interface
	if opts.IfaceName != "" {
		// If an interface was explicitly given
		ifaceFound := false
		for _, iface := range netIfaces {
			if iface.Name == opts.IfaceName {
				ifaceToUse = iface
				ifaceFound = true
				break
			}
		}
		if !ifaceFound {
			return nil, fmt.Errorf("could not find interface: %v", opts.IfaceName)
		}
	} else {
		// if no interface was given, prompt the user to select one.
		fmt.Println("Please Provide an interface to use.\nThe following are the available interfaces on the system")
		ifaceToUse, err = getInterfaceSelection(netIfaces)
		if err != nil {
			return nil, err
		}
	}

	fmt.Println("Interface to use: ", ifaceToUse.Name)
	handle, err := pcap.NewInactiveHandle(ifaceToUse.PcapName)
	if err != nil {
		return nil, err
	}
	// Setting different options as specified by user.
	if opts.Flags.IsSet(PromiscuousFlag) {
		err = handle.SetPromisc(true)
		if err != nil {
			return nil, err
		}
	}
	if opts.Flags.IsSet(MonitorFlag) {
		err = handle.SetRFMon(true)
		if err != nil {
			return nil, err
		}
	}
	if opts.Filter != "" {
		// if filter is given we set to immediate mode
		err = handle.SetImmediateMode(true)
		if err != nil {
			return nil, err
		}
	}
	err = handle.SetTimeout(500 * time.Millisecond)
	if err != nil {
		return nil, err
	}
	activeHandle, err := handle.Activate()
	if err != nil {
		return nil, err
	}
	return activeHandle, nil
}

func InterfaceSliceFromPcapInterfaceSlice(pcapIfaces []pcap.Interface) ([]Interface, error) {
	allIfaces := make([]Interface, 0, len(pcapIfaces))

	for _, pcapIface := range pcapIfaces {
		addrs := pcapInterfaceAddressSliceToPrefixSlice(pcapIface.Addresses)
		netIface, err := netInterfaceFromAddrs(addrs)
		if err != nil {
			continue
		}
		allIfaces = append(allIfaces, Interface{
			PcapName:  pcapIface.Name,
			Interface: netIface,
		})
	}

	return allIfaces, nil
}

// pcapInterfaceAddressSliceToPrefixSlice converts pcap.InterfaceAddress structs to net.Addr (net.IPNet specifically)
func pcapInterfaceAddressSliceToPrefixSlice(addrs []pcap.InterfaceAddress) []netip.Prefix {
	addresses := make([]netip.Prefix, 0, len(addrs))

	for _, addr := range addrs {
		prefix, err := IPNetToPrefix(&net.IPNet{
			IP:   addr.IP,
			Mask: addr.Netmask,
		})
		if err != nil {
			continue
		}
		addresses = append(addresses, prefix)
	}

	return addresses
}

// netInterfaceFromAddrs attempts to find a net.interface that has one of the IP addresses given
func netInterfaceFromAddrs(givenAddrs []netip.Prefix) (net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return net.Interface{}, err
	}
	for _, iface := range ifaces {
		ifaceAddrs, err := iface.Addrs()
		if err != nil {
			return net.Interface{}, err
		}
		for _, ifaceaddr := range ifaceAddrs {
			iaddr, ok := ifaceaddr.(*net.IPNet)
			if !ok {
				return net.Interface{}, fmt.Errorf("could not get net.Interface")
			}
			ifacePrefix, err := IPNetToPrefix(iaddr)
			if err != nil {
				return net.Interface{}, err
			}
			if slices.Contains(givenAddrs, ifacePrefix) {
				return iface, nil
			}
		}
	}
	return net.Interface{}, fmt.Errorf("could not get net.Interface")
}

// IPNetToPrefix converts a net.IPNet value into its netip.Prefix equivalent.
//
// It returns an error when the IP in ipnet cannot be converted to a valid
// netip.Addr.
func IPNetToPrefix(ipnet *net.IPNet) (netip.Prefix, error) {
	ip := ipnet.IP

	// Check to see if the ipnet is IPv4 and if so change the slice to a 4 byte slice to allow AddrFromSlice to return correct representation
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}

	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Prefix{}, fmt.Errorf("invalid IPNet")
	}

	ones, _ := ipnet.Mask.Size()

	return netip.PrefixFrom(addr, ones), nil
}

func getInterfaceSelection(ifaces []Interface) (Interface, error) {
	columns := []tui.TableColumn{
		{Title: "Index", Width: 5},
		{Title: "Name", Width: 40},
	}

	rows := make([]tui.TableRow, 0, len(ifaces))
	for _, iface := range ifaces {
		rows = append(rows, []string{
			strconv.Itoa(iface.Index),
			iface.Name,
		})
	}

	selectedInterfaceIndex, err := tui.GetTableSelection(rows, columns, 0)
	if err != nil {
		return Interface{}, err
	}
	return interfaceByIndex(ifaces, selectedInterfaceIndex)
}

func interfaceByIndex(ifaces []Interface, index string) (Interface, error) {
	for _, iface := range ifaces {
		if strconv.Itoa(iface.Index) == index {
			return iface, nil
		}
	}

	return Interface{}, fmt.Errorf("could not get interface")
}
