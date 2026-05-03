package pcap

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/kakeetopius/gtap/internal/argparser"
)

type Interface struct {
	PcapName string
	net.Interface
}

// go: build windows

// When sending and receiving packets on windows, pcap is used instead of the raw sockets that are available on linux only.
// The pcap library on windows requires some special names for the interface which can only be gotten via the pcap.FindAllDevs() function which returns pcap.Interface structs
// but these structs returned by pcap.FindAllDevs() do not contain all information for example the interfaces' hardware address, index etc.
// So these functions help to connect the two: pcap.Interface and net.Interface via the only common data that can be got from both -> their IP addresses.

func setUpHandle(opts *argparser.Options) (*pcap.Handle, error) {
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

	var ifaceIndex int
	if opts.Flags&argparser.IfaceFlag != 0 {
		// If an interface was explicitly given
		ifaceFound := false
		for index, iface := range netIfaces {
			if iface.Name == opts.IfaceName {
				ifaceIndex = index
				ifaceFound = true
				break
			}
		}
		if !ifaceFound {
			return nil, fmt.Errorf("could not find interface: %v", opts.IfaceName)
		}
	} else {
		stringBuilder := strings.Builder{}
		stringBuilder.WriteString("Please Provide an interface to use.\nThe following are the available interfaces on the system\n")
		for i, iface := range netIfaces {
			fmt.Fprintf(&stringBuilder, "%v. %v\n", i+1, iface.Name)
		}
		fmt.Println(stringBuilder.String())
		return nil, fmt.Errorf("interface not given")
	}

	fmt.Println("Interface to use: ", netIfaces[ifaceIndex].Name)
	handle, err := pcap.NewInactiveHandle(netIfaces[ifaceIndex].PcapName)
	if err != nil {
		return nil, err
	}
	// Setting different options as specified by user.
	if opts.Flags&argparser.PromiscuousFlag != 0 {
		err = handle.SetPromisc(true)
		if err != nil {
			return nil, err
		}
	}
	if opts.Flags&argparser.MonitorFlag != 0 {
		err = handle.SetRFMon(true)
		if err != nil {
			return nil, err
		}
	}
	if opts.Flags&argparser.FilterFlag != 0 {
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
