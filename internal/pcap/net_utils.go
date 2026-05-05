package pcap

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/kakeetopius/gtap/internal/tui"
)

// getInterfaceSelection displays the available interfaces in a table and
// returns the interface chosen by the user.
func getInterfaceSelection(ifaces []Interface) (Interface, error) {
	columns := []tui.TableColumn{
		{Title: "Index", Width: 5},
		{Title: "Name", Width: 35},
		{Title: "Description", Width: 60},
	}

	rows := make([]tui.TableRow, 0, len(ifaces))
	for _, iface := range ifaces {
		rows = append(rows, []string{
			strconv.Itoa(iface.Index),
			iface.Name,
			iface.PcapDesc,
		})
	}

	selectedInterfaceIndex, err := tui.GetTableSelection(rows, columns, 0)
	if err != nil {
		return Interface{}, err
	}
	return interfaceByIndex(ifaces, selectedInterfaceIndex)
}

// interfaceByIndex returns the interface whose index matches the provided
// string representation of the index.
func interfaceByIndex(ifaces []Interface, index string) (Interface, error) {
	for _, iface := range ifaces {
		if strconv.Itoa(iface.Index) == index {
			return iface, nil
		}
	}

	return Interface{}, fmt.Errorf("could not get interface")
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
