package pcap

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/pterm/pterm"
)

// go: build linux || darwin

func setUpHandle(opts Options) (*pcap.Handle, error) {
	allIfaces, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	if len(allIfaces) < 1 {
		return nil, fmt.Errorf("could not find any network interfaces on the system")
	}

	netIfaces := make([]Interface, 0, len(allIfaces))
	for i, iface := range allIfaces {
		netIfaces = append(netIfaces, Interface{
			PcapName: iface.Name,
			PcapDesc: iface.Description,
			// not using real net.Interface because some interfaces returned by pcap.FindAllDevs() like 'any' arent actual interfaces, so net.InterfaceByName()
			// won't find it.
			// Also other fields in the net.Interface except the Index and Name aren't used at all.
			Interface: net.Interface{
				Name:  iface.Name,
				Index: i + 1, // not real interface index. Used for selection purposes if SelectIfaceFlag flag is set.
			},
		})
	}

	var ifaceToUseName Interface
	// if CaptureAllFlag flag was set we capture all packets on all interfaces by using the 'any' interface.
	if opts.Flags.IsSet(CaptureAllFlag) {
		for _, iface := range netIfaces {
			if iface.Name == "any" {
				ifaceToUseName = iface
				break
			}
		}
	} else if opts.IfaceName != "" {
		// If an interface was explicitly given
		ifaceFound := false
		for _, iface := range netIfaces {
			if iface.Name == opts.IfaceName {
				ifaceFound = true
				ifaceToUseName = iface
				break
			}
		}
		if !ifaceFound {
			return nil, fmt.Errorf("could not find interface: %v", opts.IfaceName)
		}
	} else if opts.Flags.IsSet(SelectIfaceFlag) {
		// If SelectIfaceFlag flag is given we prompt user for an interface to use
		pterm.NewStyle(pterm.Bold).Println("Please Provide an interface to use.\nThe following are the available interfaces on the system.")
		ifaceToUseName, err = getInterfaceSelection(netIfaces)
		if err != nil {
			return nil, err
		}
	}

	pterm.Info.Println("Interface to use: ", ifaceToUseName.Name)
	handle, err := pcap.NewInactiveHandle(ifaceToUseName.PcapName)
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
