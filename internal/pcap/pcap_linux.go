package pcap

import (
	"fmt"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/kakeetopius/gtap/internal/argparser"
)

// go: build linux || darwin

func setUpHandle(opts *argparser.Options) (*pcap.Handle, error) {
	allIfaces, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	if len(allIfaces) < 1 {
		return nil, fmt.Errorf("could not find any network interfaces")
	}

	var ifaceIndex int
	// if no options were given we capture all packets by using the 'any' interface.
	if opts.Flags&argparser.CaptureAllFlag != 0 {
		for index, iface := range allIfaces {
			if iface.Name == "any" {
				ifaceIndex = index
				break
			}
		}
	} else if opts.Flags&argparser.AutoFlag != 0 {
		// If --auto flag is given we find a non-loopback interface automatically.
		for index, iface := range allIfaces {
			if iface.Name == "any" {
				continue
			}
			if iface.Name == "lo" {
				continue
			}

			ifaceIndex = index
			break
		}
	} else if opts.Flags&argparser.IfaceFlag != 0 {
		// If an interface was explicitly given
		ifaceFound := false
		for index, iface := range allIfaces {
			if iface.Name == opts.IfaceName {
				ifaceIndex = index
				ifaceFound = true
				break
			}
		}
		if !ifaceFound {
			return nil, fmt.Errorf("could not find interface: %v", opts.IfaceName)
		}
	}

	fmt.Println("Interface to use: ", allIfaces[ifaceIndex].Name)
	handle, err := pcap.NewInactiveHandle(allIfaces[ifaceIndex].Name)
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
