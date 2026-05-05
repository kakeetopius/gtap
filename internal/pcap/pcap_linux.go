package pcap

import (
	"fmt"
	"time"

	"github.com/google/gopacket/pcap"
)

// go: build linux || darwin

func setUpHandle(opts Options) (*pcap.Handle, error) {
	allIfaces, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	if len(allIfaces) < 1 {
		return nil, fmt.Errorf("could not find any network interfaces")
	}

	var ifaceToUseName string
	// if no options were given we capture all packets by using the 'any' interface.
	if opts.Flags.IsSet(CaptureAllFlag) {
		for _, iface := range allIfaces {
			if iface.Name == "any" {
				ifaceToUseName = iface.Name
				break
			}
		}
	} else if opts.Flags.IsSet(AutoIfaceFlag) {
		// If --auto flag is given we find a non-loopback interface automatically.
		for _, iface := range allIfaces {
			if iface.Name == "any" {
				continue
			}
			if iface.Name == "lo" {
				continue
			}

			ifaceToUseName = iface.Name
			break
		}
	} else if opts.IfaceName != "" {
		// If an interface was explicitly given
		ifaceFound := false
		for _, iface := range allIfaces {
			if iface.Name == opts.IfaceName {
				ifaceFound = true
				ifaceToUseName = iface.Name
				break
			}
		}
		if !ifaceFound {
			return nil, fmt.Errorf("could not find interface: %v", opts.IfaceName)
		}
	}

	fmt.Println("Interface to use: ", ifaceToUseName)
	handle, err := pcap.NewInactiveHandle(ifaceToUseName)
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
