// Package pcap provides functions to interface with the gopacket/pcap library for example to set up pcap handle, capture packets.
package pcap

// TODO
// 9. Add Option for display format (summary, verbose, hexdump)

import (
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/kakeetopius/gtap/internal/argparser"
	"github.com/kakeetopius/gtap/internal/decoding"
)

func StartCapture(opts *argparser.Options) error {
	var handle *pcap.Handle
	var err error

	if opts.Flags&argparser.InputFileFlag != 0 {
		handle, err = setUpHandleFromFile(opts.InputFile)
	} else {
		handle, err = setUpHandle(opts)
	}
	if err != nil {
		return err
	}
	defer handle.Close()

	if opts.Flags&argparser.FilterFlag != 0 {
		err = setUpFilter(handle, opts.Filter)
		if err != nil {
			return err
		}
	}

	if opts.Flags&argparser.OutputFileFlag != 0 {
		return captureToFile(handle, opts.OutputFile)
	}

	notifyChan := make(chan struct{})
	go awaitSignal(notifyChan)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	startTime := time.Now()
	for {
		select {
		case <-notifyChan:
			return printStats(handle, startTime)
		case packet := <-packets:
			decoding.DecodeDataLink(packet)
		}
	}
}

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
	activeHandle, err := handle.Activate()
	if err != nil {
		return nil, err
	}
	return activeHandle, nil
}

func setUpHandleFromFile(fileName string) (*pcap.Handle, error) {
	handle, err := pcap.OpenOffline(fileName)
	return handle, err
}

func setUpFilter(handle *pcap.Handle, filter string) error {
	fmt.Printf("Using filter: %v\n", filter)
	err := handle.SetBPFFilter(filter)
	return err
}

func captureToFile(handle *pcap.Handle, fileName string) error {
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	fmt.Printf("Capturing to file: %v\n", fileName)
	writer := pcapgo.NewWriter(file)
	writer.WriteFileHeader(uint32(handle.SnapLen()), handle.LinkType())

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	for packet := range packets {
		writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
	}
	return err
}

func printStats(handle *pcap.Handle, startTime time.Time) error {
	pcapStats, err := handle.Stats()
	if err != nil {
		return err
	}

	endTime := time.Now()
	timeDiff := endTime.Sub(startTime)

	fmt.Println("\n\n──────────────────────────────────────────────")
	fmt.Printf("Packets Received: %v\n", pcapStats.PacketsReceived)
	fmt.Printf("Packets Dropped: %v\n", pcapStats.PacketsDropped)
	fmt.Printf("Capture Duration: %v\n", timeDiff.String())
	return nil
}

func awaitSignal(notifyChan chan struct{}) {
	signalChan := make(chan os.Signal, 1)

	signal.Notify(signalChan, os.Interrupt)

	<-signalChan
	fmt.Println("Stopping Packet Capture..............")
	notifyChan <- struct{}{}
}
