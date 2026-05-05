// Package pcap provides functions to interface with the gopacket/pcap library.
package pcap

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/kakeetopius/gtap/internal/decoding"
)

func StartCapture(opts Options) error {
	var handle *pcap.Handle
	var err error
	var usingOfflineFile bool

	if opts.InputFile != "" {
		handle, err = setUpHandleFromFile(opts.InputFile)
		usingOfflineFile = true
	} else {
		handle, err = setUpHandle(opts)
	}
	if err != nil {
		return err
	}
	defer handle.Close()

	if opts.Filter != "" {
		err = setUpFilter(handle, opts.Filter)
		if err != nil {
			return err
		}
	}

	notifyChan := make(chan struct{})
	go awaitSignal(notifyChan)

	if opts.OutputFile != "" {
		return captureToFile(handle, opts.OutputFile, notifyChan)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	startTime := time.Now()
	for {
		select {
		case <-notifyChan:
			if !usingOfflineFile {
				return printStats(handle, startTime)
			}
			return nil
		case packet, ok := <-packets:
			if !ok {
				return nil
			}
			if opts.Flags.IsSet(HexDumpFlag) {
				fmt.Println(packet.Dump())
				continue
			} else if opts.Flags.IsSet(SummaryFlag) {
				fmt.Println(packet.String())
				continue
			}
			decoding.DecodeDataLink(packet)
		}
	}
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

func captureToFile(handle *pcap.Handle, fileName string, notifyChan chan struct{}) error {
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	fmt.Printf("Capturing to file: %v\n", fileName)
	writer := pcapgo.NewWriter(file)
	writer.WriteFileHeader(uint32(handle.SnapLen()), handle.LinkType())

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	startTime := time.Now()
	for {
		select {
		case <-notifyChan:
			return printStats(handle, startTime)
		case packet, ok := <-packets:
			if !ok {
				return nil
			}
			writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		}
	}
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
	fmt.Printf("Capture Duration: %v\n", timeDiff.Truncate(time.Millisecond).String())
	return nil
}

func awaitSignal(notifyChan chan struct{}) {
	signalChan := make(chan os.Signal, 1)

	signal.Notify(signalChan, os.Interrupt, syscall.SIGQUIT)

	<-signalChan
	fmt.Println("Stopping Packet Capture..............")
	notifyChan <- struct{}{}
}
