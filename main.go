package main

import (
	"errors"
	// "fmt"
	"os"

	"github.com/kakeetopius/gtap/internal/argparser"
	"github.com/kakeetopius/gtap/internal/pcap"
	"github.com/kakeetopius/gtap/internal/util"
)

func main() {
	opts, err := argparser.ParseArgs(os.Args)
	if err != nil {
		if !errors.Is(err, argparser.ErrHelp) {
			util.PrintError(err)
		}
		return
	}
	err = pcap.StartCapture(opts)
	if err != nil {
		util.PrintError(err)
	}

	// fmt.Println("──────────────────────────────────────────────")
	// util.PrintProtocolHeader("Ethernet")
	// util.PrintProtocolField("Src Mac", "00:22:44:66:88:aa")
	// util.PrintProtocolField("Dst Mac", "aa:bb:cc:ee:ff:83")
	// util.PrintProtocolField("Type", "IPv4")
	// fmt.Println()
	// util.PrintProtocolHeader("IPv4")
	// util.PrintProtocolField("Src IP", "192.168.22.1")
	// util.PrintProtocolField("Dst IP", "192.168.22.92")
	// util.PrintProtocolField("Version", "4")
	// fmt.Println()
	// util.PrintProtocolHeader("TCP")
	// util.PrintProtocolField("Src Port", "80")
	// util.PrintProtocolField("Dst Port", "443")
	// util.PrintProtocolField("Cheksum", "0x859394")
	// util.PrintProtocolField("Seq", "9841789714")
	// util.PrintProtocolField("Ack", "0989088189")
	// fmt.Println()
	// fmt.Println("──────────────────────────────────────────────")
	// util.PrintProtocolHeader("Ethernet")
	// util.PrintProtocolField("Src Mac", "00:22:44:66:88:aa")
	// util.PrintProtocolField("Dst Mac", "aa:bb:cc:ee:ff:83")
	// util.PrintProtocolField("Type", "IPv4")
	// fmt.Println()
	// util.PrintProtocolHeader("IPv4")
	// util.PrintProtocolField("Src IP", "192.168.22.1")
	// util.PrintProtocolField("Dst IP", "192.168.22.92")
	// util.PrintProtocolField("Version", "4")
	// fmt.Println()
	// util.PrintProtocolHeader("TCP")
	// util.PrintProtocolField("Src Port", "80")
	// util.PrintProtocolField("Dst Port", "443")
	// util.PrintProtocolField("Cheksum", "0x859394")
	// util.PrintProtocolField("Seq", "9841789714")
	// util.PrintProtocolField("Ack", "0989088189")
	// fmt.Println()
	// util.PrintProtocolHeader("HTTPS")
}
