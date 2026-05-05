// Package argparser offers command line argument parsing utilities.
package argparser

import (
	"errors"
	"fmt"

	"github.com/kakeetopius/gtap/internal/pcap"
	"github.com/pterm/pterm"
	"github.com/spf13/pflag"
)

var ErrHelp = errors.New("user requested help")

func ParseArgs(args []string) (pcap.Options, error) {
	flagSet := pflag.NewFlagSet("gtap", pflag.ContinueOnError)

	argOptions := pcap.Options{}
	var pcapFlags pcap.FlagSet
	if len(args) < 2 {
		pcapFlags = pcapFlags.Set(pcap.CaptureAllFlag)
		argOptions.Flags = pcapFlags
		return argOptions, nil
	}
	auto := flagSet.BoolP("auto", "a", false, "Capture packets on the first non-loopback network interface found that is up and running. Not supported on Windows.")
	filter := flagSet.StringP("filter", "f", "", "A filter to apply on the packets captured on an interface.")
	iface := flagSet.StringP("iface", "i", "", "A network interface to capture packets from only.")
	promisc := flagSet.BoolP("promisc", "p", false, "Set promiscous mode on the interface.")
	monitor := flagSet.BoolP("monitor", "m", false, "Set monitor mode on the interface. Only relevant for some wifi adapters.")
	writeFile := flagSet.StringP("write", "w", "", "Save captured packets to a pcap file. The file is first truncated to zero length")
	readFile := flagSet.StringP("read", "r", "", "Stream packets from a pcap file instead of a network interface.")
	summary := flagSet.BoolP("summary", "s", false, "Print packet structures in a summary form")
	hexdump := flagSet.BoolP("hex", "H", false, "Dump a hex version of the packet data.")

	flagSet.Usage = Usage(flagSet.FlagUsages())
	err := flagSet.Parse(args[1:])
	if err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return argOptions, ErrHelp
		}
		return argOptions, err
	}

	if len(flagSet.Args()) > 0 {
		return argOptions, fmt.Errorf("unexpected argument(s): %v", flagSet.Args())
	}
	if *auto {
		pcapFlags = pcapFlags.Set(pcap.AutoIfaceFlag)
	}
	if *promisc {
		pcapFlags = pcapFlags.Set(pcap.PromiscuousFlag)
	}
	if *monitor {
		pcapFlags = pcapFlags.Set(pcap.MonitorFlag)
	}
	if *hexdump {
		pcapFlags = pcapFlags.Set(pcap.HexDumpFlag)
	}
	if *summary {
		pcapFlags = pcapFlags.Set(pcap.SummaryFlag)
	}

	argOptions.Filter = *filter
	argOptions.IfaceName = *iface
	argOptions.OutputFile = *writeFile
	argOptions.InputFile = *readFile

	if !*auto && argOptions.IfaceName == "" {
		// if both auto and iface flags are not given we assume all packets are required.
		pcapFlags = pcapFlags.Set(pcap.CaptureAllFlag)
	}
	if pcapFlags.IsSet(pcap.SummaryFlag) && pcapFlags.IsSet(pcap.HexDumpFlag) {
		return argOptions, fmt.Errorf("cannot set both --summary and --hex flags")
	}

	argOptions.Flags = pcapFlags
	return argOptions, nil
}

func Usage(flagUsages string) func() {
	return func() {
		description := "gtap is a simple command line utility to capture, decode and display packet data.\nBy Default on unix systems if no options are given it captures all packets from all available network interfaces."

		usageStyle := pterm.NewStyle(pterm.Bold, pterm.FgBlue)

		usageStyle.Printf("Usage: ")
		pterm.Printf("gtap [OPTIONS]\n")
		usageStyle.Printf("\nDescription: ")
		fmt.Printf("%s\n\n", description)

		if flagUsages != "" {
			usageStyle.Println("Options: ")
			fmt.Println(flagUsages)
		}
	}
}
