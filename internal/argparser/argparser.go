// Package argparser offers command line argument parsing utilities.
package argparser

import (
	"errors"
	"fmt"

	"github.com/pterm/pterm"
	"github.com/spf13/pflag"
)

var ErrHelp = errors.New("user requested help")

const (
	CaptureAllFlag = 1 << iota
	FilterFlag
	PromiscuousFlag
	MonitorFlag
	AutoFlag
	IfaceFlag
	InputFileFlag
	OutputFileFlag
)

type cliArg struct {
	name        string
	shorthand   string
	placeholder string
	usage       string
}

type Options struct {
	Flags      uint16
	Filter     string
	IfaceName  string
	InputFile  string
	OutputFile string
}

func ParseArgs(args []string) (*Options, error) {
	flagSet := pflag.NewFlagSet("gtap", pflag.ContinueOnError)
	flagSet.Usage = Usage

	argOptions := Options{}
	if len(args) < 2 {
		argOptions.Flags |= CaptureAllFlag
		return &argOptions, nil
	}
	auto := flagSet.BoolP("auto", "a", false, "")
	filter := flagSet.StringP("filter", "f", "", "")
	iface := flagSet.StringP("iface", "i", "", "")
	writeFile := flagSet.StringP("write", "w", "", "")
	readFile := flagSet.StringP("read", "r", "", "")
	promisc := flagSet.BoolP("promisc", "p", false, "")
	monitor := flagSet.BoolP("monitor", "m", false, "")

	err := flagSet.Parse(args[1:])
	if err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return &argOptions, ErrHelp
		}
		return &argOptions, err
	}

	if len(flagSet.Args()) > 0 {
		return &argOptions, fmt.Errorf("unexpected argument(s): %v", flagSet.Args())
	}
	if *auto {
		argOptions.Flags |= AutoFlag
	}
	if *promisc {
		argOptions.Flags |= PromiscuousFlag
	}
	if *monitor {
		argOptions.Flags |= MonitorFlag
	}
	if flagSet.Changed("filter") {
		argOptions.Filter = *filter
		argOptions.Flags |= FilterFlag
	}
	if flagSet.Changed("iface") {
		argOptions.IfaceName = *iface
		argOptions.Flags |= IfaceFlag
	}
	if flagSet.Changed("write") {
		argOptions.OutputFile = *writeFile
		argOptions.Flags |= OutputFileFlag
	}
	if flagSet.Changed("read") {
		argOptions.InputFile = *readFile
		argOptions.Flags |= InputFileFlag
	}
	if !*auto && argOptions.Flags&IfaceFlag == 0 {
		// if both auto and iface flags are not given we assume all packets are required.
		argOptions.Flags |= CaptureAllFlag
	}

	return &argOptions, nil
}

func Usage() {
	description := "gtap is a simple command line utility to capture, decode and display packet data.\nBy Default if no options are given it captures all packets from all available network interfaces."

	usageStyle := pterm.NewStyle(pterm.FgBlue)
	descriptionStyle := pterm.NewStyle(pterm.FgMagenta)
	placeHolderStyle := pterm.NewStyle(pterm.FgYellow)

	usageStyle.Printf("Usage: ")
	pterm.Printf("gtap [OPTIONS]\n")
	usageStyle.Printf("\nDescription: ")
	descriptionStyle.Printf("%s\n\n", description)

	argHelp := []cliArg{
		{"auto", "a", "", "Capture packets on the first non-loopback network interface found that is up and running."},
		{"filter", "f", "FILTER", "A filter to apply on the packets captured on an interface. If --iface or --auto is not given the filter is applied on all interfaces"},
		{"iface", "i", "IFACE", "A network interface to capture packets from only."},
		{"promisc", "p", "", "Set promiscous mode on the interface."},
		{"monitor", "m", "", "Set monitor mode. Only relevant for some wifi adapters."},
		{"write", "w", "FILE", "Save captured packets to a pcap file. The file is first truncated to zero length"},
		{"read", "r", "FILE", "Stream packets from a pcap file instead of a network interface."},
		{"verbose", "v", "", "Print packet structures in an expanded form"},
		{"hex", "H", "", "Dump a hex version of the packet data for debugging purposes."},
		{"help", "h", "", "Show this help message."},
	}

	argNameStyle := pterm.NewStyle(pterm.FgCyan)
	shortHandStyle := pterm.NewStyle(pterm.FgLightGreen)
	helpStyle := pterm.NewStyle(pterm.FgDefault)

	usageStyle.Printf("Options: \n")
	for _, arg := range argHelp {
		shortHandStyle.Printf("-%s,  ", arg.shorthand)
		argNameStyle.Printf("--%s ", arg.name)
		placeHolderStyle.Printf("%s", arg.placeholder)
		if arg.placeholder == "" {
			fmt.Printf("\t")
		}
		fmt.Printf("\t\t")
		helpStyle.Printf("%s", arg.usage)

		fmt.Printf("\n")
	}
	fmt.Printf("\n")
}
