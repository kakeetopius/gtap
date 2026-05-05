package pcap

import "net"

const (
	// capture all packets from all interfaces.
	CaptureAllFlag Flag = 1 << iota
	// put capturing interface in promiscuous mode
	PromiscuousFlag
	// put capturing interface in monitor mode
	MonitorFlag
	// automatically use the first non loopback interface found on the system to capture packets
	SelectIfaceFlag
	// display packets in hex form
	HexDumpFlag
	// display packets in summary form
	SummaryFlag
)

type (
	Flag    uint8
	FlagSet uint16
)

func (f FlagSet) Set(flag Flag) FlagSet {
	newFs := uint16(f) | uint16(flag)
	return FlagSet(newFs)
}

func (f FlagSet) IsSet(flag Flag) bool {
	return uint16(f)&uint16(flag) != 0
}

type Options struct {
	Flags      FlagSet
	Filter     string
	IfaceName  string
	InputFile  string
	OutputFile string
}

type Interface struct {
	PcapName string
	PcapDesc string
	net.Interface
}
