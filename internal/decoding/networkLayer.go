package decoding

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/kakeetopius/gtap/internal/util"
)

func DecodeNetworkLayer(packet gopacket.Packet) {
	netLayer := packet.NetworkLayer()
	ip4, ok := netLayer.(*layers.IPv4)
	if ok {
		decodeIPv4(ip4)
	}
	ip6, ok := netLayer.(*layers.IPv6)
	if ok {
		decodeIPv6(ip6)
	}
}

func decodeIPv4(packet *layers.IPv4) {
	util.PrintProtocolHeader("IPv4")
	util.PrintProtocolField("Version", util.Htonstr(int(packet.Version)))
	util.PrintProtocolField("IHL", util.Htonstr(int(packet.IHL)))
	util.PrintProtocolField("TOS", util.Htonstr(int(packet.TOS)))
	util.PrintProtocolField("Len", util.Htonstr(int(packet.Length)))
	util.PrintProtocolField("Flags", util.Htonstr(int(packet.Flags)))
	util.PrintProtocolField("TTL", util.Htonstr(int(packet.TTL)))
	util.PrintProtocolField("Protocol", packet.Protocol.String())
	util.PrintProtocolField("Cheksum", util.Htonstr(int(packet.Checksum)))
	util.PrintProtocolField("Src IP", packet.SrcIP.String())
	util.PrintProtocolField("Dst IP", packet.DstIP.String())
}

func decodeIPv6(packet *layers.IPv6) {
	util.PrintProtocolHeader("IPv6")
	util.PrintProtocolField("Traffic Class", string(packet.TrafficClass))
	util.PrintProtocolField("Flow Label", util.Htonstr(int(packet.FlowLabel)))
	util.PrintProtocolField("Len", util.Htonstr(int(packet.Length)))
	util.PrintProtocolField("Next Proto", packet.NextHeader.String())
	util.PrintProtocolField("Src IP", packet.SrcIP.String())
	util.PrintProtocolField("Dst IP", packet.DstIP.String())
}
