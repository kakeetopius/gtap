package decoding

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/kakeetopius/gtap/internal/util"
)

func DecodeNetworkLayer(packet gopacket.Packet) {
	if packet == nil {
		return
	}
	netLayer := packet.NetworkLayer()
	ip4, ok := netLayer.(*layers.IPv4)
	if ok {
		decodeIPv4(ip4)
	}
	ip6, ok := netLayer.(*layers.IPv6)
	if ok {
		decodeIPv6(ip6)
	}
	if arp := packet.Layer(layers.LayerTypeARP); arp != nil {
		arpPacket := arp.(*layers.ARP)
		decodeARP(arpPacket)
		return
	}
	DecodeTransportLayer(packet)
}

func decodeIPv4(packet *layers.IPv4) {
	util.PrintProtocolHeader("IPv4")
	util.PrintProtocolField("Version", packet.Version)
	util.PrintProtocolField("IHL", packet.IHL)
	util.PrintProtocolField("TOS", packet.TOS)
	util.PrintProtocolField("Len", util.Ntohs(packet.Length))
	util.PrintProtocolField("Flags", util.NumtoBinStr(packet.Flags))
	util.PrintProtocolField("TTL", packet.TTL)
	util.PrintProtocolField("Protocol", packet.Protocol.String())
	util.PrintProtocolField("Cheksum", util.NumtoHexStr(util.Ntohs(packet.Checksum)))
	util.PrintProtocolField("Src IP", packet.SrcIP.String())
	util.PrintProtocolField("Dst IP", packet.DstIP.String())
}

func decodeIPv6(packet *layers.IPv6) {
	util.PrintProtocolHeader("IPv6")
	util.PrintProtocolField("Version", packet.Version)
	util.PrintProtocolField("Traffic Class", packet.TrafficClass)
	util.PrintProtocolField("Flow Label", util.Ntohs(packet.FlowLabel))
	util.PrintProtocolField("Len", util.Ntohs(packet.Length))
	util.PrintProtocolField("Next Proto", packet.NextHeader.String())
	util.PrintProtocolField("Hop Limit", packet.HopLimit)
	util.PrintProtocolField("Src IP", packet.SrcIP.String())
	util.PrintProtocolField("Dst IP", packet.DstIP.String())
}

func decodeARP(packet *layers.ARP) {
	util.PrintProtocolHeader("ARP")
	opcode := util.Ntohs(packet.Operation)
	var opcodetxt string
	switch opcode {
	case 1:
		opcodetxt = "1 Request"
		util.PrintProtocolField("Opcode", opcodetxt)
		util.PrintProtocolField("Who is", net.IP(packet.DstProtAddress).String())
		util.PrintProtocolField("Tell", net.IP(packet.SourceProtAddress).String())
		util.PrintProtocolField("Src MAC", net.HardwareAddr(packet.SourceHwAddress).String())
		util.PrintProtocolField("Hw Type", packet.AddrType.String())
		util.PrintProtocolField("Hw size", packet.HwAddressSize)
		util.PrintProtocolField("Proto type", packet.Protocol.String())
		util.PrintProtocolField("Proto size", packet.ProtAddressSize)
	case 2:
		opcodetxt = "2 Response"
		util.PrintProtocolField("Opcode", opcodetxt)
		util.PrintProtocolField("IP", net.IP(packet.SourceProtAddress).String())
		util.PrintProtocolField("Is At", net.HardwareAddr(packet.SourceHwAddress).String())
		util.PrintProtocolField("Dst IP", net.IP(packet.DstProtAddress).String())
		util.PrintProtocolField("Dst MAC", net.HardwareAddr(packet.DstHwAddress).String())
		util.PrintProtocolField("Hw Type", packet.AddrType.String())
		util.PrintProtocolField("Hw size", packet.HwAddressSize)
		util.PrintProtocolField("Proto type", packet.Protocol.String())
		util.PrintProtocolField("Proto size", packet.ProtAddressSize)
	}
}
