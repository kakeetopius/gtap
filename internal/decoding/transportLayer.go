package decoding

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/kakeetopius/gtap/internal/util"
)

func DecodeTransportLayer(packet gopacket.Packet) {
	if packet == nil {
		return
	}
	transportLayer := packet.TransportLayer()
	if tcp, ok := transportLayer.(*layers.TCP); ok {
		decodeTCP(tcp)
	} else if udp, ok := transportLayer.(*layers.UDP); ok {
		decodeUDP(udp)
	} else {
		return
	}
	decodeApplicationLayer(packet)
}

func decodeTCP(packet *layers.TCP) {
	if packet.SYN {
		util.PrintProtocolHeader("TCP-SYN")
	} else if packet.SYN && packet.ACK {
		util.PrintProtocolHeader("TCP SYN-ACK")
	} else {
		util.PrintProtocolHeader("TCP")
	}
	util.PrintProtocolField("Src Port", packet.SrcPort.String())
	util.PrintProtocolField("Dst Port", packet.DstPort.String())
	util.PrintProtocolField("Seq No", packet.Seq)
	util.PrintProtocolField("Ack Num", packet.Ack)
	util.PrintProtocolField("Checksum", util.NumtoHexStr(packet.Checksum))
}

func decodeUDP(packet *layers.UDP) {
	util.PrintProtocolHeader("UDP")
	util.PrintProtocolField("Src Port", packet.SrcPort.String())
	util.PrintProtocolField("Dst Port", packet.DstPort.String())
	util.PrintProtocolField("Length", packet.Length)
	util.PrintProtocolField("Checksum", util.NumtoHexStr(packet.Checksum))
}
