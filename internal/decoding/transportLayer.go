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
	tcp, ok := transportLayer.(*layers.TCP)
	if ok {
		decodeTCP(tcp)
	}
	udp, ok := transportLayer.(*layers.UDP)
	if ok {
		decodeUDP(udp)
	}
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
	util.PrintProtocolField("Seq No", util.Ntohs(packet.Seq))
	util.PrintProtocolField("Ack Num", util.Ntohs(packet.Ack))
	util.PrintProtocolField("Checksum", util.NumtoHexStr(util.Ntohs(packet.Checksum)))
}

func decodeUDP(packet *layers.UDP) {
	util.PrintProtocolHeader("UDP")
	util.PrintProtocolField("Src Port", packet.SrcPort.String())
	util.PrintProtocolField("Dst Port", packet.DstPort.String())
	util.PrintProtocolField("Length", util.Ntohs(packet.Length))
	util.PrintProtocolField("Checksum", util.NumtoHexStr(util.Ntohs(packet.Checksum)))
}
