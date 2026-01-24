// Package decoding is used to decode packet data and print fields within the packet.
package decoding

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/kakeetopius/gtap/internal/util"
)

func DecodeDataLink(packet gopacket.Packet) {
	linklayer := packet.LinkLayer()
	ethernetPacket, ok := linklayer.(*layers.Ethernet)
	if ok {
		decodeEthernet(ethernetPacket)
	}
	linuxsll, ok := linklayer.(*layers.LinuxSLL)
	if ok {
		decodelinuxSLL(linuxsll)
	}
	DecodeNetworkLayer(packet)
}

func decodeEthernet(packet *layers.Ethernet) {
	fmt.Println("──────────────────────────────────────────────")
	util.PrintProtocolHeader("Ethernet")
	util.PrintProtocolField("Src Mac", packet.SrcMAC.String())
	util.PrintProtocolField("Dst Mac", packet.DstMAC.String())
	util.PrintProtocolField("Type", packet.EthernetType.String())
}

func decodelinuxSLL(packet *layers.LinuxSLL) {
	fmt.Println("──────────────────────────────────────────────")
	util.PrintProtocolHeader("Linux Cooked Packet")
	addr := packet.Addr.String()
	if addr == "" {
		addr = "(none)"
	}
	util.PrintProtocolField("Src Addr", addr)
	util.PrintProtocolField("Type", packet.PacketType.String())
	util.PrintProtocolField("Ether Type", packet.EthernetType.String())
}
