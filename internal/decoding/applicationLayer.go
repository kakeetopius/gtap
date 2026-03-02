package decoding

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/kakeetopius/gtap/internal/util"
	// "github.com/kakeetopius/gtap/internal/util"
)

func decodeApplicationLayer(packet gopacket.Packet) {
	if packet == nil {
		return
	}

	tpLayer := packet.TransportLayer()
	if tcp, ok := tpLayer.(*layers.TCP); ok {
		if tcp.SrcPort == 80 || tcp.DstPort == 80 {
			http := tcp.LayerPayload()
			if len(http) > 0 {
				util.PrintProtocolHeader("HTTP")
				fmt.Printf("%s\n", tcp.LayerPayload())
			}
		}
	}

	applicationLayer := packet.ApplicationLayer()
	if dns, ok := applicationLayer.(*layers.DNS); ok {
		decodeDNS(dns)
	}
}

func decodeDNS(packet *layers.DNS) {
	util.PrintProtocolHeader("DNS")
	util.PrintProtocolField("ID", packet.ID)
	var message string
	if packet.QR {
		message = "Response"
	} else {
		message = "Query"
	}
	util.PrintProtocolField("Type", message)
	util.PrintProtocolField("Authoritative Answer", packet.AA)
	util.PrintProtocolField("Truncated", packet.TC)
	util.PrintProtocolField("Recursion desired", packet.RD)
	util.PrintProtocolField("Recursion Available", packet.RA)
	util.PrintProtocolField("Response Code", packet.ResponseCode.String())
	util.PrintProtocolField("QDCount", packet.QDCount)
	util.PrintProtocolField("ANCount", packet.ANCount)
	util.PrintProtocolField("NSCount", packet.NSCount)
	util.PrintProtocolField("ARCount", packet.ARCount)

	if len(packet.Questions) > 0 {
		util.PrintProtocolHeader("DNSQR")
	}
	for i, query := range packet.Questions {
		util.PrintProtocolHeader2(fmt.Sprintf("Query %v", i+1))
		util.PrintProtocolField("Name", string(query.Name))
		util.PrintProtocolField("Type", query.Type.String())
		util.PrintProtocolField("Class", query.Class.String())
	}

	if len(packet.Answers) > 0 {
		util.PrintProtocolHeader("DNSRR")
	}
	for i, answer := range packet.Answers {
		util.PrintProtocolHeader2(fmt.Sprintf("Response %v", i+1))
		util.PrintProtocolField("Name", string(answer.Name))
		util.PrintProtocolField("Type", answer.Type.String())
		util.PrintProtocolField("Class", answer.Class.String())
		util.PrintProtocolField("TTL", answer.TTL)
		util.PrintProtocolField("Data Len", answer.DataLength)
		util.PrintProtocolField("Record", answer.String())
	}

	// if len(packet.Authorities) > 0 {
	// 	util.PrintProtocolHeader("DNSNS")
	// }
	// for i, authority := range packet.Authorities {
	// 	util.PrintProtocolHeader2(fmt.Sprintf("Response %v", i+1))
	// 	util.PrintProtocolField("Name", string(authority.Name))
	// 	util.PrintProtocolField("Type", authority.Type.String())
	// 	util.PrintProtocolField("Class", authority.Class.String())
	// 	util.PrintProtocolField("TTL", authority.TTL)
	// 	util.PrintProtocolField("Data Len", authority.DataLength)
	// 	util.PrintProtocolField("Record", authority.String())
	// }
	//
	// if len(packet.Additionals) > 0 {
	// 	util.PrintProtocolHeader("DNSAD")
	// }
	// for i, additionals := range packet.Additionals {
	// 	util.PrintProtocolHeader2(fmt.Sprintf("Response %v", i+1))
	// 	util.PrintProtocolField("Name", string(additionals.Name))
	// 	util.PrintProtocolField("Type", additionals.Type.String())
	// 	util.PrintProtocolField("Class", additionals.Class.String())
	// 	util.PrintProtocolField("TTL", additionals.TTL)
	// 	util.PrintProtocolField("Data Len", additionals.DataLength)
	// 	util.PrintProtocolField("Record", additionals.String())
	// }
}
