// Copyright (c) 2021 Eolo S.p.A. and Altran Italia S.p.A. and/or them affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/hex"
	"external/google/gopacket"
	"fmt"
)

// core func for decode test
func CoreTestDecode(rawPacket []byte) gopacket.Packet {
	packet := gopacket.NewPacket(rawPacket, LayerTypeEthernet, gopacket.Default)

	// Get the Dot1Q layer from this packet
	if dot1qLayer := packet.Layer(LayerTypeDot1Q); dot1qLayer != nil {
		//fmt.Println("This is a Dot1Q packet!")
		dot1q, _ := dot1qLayer.(*Dot1Q)
		fmt.Printf(
			">> Dot1Q >> Type [%v] VLAN Id [%d] Priority [%d]\n",
			dot1q.Type, dot1q.VLANIdentifier, dot1q.Priority)
	}
	// Get the PPPoE layer from this packet
	if pppoeLayer := packet.Layer(LayerTypePPPoE); pppoeLayer != nil {
		// Code 0x00 means SessionData and PPPoES
		if pppoe, _ := pppoeLayer.(*PPPoE); pppoe.Code != PPPoECodeSession {
			fmt.Printf(
				">> PPPoED >> Code [%v] SessionID [%X] Length [%d] Type [%X] Version [%X]\n",
				PPPoECode(pppoe.Code), pppoe.SessionID, pppoe.Length, pppoe.Type, pppoe.Version)
			fmt.Printf(">> PPPoED >> Contiene %d Tags\n", len(pppoe.Tags))
			for _, tag := range pppoe.Tags {
				fmt.Printf(">> PPPoED Tags >> Contiene [%04X] Size %d\n",
					PPPoEDTagType(tag.Type), tag.Length)
			}
		} else if pppoe.Code == PPPoECodeSession {
			fmt.Printf(
				">> PPPoES >> Code [%v] SessionID [%X] Length [%d] Type [%X] Version [%X]\n",
				PPPoECode(pppoe.Code), pppoe.SessionID, pppoe.Length, pppoe.Type, pppoe.Version)
		}
	}

	if pppLayer := packet.Layer(LayerTypePPP); pppLayer != nil {
		fmt.Println("This is a PPP packet!")
		ppp, _ := pppLayer.(*PPP)
		fmt.Printf(
			">> PPP >> Type [%v]\n",
			ppp.PPPType)
	}

	if lcpLayer := packet.Layer(LayerTypeLCP); lcpLayer != nil {
		fmt.Println("This is a LCP packet!")
		lcp, _ := lcpLayer.(*LCP)
		fmt.Printf(
			">> LCP >> Type [%v]\n",
			lcp.Code)
		for _, option := range lcp.Options {
			fmt.Printf(">> LCP Options >> %v -> %v\n", option.Type, option.Value)
		}
	}

	if ipcpLayer := packet.Layer(LayerTypeIPCP); ipcpLayer != nil {
		fmt.Println("This is a IPCP packet!")
		ipcp, _ := ipcpLayer.(*IPCP)
		fmt.Printf(
			">> IPCP >> Type [%v]\n",
			ipcp.Code)
		for _, option := range ipcp.Options {
			fmt.Printf(">> IPCP Options >> %v -> %v\n", option.Type, option.Value)
		}
	}

	// Iterate over all layers, printing out each layer type
	for _, layer := range packet.Layers() {
		if layerType := layer.LayerType(); layerType != gopacket.LayerTypeDecodeFailure {
			fmt.Println("PACKET LAYER:", layer.LayerType())
		} else {
			fmt.Println("Unrecognized content:", layer.LayerContents())
		}
	}

	return packet
}

// core func for serialize test
func CoreTestSerialize(packet gopacket.Packet, rawPacket []byte) {

	//// Serialize parse packet
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	newBuffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializePacket(newBuffer, options, packet)
	if err != nil {
		panic(err)
	}
	outgoingPacket := newBuffer.Bytes()

	fmt.Printf("############## Hex dump of go packet serialization output [%d]:\n", len(outgoingPacket))
	fmt.Println(hex.Dump(outgoingPacket))
	fmt.Printf("############## Original packet size is [%d]:\n", len(rawPacket))
	//// Serialize parse packet - END

	fmt.Println(">>>>>>>>>>>>>>>>>>>>>")
}