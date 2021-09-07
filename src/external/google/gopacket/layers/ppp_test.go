// Copyright (c) 2021 Eolo S.p.A. and Altran Italia S.p.A. and/or them affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"testing"
)

/**
>> MANCA rfc1661 FATTO
PPP_LCP_Configure
PPP_LCP_MRU_Option
PPP_LCP_Magic_Number_Option
PPP_LCP_Echo
PPP_LCP_Terminate

>> MANCA rfc1334 FATTO
PPP_PAP_Request
PPP_PAP_Response

>> MANCA rfc1332 FATTO
PPP_IPCP
PPP_IPCP_Option_IPAddress
**/

func TestDecodeSerializeLCP(t *testing.T) {

	// PPP LCP
	var rawLcp = []byte{
		0x9c, 0xff, 0x1a, 0x4b, 0xe8, 0x4d, 0x2c, 0x9a, 0xa4, 0xc8, 0xe3, 0x6c, 0x81, 0x00, 0x00, 0x32,
		0x88, 0x64, 0x11, 0x00, 0x00, 0x40, 0x00, 0x14, 0xc0, 0x21, 0x01, 0x01, 0x00, 0x12, 0x01, 0x04,
		0x05, 0xd4, 0x05, 0x06, 0x96, 0xea, 0x2f, 0x33, 0x03, 0x04, 0xc0, 0x23,
	}

	packet := CoreTestDecode(rawLcp)

	CoreTestSerialize(packet, rawLcp)
}

func TestDecodeSerializeLCPEchoRequestAndReply(t *testing.T) {

	// PPP LCP Echo Request
	var lcpEchoRequest = []byte{
		0x2c, 0x9a, 0xa4, 0xc8, 0xe3, 0x6c, 0x9c, 0xff, 0x1a, 0x4b, 0xe8, 0x4d, 0x81, 0x00, 0x00, 0x32,
		0x88, 0x64, 0x11, 0x00, 0x00, 0x40, 0x00, 0x0a, 0xc0, 0x21, 0x09, 0x03, 0x00, 0x08, 0x26, 0xf3,
		0x75, 0x5a,
	}

	packet1 := CoreTestDecode(lcpEchoRequest)

	CoreTestSerialize(packet1, lcpEchoRequest)

	// PPP LCP Echo Reply
	var lcpEchoReply = []byte{
		0x9c, 0xff, 0x1a, 0x4b, 0xe8, 0x4d, 0x2c, 0x9a, 0xa4, 0xc8, 0xe3, 0x6c, 0x81, 0x00, 0x00, 0x32,
		0x88, 0x64, 0x11, 0x00, 0x00, 0x40, 0x00, 0x0a, 0xc0, 0x21, 0x0a, 0x03, 0x00, 0x08, 0x96, 0xea,
		0x2f, 0x33,
	}

	packet2 := CoreTestDecode(lcpEchoReply)

	CoreTestSerialize(packet2, lcpEchoReply)
}

func TestDecodeSerializePAP(t *testing.T) {

	// PPP PAP
	var rawPap = []byte{
		0x2c, 0x9a, 0xa4, 0xc8, 0xe3, 0x6c, 0x9c, 0xff, 0x1a, 0x4b, 0xe8, 0x4d, 0x81, 0x00, 0x00, 0x32,
		0x88, 0x64, 0x11, 0x00, 0x00, 0x40, 0x00, 0x1b, 0xc0, 0x23, 0x01, 0x01, 0x00, 0x19, 0x0f, 0x65,
		0x6c, 0x69, 0x6f, 0x65, 0x6c, 0x69, 0x6f, 0x65, 0x6c, 0x69, 0x6f, 0x31, 0x34, 0x31, 0x04, 0x74,
		0x65, 0x73, 0x74,
	}

	packet := CoreTestDecode(rawPap)

	CoreTestSerialize(packet, rawPap)
}

func TestDecodeSerializeIPCP(t *testing.T) {

	// PPP IPCP
	var rawIpcp = []byte{
		0xba, 0x1a, 0x23, 0x87, 0x07, 0x93, 0x52, 0x55, 0x00, 0xe3, 0x0a, 0xb5, 0x88, 0x64, 0x11, 0x00,
		0x00, 0x40, 0x00, 0x0c, 0x80, 0x21, 0x01, 0x02, 0x00, 0x0a, 0x03, 0x06, 0x51, 0xae, 0x00, 0x15,
	}

	packet := CoreTestDecode(rawIpcp)

	CoreTestSerialize(packet, rawIpcp)
}
