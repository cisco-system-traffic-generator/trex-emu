// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package dot1x

import (
	"encoding/binary"
)

const (
	MS_CHAPV2_CHALLENGE  = 1
	MS_CHAPV2_RESPONSE   = 2
	MS_CHAPV2_SUCCESS    = 3
	MS_CHAPV2_FAILURE    = 4
	MS_CHAPV2_CHANGE_PWD = 7
)

type EapMschapv2Handler struct {
	b                     []byte
	r                     []byte
	peerChallenge         []byte
	authenticatorResponse string
	waitForSuccess        bool
}

func (o *EapMschapv2Handler) GetName() string {
	return ("eap-mschapv2")
}

func (o *EapMschapv2Handler) BuildResp(d *Dot1xMethodData) (bool, bool, []byte) {
	passwd := d.plug.cfg.Password
	user := d.plug.cfg.User
	if passwd != nil {
		if d.eap.Length >= (16+5+5) && (d.eap.TypeData != nil) {
			if len(d.eap.TypeData) >= (16 + 5) {
				b := d.eap.TypeData
				OpCode := b[0]
				msCHAPv2Id := b[1]
				MSLength := binary.BigEndian.Uint16(b[2:4])
				ValueSize := b[4]

				if (OpCode == MS_CHAPV2_SUCCESS) && (MSLength > 45) {
					s := string(d.eap.TypeData[4:])
					if len(s) == 42 {
						if s == o.authenticatorResponse {
							return true, true, []byte{MS_CHAPV2_SUCCESS}
						}
					}
				}

				if (OpCode == MS_CHAPV2_CHALLENGE) && (ValueSize == 16) && (MSLength >= 16+5) {
					authChallenge := d.eap.TypeData[5 : 5+16]
					if d.plug.Tctx.Simulation {
						o.peerChallenge = []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8}
					} else {
						genChalange16B(&o.peerChallenge)
					}
					res, e := Encryptv2(authChallenge, o.peerChallenge, *user, *passwd)
					if e != nil {
						d.plug.stats.pktMethodWrongLen++
						return false, false, []byte{}
					}

					/*The MS-CHAP-V2 Response packet is identical in format to the standard
					CHAP Response packet.  However, the Value field is sub-formatted
					differently as follows:

					// header
					uint8_t OpCode;
					uint8_t MS_CHAPv2_ID;
					uint16_t MS_Length;
					uint8_t Value_Size;


					16 octets: Peer-Challenge
					8 octets: Reserved, must be zero
					24 octets: NT-Response
					1 octet : Flags
					*/
					l := uint8(16 + 8 + 24 + 1)
					o.r = o.r[:0]
					o.r = append(o.r, MS_CHAPV2_RESPONSE)
					o.r = append(o.r, msCHAPv2Id)
					o.r = append(o.r, 0)
					o.r = append(o.r, l+5+uint8(len([]byte(*user))))
					o.r = append(o.r, l)

					o.r = append(o.r, o.peerChallenge...)
					o.r = append(o.r, 0, 0, 0, 0, 0, 0, 0, 0) //reserve
					o.r = append(o.r, res.ChallengeResponse...)
					o.r = append(o.r, 0) // flags
					o.r = append(o.r, []byte(*user)...)
					o.authenticatorResponse = res.AuthenticatorResponse
					return true, false, o.r
				}

			}
		}
		d.plug.stats.pktMethodWrongLen++
	} else {
		d.plug.stats.pktMethodNoPassword++
	}
	return false, false, []byte{}
}

func (o *EapMschapv2Handler) Success(d *Dot1xMethodData) bool {

	return true
}

func (o *EapMschapv2Handler) OnRemove() {

}

func NewEapMschapv2() Dot1xMethodIF {
	p := new(EapMschapv2Handler)
	p.b = make([]byte, 0)
	p.r = make([]byte, 0)
	p.waitForSuccess = false
	p.peerChallenge = make([]byte, 16)

	return p
}
