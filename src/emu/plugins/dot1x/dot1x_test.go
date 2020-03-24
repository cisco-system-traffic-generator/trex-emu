// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package dot1x

import (
	"bytes"
	"crypto/md5"
	"emu/core"
	"encoding/binary"
	"encoding/hex"
	"external/google/gopacket/layers"
	"flag"
	"fmt"
	"testing"
	"time"
)

var monitor int

type Dot1xTestBase struct {
	testname     string
	dropAll      bool
	monitor      bool
	match        uint8
	capture      bool
	duration     time.Duration
	clientsToSim int
	cb           IgmpTestCb
	cbArg1       interface{}
	cbArg2       interface{}
}

type IgmpTestCb func(tctx *core.CThreadCtx, test *Dot1xTestBase) int

func (o *Dot1xTestBase) Run(t *testing.T) {

	var simVeth VethIgmpSim
	simVeth.DropAll = o.dropAll
	var simrx core.VethIFSim
	simrx = &simVeth
	if o.match > 0 {
		simVeth.match = o.match
	}
	tctx, _ := createSimulationEnv(&simrx, o.clientsToSim)
	if o.cb != nil {
		o.cb(tctx, o)
	}
	m := false
	if monitor > 0 {
		m = true
	}
	simVeth.tctx = tctx
	tctx.Veth.SetDebug(m, o.capture)
	tctx.MainLoopSim(o.duration)
	defer tctx.Delete()
	var key core.CTunnelKey
	key.Set(&core.CTunnelData{Vport: 1, Vlans: [2]uint32{0x81000001, 0x81000002}})

	ns := tctx.GetNs(&key)
	if ns == nil {
		t.Fatalf(" can't find ns")
		return
	}
	c := ns.CLookupByMac(&core.MACKey{0, 0, 1, 0, 0, 1})
	nsplg := c.PluginCtx.Get(DOT1X_PLUG)
	if nsplg == nil {
		t.Fatalf(" can't find plugin")
	}
	dot1xPlug := nsplg.Ext.(*PluginDot1xClient)
	dot1xPlug.cdbv.Dump()
	tctx.GetCounterDbVec().Dump()

	//tctx.SimRecordAppend(igmpPlug.cdb.MarshalValues(false))
	tctx.SimRecordCompare(o.testname, t)

}

func createSimulationEnv(simRx *core.VethIFSim, num int) (*core.CThreadCtx, *core.CClient) {
	tctx := core.NewThreadCtx(0, 4510, true, simRx)
	var key core.CTunnelKey
	key.Set(&core.CTunnelData{Vport: 1, Vlans: [2]uint32{0x81000001, 0x81000002}})
	ns := core.NewNSCtx(tctx, &key)

	tctx.AddNs(&key, ns)
	dg := core.Ipv4Key{0, 0, 0, 0}

	client := core.NewClient(ns, core.MACKey{0, 0, 1, 0, 0, 1},
		core.Ipv4Key{0, 0, 0, 0},
		core.Ipv6Key{},
		dg)
	ns.AddClient(client)

	var cinitJson [][]byte
	cinitJson = make([][]byte, 0)
	cinitJson = append(cinitJson, []byte(`{"user": "hhaim", "password":"432768ec1d"}`))

	ns.PluginCtx.CreatePlugins([]string{"dot1x"}, [][]byte{})
	client.PluginCtx.CreatePlugins([]string{"dot1x"}, cinitJson)
	ns.Dump()
	tctx.RegisterParserCb("dot1x")

	nsplg := ns.PluginCtx.Get(DOT1X_PLUG)
	if nsplg == nil {
		panic(" can't find plugin")
	}
	//nsPlug := nsplg.Ext.(*PluginDhcpNs)

	return tctx, nil
}

type VethIgmpSim struct {
	DropAll bool
	cnt     uint8
	match   uint8
	tctx    *core.CThreadCtx
}

func genMbuf(tctx *core.CThreadCtx, pkt []byte) *core.Mbuf {
	m := tctx.MPool.Alloc(uint16(len(pkt)))
	m.SetVPort(1)
	m.Append(pkt)
	return m
}

func (o *VethIgmpSim) ProcessTxToRx(m *core.Mbuf) *core.Mbuf {

	var mr *core.Mbuf
	mr = nil

	if o.DropAll {
		m.FreeMbuf()
		return nil
	}

	if o.match == 0 {
		switch o.cnt {
		case 0:
			pkt := GenerateOfferPacket(uint8(layers.EAPCodeRequest), 0, uint8(layers.EAPTypeIdentity), []byte{})
			mr = genMbuf(o.tctx, pkt)
		case 1:
			c, _ := hex.DecodeString("a1501e8bb2701d3d9b535594993f67a7")
			bsize := uint8(len(c))
			d := make([]byte, 0)
			d = append(d, bsize)
			d = append(d, c...)

			pkt := GenerateOfferPacket(uint8(layers.EAPCodeRequest), 0, uint8(EAP_TYPE_MD5), d)
			mr = genMbuf(o.tctx, pkt)
		case 2:
			pkt := GenerateOfferPacket(uint8(layers.EAPCodeSuccess), 0, 0, []byte{})
			mr = genMbuf(o.tctx, pkt)
		}
	}

	if o.match == 1 {
		switch o.cnt {
		case 0:
			pkt := GenerateOfferPacket(uint8(layers.EAPCodeRequest), 0, uint8(layers.EAPTypeIdentity), []byte{})
			mr = genMbuf(o.tctx, pkt)
		case 1:
			c, _ := hex.DecodeString("a1501e8bb2701d3d9b535594993f67a7")
			bsize := uint8(len(c)) + 5
			d := make([]byte, 0)
			d = append(d, MS_CHAPV2_CHALLENGE)
			d = append(d, 7)
			d = append(d, 0)
			d = append(d, bsize)
			d = append(d, 16)
			d = append(d, c...)

			pkt := GenerateOfferPacket(uint8(layers.EAPCodeRequest), 0, uint8(EAP_TYPE_MSCHAPV2), d)
			mr = genMbuf(o.tctx, pkt)
		case 2:
			r := "S=02015805D1D885FF9B15AB39693AEDC8B96C8101"
			l := uint8(len(r))
			d := make([]byte, 0)
			d = append(d, MS_CHAPV2_SUCCESS)
			d = append(d, 7)
			d = append(d, 0)
			d = append(d, l+5)
			d = append(d, l)
			d = append(d, []byte(r)...)

			pkt := GenerateOfferPacket(uint8(layers.EAPCodeSuccess), 0, uint8(EAP_TYPE_MSCHAPV2), d)
			mr = genMbuf(o.tctx, pkt)
		}
	}

	o.cnt++
	m.FreeMbuf()
	return mr
}

func getL2() []byte {
	l2 := []byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x03, 0, 0, 1, 0, 0, 2, 0x81, 00, 0x00, 0x01, 0x81, 00, 0x00, 0x02, 0x88, 0x8e}
	return l2
}

func GenerateOfferPacket(code uint8,
	id uint8,
	eaptype uint8,
	d []byte) []byte {

	l2 := getL2()
	l3 := uint16(len(l2))
	eapPkt := core.PacketUtlBuild(
		&layers.EAPOL{
			Version: 2,
			Type:    layers.EAPOLTypeEAP,
			Length:  0},
	)

	p := append(l2, eapPkt...)
	var leneap uint16
	var short bool

	if len(d) == 0 && (eaptype == 0) {
		short = true
		p = append(p, 0, 0, 0, 0)
		leneap = uint16(EAPSIZE_PKT_HEADER - 1)
	} else {
		p = append(p, 0, 0, 0, 0, 0)
		leneap = uint16(len(d) + EAPSIZE_PKT_HEADER)

	}
	p[l3] = 1 // set the new version
	p[l3+1] = byte(layers.EAPOLTypeEAP)
	binary.BigEndian.PutUint16(p[l3+2:l3+4], leneap)
	p[l3+4] = code
	p[l3+5] = id
	binary.BigEndian.PutUint16(p[l3+6:l3+8], leneap)
	if !short {
		p[l3+8] = eaptype
		p = append(p, d...)
	}
	return p
}

func TestPlugindot1x_1(t *testing.T) {
	a := &Dot1xTestBase{
		testname:     "dot1x_1",
		dropAll:      false,
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     60 * time.Second,
		clientsToSim: 1,
	}
	a.Run(t)
}

func TestPlugindot1x_2(t *testing.T) {
	authChallenge := []byte{
		0x5B, 0x5D, 0x7C, 0x7D, 0x7B, 0x3F, 0x2F, 0x3E,
		0x3C, 0x2C, 0x60, 0x21, 0x32, 0x26, 0x26, 0x28,
	}
	peerChallenge := []byte{
		0x21, 0x40, 0x23, 0x24, 0x25, 0x5E, 0x26, 0x2A,
		0x28, 0x29, 0x5F, 0x2B, 0x3A, 0x33, 0x7C, 0x7E,
	}
	res, e := Encryptv2(authChallenge, peerChallenge, "User", "clientPass")
	if e != nil {
		t.Fatal(e)
	}

	expect := []byte{
		0x82, 0x30, 0x9E, 0xCD, 0x8D, 0x70, 0x8B, 0x5E,
		0xA0, 0x8F, 0xAA, 0x39, 0x81, 0xCD, 0x83, 0x54,
		0x42, 0x33, 0x11, 0x4A, 0x3D, 0x85, 0xD6, 0xDF,
	}
	if bytes.Compare(res.ChallengeResponse, expect) != 0 {
		t.Fatal(fmt.Printf("TestEncryptMSCHAP2 bytes wrong. expect=%d found=%d", expect, res.ChallengeResponse))
	}

	if len(res.AuthenticatorResponse) != 42 {
		t.Fatal(fmt.Printf("TestEncryptMSCHAP2 authRes not 42-octets, found=%v", res.AuthenticatorResponse))
	}
}

func TestPlugindot1x_3(t *testing.T) {
	var a []byte
	a = make([]byte, 0)

	for i := 0; i < 2; i++ {
		genChalange16B(&a)
		fmt.Printf("%d,%d,%s \n", i, len(a), hex.Dump(a))

	}
}

func TestPlugindot1x_4(t *testing.T) {
	a := &Dot1xTestBase{
		testname:     "dot1x_4",
		dropAll:      false,
		monitor:      false,
		match:        1,
		capture:      true,
		duration:     60 * time.Second,
		clientsToSim: 1,
	}
	a.Run(t)
}

//1d26fddba3f9ad3f360d86eba7cba4b5
//hhaim
//cc2221916ff64b685df4d431cb93083d

func TestPlugindot1x_5(t *testing.T) {
	b := []byte{}
	b = b[:0] //[id,password,challeng]
	b = append(b, 254)
	b = append(b, []byte("hhaim")...)
	b = append(b, []byte{0x1d, 0x26, 0xfd, 0xdb, 0xa3, 0xf9, 0xad, 0x3f, 0x36, 0x0d, 0x86, 0xeb, 0xa7, 0xcb, 0xa4, 0xb5}...)
	r := md5.Sum(b)
	fmt.Printf("%s\n", hex.Dump(r[:]))
}

func TestPlugindot1x_6(t *testing.T) {
	b := []byte{}
	b = b[:0] //[id,password,challeng]
	b = append(b, 2)
	b = append(b, []byte("hhaim")...)
	b = append(b, []byte{0x00, 0x8e, 0x12, 0x48, 0xca, 0x7c, 0xeb, 0x4a, 0xce, 0xca, 0x32, 0x1d, 0xe9, 0xd1, 0xcd, 0x61}...)
	//b = append(b, []byte{0x1d, 0x26, 0xfd, 0xdb, 0xa3, 0xf9, 0xad, 0x3f, 0x36, 0x0d, 0x86, 0xeb, 0xa7, 0xcb, 0xa4, 0xb5}...)
	r := md5.Sum(b)
	fmt.Printf("%s\n", hex.Dump(r[:]))
}

func init() {
	flag.IntVar(&monitor, "monitor", 0, "monitor")
}
