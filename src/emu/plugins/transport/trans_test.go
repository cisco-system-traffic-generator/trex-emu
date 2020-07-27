// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package transport

import (
	"emu/core"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"testing"
	"time"
)

const (
	TRAN_PLUG = "transport"
)

var monitor int

type TransportTestBase struct {
	testname     string
	monitor      bool
	match        uint8
	capture      bool
	duration     time.Duration
	clientsToSim int
	cb           TransportTestCb
	amount       uint32
	cbArg1       interface{}
	cbArg2       interface{}
}

type TransportTestCb func(tctx *core.CThreadCtx, test *TransportTestBase) int

func (o *TransportTestBase) Run(t *testing.T, compare bool) {

	var simVeth VethIcmpSim
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
	nsplg := ns.PluginCtx.Get(TRAN_PLUG)
	if nsplg == nil {
		t.Fatalf(" can't find plugin")
	}
	//icmpPlug := nsplg.Ext.(*PluginIcmpNs)
	//icmpPlug.cdb.Dump()
	//tctx.SimRecordAppend(icmpPlug.cdb.MarshalValues(false))
	//if compare {
	//tctx.SimRecordCompare(o.testname, t)
	//}
}

func createSimulationEnv(simRx *core.VethIFSim, num int) (*core.CThreadCtx, *core.CClient) {
	tctx := core.NewThreadCtx(0, 4510, true, simRx)
	var key core.CTunnelKey
	key.Set(&core.CTunnelData{Vport: 1, Vlans: [2]uint32{0x81000001, 0x81000002}})
	ns := core.NewNSCtx(tctx, &key)
	tctx.AddNs(&key, ns)
	for j := 0; j < num; j++ {
		a := uint8((j >> 8) & 0xff)
		b := uint8(j & 0xff)
		var dg core.Ipv4Key
		if num == 1 {
			dg = core.Ipv4Key{16, 0, 0, 2}
		} else {
			dg = core.Ipv4Key{16, 1, a, b}
		}
		client := core.NewClient(ns, core.MACKey{0, 0, 1, 0, a, b},
			core.Ipv4Key{16, 0, a, b},
			core.Ipv6Key{},
			dg)
		ns.AddClient(client)
		//	client.PluginCtx.CreatePlugins([]string{"icmp"}, [][]byte{})
	}
	//tctx.RegisterParserCb("icmp")
	return tctx, nil
}

type VethIcmpSim struct {
	cnt   uint8
	match uint8
	tctx  *core.CThreadCtx
}

func (o *VethIcmpSim) ProcessTxToRx(m *core.Mbuf) *core.Mbuf {
	m.FreeMbuf()
	return nil
}

var a int = 12
var b int = 13

/*TestPluginIcmp1 - does not answer to default gateway, should repeat query */

func testReadOffset(tobuf []byte) {
	copy(tobuf[:], []byte{1, 2, 3, 4})
}

func TestPluginTrans1(t *testing.T) {
	tctx := core.NewThreadCtx(0, 4510, false, nil)
	s := newTxSocket(tctx, 32*1024)
	s.sanityCheck()
	fmt.Printf("%v \n", s)
	for i := 0; i < 32*1024+1; i++ {
		s.writeHead([]byte{byte(i)})
	}
	//for i := 0; i < 4; i++ {
	//	s.writeHead([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
	//}
	//for i := 0; i < 9; i++ {
	//		s.writeHead([]byte{byte(i)})
	//	}

	fmt.Printf("%v \n", s)
	s.sbdrop(1024)
	fmt.Printf("%v \n", s)
	s.sbdrop(1023)
	fmt.Printf("%v \n", s)
	s.sbdrop(2)
	fmt.Printf("%v \n", s)
	s.sbdrop(30300)
	fmt.Printf("%v \n", s)
	s.sbdrop(400)
	fmt.Printf("%v \n", s)
	s.sbdrop_all()
	fmt.Printf("%v \n", s)
	s.onRemove()
}

func getTestBuffer(cnt int, size int) []byte {
	var b []byte
	b = make([]byte, size)
	for i := 0; i < size; i++ {
		b[i] = byte(cnt + i)
	}
	return b
}

func compareReadBuf(s *txSocketQueue, cnt int, size int) {
	var b []byte
	b = make([]byte, size)
	niter := rand.Intn(10)
	fmt.Printf(" vec : %v \n", s)
	for j := 0; j < niter; j++ {

		roffset := uint32(rand.Intn(int(size)))
		readz := uint32(uint32(size) - roffset)
		fmt.Printf(" [iter:%v] %v offset %v:%v:%v \n", j, size, roffset, readz, roffset+readz)
		if readz > 0 {
			if roffset == 3338 {
				fmt.Printf(" here \n")
			}
			s.readOffset(roffset, readz, b)
			for i := 0; i < int(readz); i++ {
				if b[i] != byte(cnt+i+int(roffset)) {
					panic(" b[i] != byte(cnt+i) ")
				}
			}
		}
	}
}

func compareReadBufBasic(s *txSocketQueue, cnt int, size int) {
	var b []byte
	b = make([]byte, size)
	s.readOffset(0, uint32(size), b)
	for i := 0; i < int(size); i++ {
		if b[i] != byte(cnt+i) {
			panic(" b[i] != byte(cnt+i) ")
		}
	}
}

func TestPluginTrans2(t *testing.T) {
	tctx := core.NewThreadCtx(0, 4510, false, nil)
	s := newTxSocket(tctx, 32*1024)
	iter := 10
	cnt := 0
	readcnt := 0
	for i := 0; i < iter; i++ {
		fmt.Printf(" iter %d \n", i)
		size := rand.Intn(int(s.getFreeSize()) + 1)
		buf := getTestBuffer(cnt, size)
		fmt.Printf(" add buffer %v \n", size)
		if s.writeHead(buf) != size {
			panic(" can't be")
		}
		cnt += size
		fmt.Printf("after add \n")
		fmt.Printf("%v \n", s)

		s.sanityCheck()
		di := rand.Intn(10)
		for j := 0; j < di; j++ {
			fmt.Printf(" drop-iter %d \n", j)
			// eat
			if s.getSize() == 0 {
				break
			}
			d := uint32(rand.Intn(int(s.getSize() + 1)))
			fmt.Printf(" drop size %v \n", d)
			if d > 0 {
				compareReadBuf(s, readcnt, int(d))
				s.sbdrop(d)
				readcnt += int(d)
				s.sanityCheck()
			}
			//compareReadBufBasic(s, readcnt, int(d))
		}
		fmt.Printf("%v \n", s)
	}
	//for {

	//}
	//s.sanityCheck()
	/*
		fmt.Printf("%v \n", s)
		for i := 0; i < 32*1024+1; i++ {
			s.writeHead([]byte{byte(i)})
		}
		//for i := 0; i < 4; i++ {
		//	s.writeHead([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
		//}
		//for i := 0; i < 9; i++ {
		//		s.writeHead([]byte{byte(i)})
		//	}

		fmt.Printf("%v \n", s)
		s.sbdrop(1024)
		fmt.Printf("%v \n", s)
		s.sbdrop(1023)
		fmt.Printf("%v \n", s)
		s.sbdrop(2)
		fmt.Printf("%v \n", s)
		s.sbdrop(30300)
		fmt.Printf("%v \n", s)
		s.sbdrop(400)
		fmt.Printf("%v \n", s)
		s.sbdrop_all()
		fmt.Printf("%v \n", s)
		s.onRemove()*/
}

type TransportSimTestBase struct {
	testname     string
	monitor      bool
	match        uint8
	capture      bool
	duration     time.Duration
	clientsToSim int
	cb           TransportTestCb
	amount       uint32
	cbArg1       interface{}
	cbArg2       interface{}
	param        transportSimParam
}

func (o *TransportSimTestBase) Run(t *testing.T, compare bool) {
	rand.Seed(0x1234)
	sim := newTransportSim(&o.param)

	m := false
	if monitor > 0 {
		m = true
	}

	sim.tctx.Veth.SetDebug(m, o.capture)
	sim.tctx.MainLoopSim(o.duration)
	fmt.Printf("\n== Client counters === \n")
	sim.client.ctx.cdbv.Dump()
	fmt.Printf("\n== Server counters === \n")
	sim.server.ctx.cdbv.Dump()

	acf := sim.client.ctx.getActiveFlows() + sim.server.ctx.getActiveFlows()
	if acf > 0 {
		panic(" active flows exists")
	}

	defer sim.tctx.Delete()
	sim.tctx.SimRecordCompare(o.testname, t)
}

func TestPluginTrans4(t *testing.T) {
	a := &TransportSimTestBase{
		testname:     "tcp1",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     10 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:                    "a",
			sendRandom:              false,
			totalClientToServerSize: 1024,
			chunkSize:               1024,
			closeByClient:           true},
	}
	a.Run(t, false)
}

func TestPluginV601(t *testing.T) {
	a := &TransportSimTestBase{
		testname:     "tcp1-v6",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     10 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:                    "a",
			sendRandom:              false,
			totalClientToServerSize: 1024,
			chunkSize:               1024,
			closeByClient:           true,
			ipv6:                    true},
	}
	a.Run(t, false)
}

func TestPluginV602(t *testing.T) {
	a := &TransportSimTestBase{
		testname:     "tcp1-v6-02",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     10 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:                    "a",
			sendRandom:              false,
			totalClientToServerSize: 60000,
			chunkSize:               60000,
			closeByClient:           true,
			ipv6:                    true},
	}
	a.Run(t, false)
}

func TestPluginTrans6(t *testing.T) {
	a := &TransportSimTestBase{
		testname:     "tcp1-6",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     10 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:                    "a",
			sendRandom:              false,
			totalClientToServerSize: 5024,
			chunkSize:               5024,
			closeByClient:           true},
	}
	a.Run(t, false)
}

func TestPluginTrans7(t *testing.T) {
	a := &TransportSimTestBase{
		testname:     "tcp1-7",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     10 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:                    "a",
			sendRandom:              false,
			totalClientToServerSize: 60000,
			chunkSize:               60000,
			closeByClient:           true},
	}
	a.Run(t, false)
}

func TestPluginTrans8(t *testing.T) {
	a := &TransportSimTestBase{
		testname:     "tcp1-8",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     100 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:                    "a",
			sendRandom:              true,
			totalClientToServerSize: 60000,
			chunkSize:               5000,
			closeByClient:           true,
			debug:                   false},
	}
	a.Run(t, false)
}

// close by server
func TestPluginTrans9(t *testing.T) {
	a := &TransportSimTestBase{
		testname:     "tcp1-9",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     10 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:                    "a",
			sendRandom:              false,
			totalClientToServerSize: 1024,
			chunkSize:               1024,
			closeByClient:           false},
	}
	a.Run(t, false)
}

// check reset by client
func TestPluginTrans10(t *testing.T) {
	a := &TransportSimTestBase{
		testname:     "tcp1-10",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     10 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:                    "a",
			sendRandom:              false,
			totalClientToServerSize: 1024,
			chunkSize:               1024,
			closeByClient:           true,
			CloseByRst:              true},
	}
	a.Run(t, false)
}

// random packet drop
func TestPluginTrans11(t *testing.T) {
	a := &TransportSimTestBase{
		testname:     "tcp1-11",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     200 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:                    "a",
			sendRandom:              false,
			totalClientToServerSize: 60024,
			chunkSize:               5000,
			closeByClient:           true,
			drop:                    0.1},
	}
	a.Run(t, false)
}

// keepalive
func TestPluginTrans12(t *testing.T) {
	a := &TransportSimTestBase{
		testname:     "tcp1-12",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     200 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:                    "a",
			sendRandom:              false,
			totalClientToServerSize: 60024,
			chunkSize:               5000,
			closeByClient:           true,
			drop:                    0.1},
	}
	a.Run(t, false)
}

// test server -> client
// name of the test is "s_c"

func TestPluginTransSc1(t *testing.T) {
	a := &TransportSimTestBase{
		testname:     "tcpsc-1",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     200 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:                    "s_c",
			sendRandom:              false,
			totalClientToServerSize: 1024,
			chunkSize:               1024,
			closeByClient:           true,
			drop:                    0},
	}
	a.Run(t, false)
}

func TestPluginTransSc2(t *testing.T) {
	a := &TransportSimTestBase{
		testname:     "tcpsc-2",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     200 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:                    "s_c",
			sendRandom:              true,
			totalClientToServerSize: 60024,
			chunkSize:               5000,
			closeByClient:           true,
			drop:                    0},
	}
	a.Run(t, false)
}

func TestPluginTransSc3(t *testing.T) {
	a := &TransportSimTestBase{
		testname:     "tcpsc-3",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     200 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:                    "s_c",
			sendRandom:              true,
			totalClientToServerSize: 60024,
			chunkSize:               5000,
			closeByClient:           false,
			drop:                    0},
	}
	a.Run(t, false)
}

func TestPluginTransSc4(t *testing.T) {
	a := &TransportSimTestBase{
		testname:     "tcpsc-4",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     200 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:                    "s_c",
			sendRandom:              true,
			totalClientToServerSize: 60024,
			chunkSize:               5000,
			closeByClient:           false,
			drop:                    0.02},
	}
	a.Run(t, false)
}

// request response #1 , client sends request and server send response
func TestPluginTransrr1(t *testing.T) {
	a := &TransportSimTestBase{
		testname:     "tcprr-1",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     200 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name: "r_r",
			drop: 0},
	}
	a.Run(t, false)
}

func TestPluginTransIoctl1(t *testing.T) {
	a := &TransportSimTestBase{
		testname:     "ioctl1",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     10 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:                    "a",
			sendRandom:              false,
			totalClientToServerSize: 1024,
			chunkSize:               1024,
			closeByClient:           true,
			ioctlc:                  &map[string]interface{}{"tos": 1, "ttl": 7, "mss": 512},
			ioctls:                  &map[string]interface{}{"tos": 0x11, "ttl": 0x17},
		},
	}
	a.Run(t, false)
}

func TestPluginTransIoctl2(t *testing.T) {
	a := &TransportSimTestBase{
		testname:     "ioctl2",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     10 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:                    "a",
			sendRandom:              false,
			totalClientToServerSize: 1024,
			chunkSize:               1024,
			closeByClient:           true,
			ioctlc:                  &map[string]interface{}{"mss": 32, "initwnd": 20},
		},
	}
	a.Run(t, false)
}

func TestPluginTransIoctl3(t *testing.T) {
	a := &TransportSimTestBase{
		testname:     "ioctl3",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     10 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:                    "a",
			sendRandom:              false,
			totalClientToServerSize: 5000,
			chunkSize:               5000,
			closeByClient:           true,
			ioctlc:                  &map[string]interface{}{"no_delay": 2},
		},
	}
	a.Run(t, false)
}

func TestPluginTransIoctl4(t *testing.T) {
	a := &TransportSimTestBase{
		testname:     "ioctl4",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     10 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:                    "a",
			sendRandom:              false,
			totalClientToServerSize: 10000,
			chunkSize:               10000,
			closeByClient:           true,
			//ioctlc:                  &map[string]interface{}{"no_delay": 0, "no_delay_counter": 0},
			ioctls: &map[string]interface{}{"no_delay": 0, "no_delay_counter": 0},
		},
	}
	a.Run(t, false)
}

func TestPluginTransIoctl5(t *testing.T) {
	a := &TransportSimTestBase{
		testname:     "ioctl5",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     100 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:                    "a",
			sendRandom:              false,
			totalClientToServerSize: 10000,
			chunkSize:               10000,
			closeByClient:           true,
			ioctlc:                  &map[string]interface{}{"txbufsize": 128 * 1024, "rxbufsize": 128 * 1024},
			ioctls:                  &map[string]interface{}{"rxbufsize": 2 * 1024},
		},
	}
	a.Run(t, false)
}

func MyDial(network, address string) error {
	fmt.Printf(" %v %v \n", network, address)
	host, port, err := net.SplitHostPort(address)
	fmt.Printf(" %v : %v : %v \n", host, port, err)
	ip := net.ParseIP(host)
	fmt.Printf(" %v \n", []byte(ip))
	return nil
}

func TestPluginTransFt1(t *testing.T) {
	var ctx transportCtx

	ctx.Dial("tcp", "16.0.0.1:80", nil, nil)
	ctx.Dial("tcp", "[2001:db8::1]:80", nil, nil)

}

func TestPluginTransFt2(t *testing.T) {
	var src srcPortManager
	rand.Seed(0x1234)
	a := &TransportSimTestBase{
		testname:     "ioctl5",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     100 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:                    "a",
			sendRandom:              false,
			totalClientToServerSize: 10000,
			chunkSize:               10000,
			closeByClient:           true,
			ioctlc:                  &map[string]interface{}{"txbufsize": 128 * 1024, "rxbufsize": 128 * 1024},
			ioctls:                  &map[string]interface{}{"rxbufsize": 2 * 1024},
		},
	}
	sim := newTransportSim(&a.param)
	src.init(sim.client.ctx)

	for i := 0; i < 10; i++ {
		fmt.Printf(" %v \n", src.allocPort(0x11))
	}

	for i := 0; i < 10; i++ {
		src.freePort(0x11, 1025+uint16(i))
	}

	for i := 0; i < 10; i++ {
		fmt.Printf(" %v \n", src.allocPort(0x11))
	}

	sim.client.ctx.cdbv.Dump()
}

func TestPluginUdp1(t *testing.T) {
	a := &TransportSimTestBase{
		testname:     "tcp-udp1",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     10 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:                    "r_r",
			sendRandom:              false,
			totalClientToServerSize: 1024,
			chunkSize:               1024,
			closeByClient:           true,
			udp:                     true,
		},
	}
	a.Run(t, false)
}

func TestPluginUdp2(t *testing.T) {
	a := &TransportSimTestBase{
		testname:     "tcp-udp2",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     10 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:                    "r_r",
			sendRandom:              false,
			totalClientToServerSize: 1024,
			chunkSize:               1024,
			closeByClient:           true,
			udp:                     true,
			ipv6:                    true,
		},
	}
	a.Run(t, false)
}

func init() {
	flag.IntVar(&monitor, "monitor", 0, "monitor")
}
