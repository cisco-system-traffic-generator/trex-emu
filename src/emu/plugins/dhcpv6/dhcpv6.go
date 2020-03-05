package dhcpv6

/*
RFC 8415  DHCPv6 client

client inijson {
	TimerDiscoverSec uint32 `json:"timerd"`
	TimerOfferSec    uint32 `json:"timero"`
}:

*/

import (
	"emu/core"
	"encoding/binary"
	"external/google/gopacket"
	"external/google/gopacket/layers"
	"external/osamingo/jsonrpc"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/intel-go/fastjson"
)

const (
	DHCPV6_PLUG = "dhcpv6"
	/* state of each client */
	DHCP_STATE_INIT       = 0
	DHCP_STATE_REBOOTING  = 1
	DHCP_STATE_REQUESTING = 2
	DHCP_STATE_SELECTING  = 3
	DHCP_STATE_REBINDING  = 4
	DHCP_STATE_RENEWING   = 5
	DHCP_STATE_BOUND      = 6
	IPV6_HEADER_SIZE      = 40
)

type DhcpInit struct {
	TimerDiscoverSec uint32 `json:"timerd"`
	TimerOfferSec    uint32 `json:"timero"`
}

type DhcpStats struct {
	pktTxDiscover    uint64
	pktRxOffer       uint64
	pktTxRequest     uint64
	pktRxAck         uint64
	pktRxLenErr      uint64
	pktRxParserErr   uint64
	pktRxWrongXid    uint64
	pktRxWrongHwType uint64
	pktRxWrongIP     uint64
	pktRxUnhandle    uint64
	pktRxNotify      uint64
	pktRxRenew       uint64
	pktRxNack        uint64
	pktRxRebind      uint64
}

func NewDhcpStatsDb(o *DhcpStats) *core.CCounterDb {
	db := core.NewCCounterDb("dhcpv6")

	db.Add(&core.CCounterRec{
		Counter:  &o.pktTxDiscover,
		Name:     "pktTxDiscover",
		Help:     "Tx discover ",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxOffer,
		Name:     "pktRxOffer",
		Help:     "received offer ",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.pktTxRequest,
		Name:     "pktTxRequest",
		Help:     "tx request",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxAck,
		Name:     "pktRxAck",
		Help:     "ack from the server",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxLenErr,
		Name:     "pktRxLenErr",
		Help:     "len error",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxParserErr,
		Name:     "pktRxParserErr",
		Help:     "parser error",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxUnhandle,
		Name:     "pktRxUnhandle",
		Help:     "unhandle dhcp packet",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxNotify,
		Name:     "pktRxNotify",
		Help:     "notify with new IPv6 addr",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxRenew,
		Name:     "pktRxRenew",
		Help:     "renew",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxNack,
		Name:     "pktRxNack",
		Help:     "nack",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxRebind,
		Name:     "pktRxRebind",
		Help:     "nack",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	return db
}

type PluginDhcpClientTimer struct {
}

func (o *PluginDhcpClientTimer) OnEvent(a, b interface{}) {
	pi := a.(*PluginDhcpClient)
	pi.onTimerEvent()
}

//PluginDhcpClient information per client
type PluginDhcpClient struct {
	core.PluginBase
	dhcpNsPlug *PluginDhcpNs
	timerw     *core.TimerCtx
	cnt        uint8
	state      uint8
	ticksStart uint64

	ipv6                       net.IP
	server                     net.IP
	serverMac                  core.MACKey
	dg                         core.Ipv4Key
	timer                      core.CHTimerObj
	stats                      DhcpStats
	cdb                        *core.CCounterDb
	cdbv                       *core.CCounterDbVec
	timerCb                    PluginDhcpClientTimer
	timerDiscoverRetransmitSec uint32
	timerOfferRetransmitSec    uint32
	t1                         uint32
	t2                         uint32
	discoverPktTemplate        []byte
	l3Offset                   uint16
	l4Offset                   uint16
	l7Offset                   uint16
	xid                        uint32
	iaid                       uint32
	serverOption               []byte
}

var dhcpEvents = []string{}

/*NewDhcpClient create plugin */
func NewDhcpClient(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	var init DhcpInit
	err := fastjson.Unmarshal(initJson, &init)

	o := new(PluginDhcpClient)
	o.InitPluginBase(ctx, o)             /* init base object*/
	o.RegisterEvents(ctx, dhcpEvents, o) /* register events, only if exits*/
	nsplg := o.Ns.PluginCtx.GetOrCreate(DHCPV6_PLUG)
	o.dhcpNsPlug = nsplg.Ext.(*PluginDhcpNs)
	o.OnCreate()

	if err == nil {
		/* init json was provided */
		if init.TimerDiscoverSec > 0 {
			o.timerDiscoverRetransmitSec = init.TimerDiscoverSec
		}
		if init.TimerOfferSec > 0 {
			o.timerOfferRetransmitSec = init.TimerOfferSec
		}
	}

	return &o.PluginBase
}

func (o *PluginDhcpClient) OnCreate() {
	o.timerw = o.Tctx.GetTimerCtx()
	o.preparePacketTemplate()
	o.timerDiscoverRetransmitSec = 5
	o.timerOfferRetransmitSec = 10
	o.cdb = NewDhcpStatsDb(&o.stats)
	o.cdbv = core.NewCCounterDbVec("dhcpv6")
	o.cdbv.Add(o.cdb)
	o.timer.SetCB(&o.timerCb, o, 0) // set the callback to OnEvent
	o.ticksStart = o.timerw.Ticks
	o.SendDiscover()
}

func (o *PluginDhcpClient) buildPacket(l2 []byte, dhcp *layers.DHCPv6) []byte {

	ipv6pkt := core.PacketUtlBuild(

		&layers.IPv6{
			Version:      6,
			TrafficClass: 0,
			FlowLabel:    0,
			Length:       8,
			NextHeader:   layers.IPProtocolUDP,
			HopLimit:     1,
			SrcIP:        net.IP{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			DstIP:        net.IP{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02},
		},

		&layers.UDP{SrcPort: 546, DstPort: 547},
		dhcp,
	)

	p := append(l2, ipv6pkt...)
	ipoffset := len(l2)

	pktSize := len(p)

	ipv6 := layers.IPv6Header(p[ipoffset : ipoffset+IPV6_HEADER_SIZE])

	// set local ip
	var l6 core.Ipv6Key
	o.Client.GetIpv6LocalLink(&l6)
	copy(ipv6.SrcIP()[:], l6[:])
	copy(p[0:6], []byte{0x33, 0x33, 0, 1, 0, 2})

	rcof := ipoffset + IPV6_HEADER_SIZE
	binary.BigEndian.PutUint16(p[rcof+4:rcof+6], uint16(pktSize-rcof))
	ipv6.SetPyloadLength(uint16(pktSize - rcof))
	ipv6.FixUdpL4Checksum(p[rcof:], 0)

	return p
}

func (o *PluginDhcpClient) preparePacketTemplate() {
	l2 := o.Client.GetL2Header(true, uint16(layers.EthernetTypeIPv6))
	o.l3Offset = uint16(len(l2))

	var xid uint32
	var iaid uint32
	if !o.Tctx.Simulation {
		xid = uint32(rand.Intn(0xffffff))
		iaid = uint32(rand.Intn(0xffffffff))
	} else {
		xid = 0x345678
		iaid = 0x12345678
	}
	o.xid = xid
	o.iaid = iaid

	dhcp := &layers.DHCPv6{MsgType: layers.DHCPv6MsgTypeSolicit,
		TransactionID: []byte{(byte((xid >> 16) & 0xff)), byte(((xid & 0xff00) >> 8)), byte(xid & 0xff)}}

	clientid := &layers.DHCPv6DUID{Type: layers.DHCPv6DUIDTypeLL, HardwareType: []byte{0, 1}, LinkLayerAddress: o.Client.Mac[:]}
	dhcp.Options = append(dhcp.Options, layers.NewDHCPv6Option(layers.DHCPv6OptClientID, clientid.Encode()))
	dhcp.Options = append(dhcp.Options, layers.NewDHCPv6Option(layers.DHCPv6OptOro, []byte{0, 0x11, 0, 0x17, 0, 0x18, 0x00, 0x27}))
	dhcp.Options = append(dhcp.Options, layers.NewDHCPv6Option(layers.DHCPv6OptVendorClass, []byte{0x00, 0x00, 0x01, 0x37, 0x00, 0x08, 0x4d, 0x53, 0x46, 0x54, 0x20, 0x35, 0x2e, 0x30}))

	ianao := []byte{0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00}

	binary.BigEndian.PutUint32(ianao[0:4], iaid)

	dhcp.Options = append(dhcp.Options, layers.NewDHCPv6Option(layers.DHCPv6OptIANA, ianao))
	dhcp.Options = append(dhcp.Options, layers.NewDHCPv6Option(layers.DHCPv6OptElapsedTime, []byte{0x00, 0x00}))

	o.l4Offset = o.l3Offset + IPV6_HEADER_SIZE
	o.l7Offset = o.l4Offset + 8

	o.discoverPktTemplate = o.buildPacket(l2, dhcp)

	//dhcp.Options = append(dhcp.Options, layers.NewDHCPv6Option(layers.DHCPv6OptElapsedTime, []byte{0x00, 0x00}))

	//dhcp.Options = append(dhcp.Options, layers.NewDHCPv6Option(layers.DHCPv6OptVendorClass, []byte{0x00, 0x00, 0x01, 0x37, 0x00, 0x08, 0x4d, 0x53, 0x46, 0x54, 0x20, 0x35, 0x2e, 0x30}))

	// just add the server option (save it and past it)
	//00 02 00 0e 00 01 00 01 21 54 ee e7 00 0c 29 70　3d d8

}

func (o *PluginDhcpClient) SendDhcpPacket(
	msgType byte,
	serverOption bool) {

	var msec uint32
	msec = uint32(o.timerw.Ticks-o.ticksStart) * o.timerw.MinTickMsec()

	pad := 0
	if serverOption {
		pad = len(o.serverOption)
	}

	m := o.Tctx.MPool.Alloc(uint16(len(o.discoverPktTemplate) + pad))
	m.Append(o.discoverPktTemplate)

	if serverOption {
		m.Append(o.serverOption)
	}

	p := m.GetData()

	of := o.l7Offset + 68 // time
	binary.BigEndian.PutUint16(p[of:of+2], uint16(msec/10))
	of = o.l7Offset
	p[of] = byte(msgType)

	ipv6o := o.l3Offset
	ipv6 := layers.IPv6Header(p[ipv6o : ipv6o+IPV6_HEADER_SIZE])

	if serverOption {
		newlen := ipv6.PayloadLength() + uint16(pad)
		ipv6.SetPyloadLength(newlen)
		binary.BigEndian.PutUint16(p[o.l4Offset+4:o.l4Offset+6], newlen)
	}

	ipv6.FixUdpL4Checksum(p[o.l4Offset:], 0)

	o.Tctx.Veth.Send(m)
}

func (o *PluginDhcpClient) DebugSendDiscover() {
	//o.Tctx.Veth.SendBuffer(false, o.Client, o.discoverPktTemplate)
	//o.timerw.Ticks
	//o.SendDiscoverPacket(180, 1, false)

	//o.serverOption = []byte{0x00, 0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x21, 0x54, 0xee, 0xe7, 0x00, 0x0c, 0x29, 0x70, 0x3d, 0xd8}
	//o.SendDiscoverPacket(190, 3, true)

}

func (o *PluginDhcpClient) SendDiscover() {
	o.state = DHCP_STATE_INIT
	o.cnt = 0
	o.restartTimer(o.timerDiscoverRetransmitSec)
	o.stats.pktTxDiscover++
	o.SendDhcpPacket(byte(layers.DHCPv6MsgTypeSolicit), false)
}

/*OnEvent support event change of IP  */
func (o *PluginDhcpClient) OnEvent(msg string, a, b interface{}) {

}

func (o *PluginDhcpClient) OnRemove(ctx *core.PluginCtx) {
	/* force removing the link to the client */
	o.SendRenewRebind(false, true, 0)
	ctx.UnregisterEvents(&o.PluginBase, dhcpEvents)
	// TBD send release message
	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}
}

func (o *PluginDhcpClient) SendRenewRebind(rebind bool, release bool, timerSec uint32) {

	o.stats.pktTxRequest++
	o.restartTimer(timerSec)

	if release {
		o.SendDhcpPacket(byte(layers.DHCPv6MsgTypeRelease), true)
		return
	}

	if rebind {
		o.SendDhcpPacket(byte(layers.DHCPv6MsgTypeRebind), true)
	} else {
		o.SendDhcpPacket(byte(layers.DHCPv6MsgTypeRenew), true)
	}
}

func (o *PluginDhcpClient) SendReq() {

	o.restartTimer(o.timerOfferRetransmitSec)
	o.SendDhcpPacket(byte(layers.DHCPv6MsgTypeRequest), true)
	o.stats.pktTxRequest++
}

func convert(ipv4 net.IP) core.Ipv4Key {
	var key core.Ipv4Key
	if len(ipv4) != 4 {
		return key
	}
	key[0] = ipv4[0]
	key[1] = ipv4[1]
	key[2] = ipv4[2]
	key[3] = ipv4[3]
	return key
}

func XidToUint32(xid []byte) uint32 {
	var res uint32
	if len(xid) != 3 {
		return 0xffffffff
	}
	res = uint32(xid[0])<<16 + uint32(xid[1])<<8 + uint32(xid[2])
	return res
}

func (o *PluginDhcpClient) verifyPkt(dhcph *layers.DHCPv6, ipv6 layers.IPv6Header) int {
	if XidToUint32(dhcph.TransactionID) != o.xid {
		o.stats.pktRxWrongXid++
		return -1
	}

	/*
		if dhcph.HardwareType != layers.LinkTypeEthernet {
			o.stats.pktRxWrongHwType++
			return -1
		}

		if dhcph.HardwareLen != 6 {
			o.stats.pktRxWrongHwType++
			return -1
		}

		o.ipv6 = dhcph.YourClientIP
		o.server = dhcph.NextServerIP

		skey := convert(dhcph.NextServerIP)

		if skey.IsZero() {
			o.stats.pktRxWrongIP++
			return -1
		}

		if len(dhcph.YourClientIP) != 4 {
			o.stats.pktRxWrongIP++
			return -1

		}
		key := convert(dhcph.YourClientIP)
		if key.Uint32() != ipv4.GetIPDst() {
			o.stats.pktRxWrongIP++
			return -1
		}
	*/
	return 0
}

func (o *PluginDhcpClient) restartTimer(sec uint32) {
	if sec == 0 {
		return
	}
	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}
	o.timerw.Start(&o.timer, time.Duration(sec)*time.Second)
}

func (o *PluginDhcpClient) getT1InSec(p *layers.DHCPOption) uint32 {
	if len(p.Data) != 4 {
		return 1811
	}
	return uint32(p.Data[0])<<24 | uint32(p.Data[1])<<16 | uint32(p.Data[2])<<8 | uint32(p.Data[3])
}

//onTimerEvent on timer event callback
func (o *PluginDhcpClient) onTimerEvent() {
	switch o.state {
	case DHCP_STATE_INIT:
		o.SendDiscover()
	case DHCP_STATE_REQUESTING:
		o.cnt++
		if o.cnt > 5 {
			o.SendDiscover()
		} else {
			o.SendReq()
		}
	case DHCP_STATE_BOUND:
		o.state = DHCP_STATE_RENEWING
		o.stats.pktRxRenew++
		o.SendRenewRebind(false, false, o.t2-o.t1)
	case DHCP_STATE_RENEWING:
		o.state = DHCP_STATE_REBINDING
		o.stats.pktRxRebind++
		o.SendRenewRebind(true, false, o.timerOfferRetransmitSec)
	}

}

func (o *PluginDhcpClient) HandleAckNak(dhcpmt layers.DHCPv6MsgType,
	dhcph *layers.DHCPv6,
	ipv6 layers.IPv6Header,
	t1 uint32,
	t2 uint32,
	notify bool) int {
	switch dhcpmt {
	case layers.DHCPv6MsgTypeReply:
		o.stats.pktRxAck++
		if o.verifyPkt(dhcph, ipv6) != 0 {
			return -1
		}
		o.state = DHCP_STATE_BOUND
		if notify {
			o.stats.pktRxNotify++
			// TBD need to fix
			/*
				//ipv4addr := ipv6.GetIPDst()
				if ipv4addr != 0 {
					var ipv4key core.Ipv4Key
					ipv4key.SetUint32(ipv4addr)
					// update ip
					o.Client.UpdateIPv4(ipv4key)
					if !o.dg.IsZero() {
						// update dg
						ipv4key.SetUint32(o.dg.Uint32())
						o.Client.UpdateDgIPv4(ipv4key)
					}
				}*/
		}
		o.restartTimer(t1)
		o.t1 = t1
		o.t2 = t2
		if o.t2 < o.t1 {
			o.t2 = o.t1 + 1
		}
	case layers.DHCPv6MsgTypeAdverstise:
		o.SendDiscover()
	}
	return 0
}

func (o *PluginDhcpClient) HandleRxDhcpPacket(ps *core.ParserPacketState) int {

	m := ps.M
	p := m.GetData()
	/* the header is at least 8 bytes*/

	ipv6 := layers.IPv6Header(p[ps.L3 : ps.L3+IPV6_HEADER_SIZE])

	dhcphlen := ps.L7Len

	if dhcphlen < 4 {
		o.stats.pktRxLenErr++
		return core.PARSER_ERR
	}

	var dhcph layers.DHCPv6
	err := dhcph.DecodeFromBytes(p[ps.L7:ps.L7+dhcphlen], gopacket.NilDecodeFeedback)
	if err != nil {
		o.stats.pktRxParserErr++
		return core.PARSER_ERR
	}

	var dhcpmt layers.DHCPv6MsgType
	dhcpmt = dhcph.MsgType
	o.dg.SetUint32(0)
	var t1 uint32
	var t2 uint32
	cid := []byte{}
	sid := []byte{}
	var iana layers.DHCPv6OptionIANA

	for _, op := range dhcph.Options {
		switch op.Code {
		case layers.DHCPv6OptClientID:
			cid = op.Data
		case layers.DHCPv6OptServerID:
			sid = op.Data
		case layers.DHCPv6OptIANA:
			iana.Decode(op.Data)
		default:
		}
	}
	fmt.Printf(" %v \n", cid)
	fmt.Printf(" %v \n", sid)
	fmt.Printf(" %v \n", iana)

	switch o.state {
	case DHCP_STATE_INIT:

		if dhcpmt == layers.DHCPv6MsgTypeAdverstise {
			o.stats.pktRxOffer++
			if o.verifyPkt(&dhcph, ipv6) != 0 {
				return -1
			}

			copy(o.serverMac[:], p[6:12])
			o.state = DHCP_STATE_REQUESTING
			o.SendReq()
			return 0
		}

	case DHCP_STATE_REQUESTING:
		return o.HandleAckNak(dhcpmt, &dhcph, ipv6, t1, t2, true)
	case DHCP_STATE_BOUND:
		o.stats.pktRxUnhandle++
	case DHCP_STATE_RENEWING:
		return o.HandleAckNak(dhcpmt, &dhcph, ipv6, t1, t2, true)

	case DHCP_STATE_REBINDING:
		return o.HandleAckNak(dhcpmt, &dhcph, ipv6, t1, t2, true)

	default:
		o.stats.pktRxUnhandle++
	}
	return (0)
}

// PluginDhcpNs icmp information per namespace
type PluginDhcpNs struct {
	core.PluginBase
	stats DhcpStats
}

func NewDhcpNs(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {

	o := new(PluginDhcpNs)
	o.InitPluginBase(ctx, o)
	o.RegisterEvents(ctx, []string{}, o)

	return &o.PluginBase
}

func (o *PluginDhcpNs) OnRemove(ctx *core.PluginCtx) {
}

func (o *PluginDhcpNs) OnEvent(msg string, a, b interface{}) {

}

func (o *PluginDhcpNs) SetTruncated() {

}

func (o *PluginDhcpNs) HandleRxDhcpPacket(ps *core.ParserPacketState) int {

	m := ps.M
	p := m.GetData()
	/* the header is at least 8 bytes*/
	/* UDP checksum was verified in the parser */
	var mackey core.MACKey
	copy(mackey[:], p[0:6])

	client := o.Ns.CLookupByMac(&mackey)

	if client == nil {
		return core.PARSER_ERR
	}

	cplg := client.PluginCtx.Get(DHCPV6_PLUG)
	if cplg == nil {
		return core.PARSER_ERR
	}
	dhcpCPlug := cplg.Ext.(*PluginDhcpClient)
	return dhcpCPlug.HandleRxDhcpPacket(ps)
}

// HandleRxDhcpPacket Parser call this function with mbuf from the pool
func HandleRxDhcpv6Packet(ps *core.ParserPacketState) int {

	ns := ps.Tctx.GetNs(ps.Tun)
	if ns == nil {
		return core.PARSER_ERR
	}
	nsplg := ns.PluginCtx.Get(DHCPV6_PLUG)
	if nsplg == nil {
		return core.PARSER_ERR
	}
	dhcpPlug := nsplg.Ext.(*PluginDhcpNs)
	return dhcpPlug.HandleRxDhcpPacket(ps)

}

// Tx side client get an event and decide to act !
// let's see how it works and add some tests

type PluginDhcpCReg struct{}
type PluginDhcpNsReg struct{}

func (o PluginDhcpCReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	return NewDhcpClient(ctx, initJson)
}

func (o PluginDhcpNsReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	return NewDhcpNs(ctx, initJson)
}

/*******************************************/
/*  RPC commands */
type (
	ApiDhcpClientCntHandler struct{}
)

func getNs(ctx interface{}, params *fastjson.RawMessage) (*PluginDhcpNs, *jsonrpc.Error) {
	tctx := ctx.(*core.CThreadCtx)
	plug, err := tctx.GetNsPlugin(params, DHCPV6_PLUG)

	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	arpNs := plug.Ext.(*PluginDhcpNs)

	return arpNs, nil
}

func getClientPlugin(ctx interface{}, params *fastjson.RawMessage) (*PluginDhcpClient, *jsonrpc.Error) {
	tctx := ctx.(*core.CThreadCtx)

	plug, err := tctx.GetClientPlugin(params, DHCPV6_PLUG)

	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	pClient := plug.Ext.(*PluginDhcpClient)

	return pClient, nil
}

func (h ApiDhcpClientCntHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	var p core.ApiCntParams
	tctx := ctx.(*core.CThreadCtx)
	c, err := getClientPlugin(ctx, params)
	return c.cdbv.GeneralCounters(err, tctx, params, &p)
}

func init() {

	/* register of plugins callbacks for ns,c level  */
	core.PluginRegister(DHCPV6_PLUG,
		core.PluginRegisterData{Client: PluginDhcpCReg{},
			Ns:     PluginDhcpNsReg{},
			Thread: nil}) /* no need for thread context for now */

	/* The format of the RPC commands xxx_yy_zz_aa

	  xxx - the plugin name

	  yy  - ns - namespace
			c  - client
			t   -thread

	  zz  - cmd  command like ping etc
			set  set configuration
			get  get configuration/counters

	  aa - misc
	*/

	core.RegisterCB("dhcp_client_cnt", ApiDhcpClientCntHandler{}, false) // get counters/meta

	/* register callback for rx side*/
	core.ParserRegister("dhcpv6", HandleRxDhcpv6Packet)
}

func Register(ctx *core.CThreadCtx) {
	ctx.RegisterParserCb("dhcpv6")
}
