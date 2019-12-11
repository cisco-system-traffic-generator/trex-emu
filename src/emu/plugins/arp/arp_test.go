package arp

import (
	"emu/core"
	"external/google/gopacket/layers"
	"fmt"
	"testing"
	"time"
)

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
		client.PluginCtx.CreatePlugins([]string{"arp"}, [][]byte{})
	}
	tctx.RegisterParserCb("arp")
	return tctx, nil
}

type VethArpSim struct {
	DropAll bool
	cnt     uint8
	match   uint8
	tctx    *core.CThreadCtx
}

func (o *VethArpSim) ProcessTxToRx(m *core.Mbuf) *core.Mbuf {
	if o.DropAll {
		m.FreeMbuf()
		return nil
	}

	var arpHeader layers.ArpHeader
	var arpHeader1 layers.ArpHeader
	arpHeader = m.GetData()[22:]
	if arpHeader.GetOperation() == 1 && (arpHeader.GetDstIpAddress() == 0x10000002) {
		o.cnt++
		if o.cnt != 0 {
			if o.cnt > o.match && o.cnt < (o.match+5) {
				m.FreeMbuf()
				return nil
			}

		}
		m1 := o.tctx.MPool.Alloc(uint16(m.PktLen()))
		m1.SetVPort(m.VPort())
		m1.Append(m.GetData())
		eth := layers.EthernetHeader(m1.GetData()[0:12])
		eth.SetDestAddress(arpHeader.GetSourceAddress())
		eth.SetSrcAddress([]byte{0, 0, 2, 0, 0, 0})
		arpHeader1 = m1.GetData()[22:]
		arpHeader1.SetOperation(2)
		arpHeader1.SetDestAddress(arpHeader.GetSourceAddress())
		arpHeader1.SetDstIpAddress(arpHeader.GetSrcIpAddress())
		arpHeader1.SetSourceAddress([]byte{0, 0, 2, 0, 0, 0})
		arpHeader1.SetSrcIpAddress(0x10000002)
		m.FreeMbuf()
		return m1
	}
	m.FreeMbuf()
	return nil
}

/*TestPluginArp1 - does not answer to default gateway, should repeat query */
func TestPluginArp1(t *testing.T) {
	var simVeth VethArpSim
	simVeth.DropAll = true
	var simrx core.VethIFSim
	simrx = &simVeth
	tctx, _ := createSimulationEnv(&simrx, 1)
	tctx.Veth.SetDebug(false, true)
	tctx.MainLoopSim(1 * time.Minute)
	var key core.CTunnelKey
	key.Set(&core.CTunnelData{Vport: 1, Vlans: [2]uint32{0x81000001, 0x81000002}})

	ns := tctx.GetNs(&key)
	if ns == nil {
		t.Fatalf(" can't find ns")
		return
	}
	nsplg := ns.PluginCtx.Get(ARP_PLUG)
	if nsplg == nil {
		t.Fatalf(" can't find plugin")
	}
	arpnPlug := nsplg.Ext.(*PluginArpNs)
	arpnPlug.cdb.Dump()
	tctx.SimRecordAppend(arpnPlug.cdb.MarshalValues())
	tctx.SimRecordCompare("arp1", t)
	/* TBD compare the counters and pcap files */
}

func TestPluginArp2(t *testing.T) {
	var simVeth VethArpSim
	simVeth.DropAll = false
	var simrx core.VethIFSim
	simrx = &simVeth
	simVeth.match = 2
	tctx, _ := createSimulationEnv(&simrx, 1)
	tctx.Veth.SetDebug(false, true)
	simVeth.tctx = tctx
	tctx.MainLoopSim(60 * time.Minute)
	var key core.CTunnelKey
	key.Set(&core.CTunnelData{Vport: 1, Vlans: [2]uint32{0x81000001, 0x81000002}})

	ns := tctx.GetNs(&key)
	if ns == nil {
		t.Fatalf(" can't find ns")
		return
	}
	nsplg := ns.PluginCtx.Get(ARP_PLUG)
	if nsplg == nil {
		t.Fatalf(" can't find plugin")
	}
	arpnPlug := nsplg.Ext.(*PluginArpNs)
	arpnPlug.cdb.Dump()
	tctx.SimRecordAppend(arpnPlug.cdb.MarshalValues())
	tctx.SimRecordCompare("arp2", t)
	/* TBD compare the counters and pcap files */
}

func TestPluginArp3(t *testing.T) {
	var simVeth VethArpSim
	simVeth.DropAll = true
	var simrx core.VethIFSim
	simrx = &simVeth
	var now time.Time
	var d time.Duration

	tctx, _ := createSimulationEnv(&simrx, 10)
	tctx.Veth.SetDebug(false, true)
	simVeth.tctx = tctx
	now = time.Now()
	tctx.MainLoopSim(10 * time.Minute)
	d = time.Now().Sub(now)
	fmt.Println(d)

	var key core.CTunnelKey
	key.Set(&core.CTunnelData{Vport: 1, Vlans: [2]uint32{0x81000001, 0x81000002}})

	ns := tctx.GetNs(&key)
	if ns == nil {
		t.Fatalf(" can't find ns")
		return
	}
	nsplg := ns.PluginCtx.Get(ARP_PLUG)
	if nsplg == nil {
		t.Fatalf(" can't find plugin")
	}
	arpnPlug := nsplg.Ext.(*PluginArpNs)
	arpnPlug.cdb.Dump()
	tctx.SimRecordAppend(arpnPlug.cdb.MarshalValues())
	tctx.SimRecordCompare("arp3", t)
}
