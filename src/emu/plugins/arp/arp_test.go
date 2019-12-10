package arp

import (
	"emu/core"
	"testing"
	"time"
)

func createSimulationEnv(simRx *core.VethIFSim) (*core.CThreadCtx, *core.CClient) {
	tctx := core.NewThreadCtx(0, 4510, true, simRx)
	var key core.CTunnelKey
	key.Set(&core.CTunnelData{Vport: 1, Vlans: [2]uint32{0x81000001, 0x81000002}})
	ns := core.NewNSCtx(tctx, &key)
	tctx.AddNs(&key, ns)
	client := core.NewClient(ns, core.MACKey{0, 0, 1, 0, 0, 0},
		core.Ipv4Key{16, 0, 0, 1},
		core.Ipv6Key{},
		core.Ipv4Key{16, 0, 0, 2})
	ns.AddClient(client)
	client.PluginCtx.CreatePlugins([]string{"arp"}, [][]byte{})
	tctx.RegisterParserCb("arp")
	return tctx, client
}

type VethArpSim struct {
	DropAll bool
}

func (o *VethArpSim) ProcessTxToRx(m *core.Mbuf) *core.Mbuf {
	if o.DropAll {
		m.FreeMbuf()
		return nil
	}
	return nil
}

func TestPluginArp1(t *testing.T) {
	var simVeth VethArpSim
	simVeth.DropAll = true
	var simrx core.VethIFSim
	simrx = &simVeth
	tctx, _ := createSimulationEnv(&simrx)
	tctx.MainLoopSim(30 * time.Minute)
	var key core.CTunnelKey
	key.Set(&core.CTunnelData{Vport: 1, Vlans: [2]uint32{0x81000001, 0x81000002}})

	t.Log("OK \n")
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
}
