package core

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"
)

/* Thread Ctx includes
   1. map of network namespace per Tunnel data tuple of [port,dot1q,QinQ]
   2. instance of timerw for schedule events

*/

type CTunnelData struct {
	Vport uint16    // virtual port
	Vlans [2]uint32 // vlan tags include tpid
}

type CTunnelKey [4 + 4 + 4]byte

func (o *CTunnelKey) DumpHex() {
	fmt.Println(hex.Dump(o[0:]))
}

func (o CTunnelKey) String() string {
	var d CTunnelData
	o.Get(&d)
	s := fmt.Sprintf("%+v", d)
	return s
}

func (o *CTunnelKey) Set(d *CTunnelData) {
	binary.LittleEndian.PutUint16(o[2:4], 0)
	binary.LittleEndian.PutUint16(o[0:2], d.Vport)
	binary.LittleEndian.PutUint32(o[4:8], d.Vlans[0])
	binary.LittleEndian.PutUint32(o[8:12], d.Vlans[1])
}

func (o *CTunnelKey) Get(d *CTunnelData) {
	d.Vport = binary.LittleEndian.Uint16(o[0:2])
	d.Vlans[0] = binary.LittleEndian.Uint32(o[4:8])
	d.Vlans[1] = binary.LittleEndian.Uint32(o[8:12])
}

type MapPortT map[uint16]bool
type MapNsT map[CTunnelKey]*CNSCtx

type CThreadCtxStats struct {
	addNs    uint64
	removeNs uint64
	activeNs uint64 // calculated field
}

// CThreadCtx network namespace context
type CThreadCtx struct {
	timerctx *TimerCtx
	portMap  MapPortT // valid port for this context
	Id       uint32
	mapNs    MapNsT // map tunnel to namespace
	nsHead   DList  // list of ns
	epoc     uint32 // number of timer adding/removing ns used by RPC

	stats CThreadCtxStats
}

func NewThreadCtx(Id uint32) *CThreadCtx {
	o := new(CThreadCtx)
	o.timerctx = NewTimerCtx()
	o.portMap = make(MapPortT)
	o.mapNs = make(MapNsT)
	o.nsHead.SetSelf()
	return o
}

func (o *CThreadCtx) C() <-chan time.Time {
	return o.timerctx.Timer.C
}

func (o *CThreadCtx) HasNs(key *CTunnelKey) bool {
	_, ok := o.mapNs[*key]
	return ok
}

func (o *CThreadCtx) GetNs(key *CTunnelKey) *CNSCtx {
	r, _ := o.mapNs[*key]
	return r
}

func (o *CThreadCtx) AddNs(key *CTunnelKey, ns *CNSCtx) error {
	if o.HasNs(key) {
		return fmt.Errorf("ns with tunnel %v already exists", *key)
	}
	o.stats.addNs++
	o.mapNs[*key] = ns
	o.nsHead.AddLast(&ns.dlist)
	o.epoc++
	return nil
}

func (o *CThreadCtx) RemoveNs(key *CTunnelKey) error {
	if !o.HasNs(key) {
		return fmt.Errorf("ns with tunnel %v does not exists, could not remove", *key)
	}
	o.stats.removeNs++
	ns := o.GetNs(key)
	o.epoc++
	o.nsHead.RemoveNode(&ns.dlist)
	delete(o.mapNs, *key)
	return nil
}

// IterReset save the rpc epoc and operate only if there wasn't a change
func (o *CThreadCtx) IterReset() {
	fmt.Printf("reset iterator ")
}

// GetNext return error in case the epoc was changed, use
func (o *CThreadCtx) GetNext(n uint16) {
	fmt.Printf("next")
}

// TODO add RPC for counters,iterator, vport, tunnel
//
