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
const (
	mBUFS_CACHE = 1024 /* number of mbuf cached per size */
)

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
	timerctx   *TimerCtx
	MPool      MbufPoll /* mbuf pool */
	portMap    MapPortT // valid port for this cCZmqJsonRPC2t
	Id         uint32
	mapNs      MapNsT // map tunnel to namespaceCZmqJsonRPC2
	nsHead     DList  // list of ns
	PluginCtx  *PluginCtx
	rpc        CZmqJsonRPC2
	apiHandler string
	stats      CThreadCtxStats
	epoc       uint32 // number of timer adding/removing ns used by RPC
	iterEpoc   uint32
	iterReady  bool
	iter       DListIterHead
	Veth       VethIF
}

func NewThreadCtx(Id uint32, serverPort uint16) *CThreadCtx {
	o := new(CThreadCtx)
	o.timerctx = NewTimerCtx()
	o.portMap = make(MapPortT)
	o.mapNs = make(MapNsT)
	o.MPool.Init(mBUFS_CACHE)
	o.rpc.NewZmqRpc(serverPort)
	o.rpc.SetCtx(o) /* back pointer to interface this */
	o.nsHead.SetSelf()
	o.PluginCtx = NewPluginCtx(nil, nil, o, PLUGIN_LEVEL_THREAD)
	return o
}

func (o *CThreadCtx) MainLoop() {

	for {
		select {
		case req := <-o.rpc.GetC():
			o.rpc.HandleReqToChan(req) // RPC command
		case <-o.C():
			o.timerctx.HandleTicks()
		}
	}

}

func (o *CThreadCtx) Delete() {
	o.rpc.Delete()
}

func (o *CThreadCtx) StartRxThread() {
	o.rpc.StartRxThread()
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
func (o *CThreadCtx) IterReset() bool {
	o.iterEpoc = o.epoc
	o.iter.Init(&o.nsHead)
	if o.nsHead.IsEmpty() {
		o.iterReady = false
		return false
	}
	o.iterReady = true
	return true

}

// GetNext return error in case the epoc was changed, use
func (o *CThreadCtx) GetNext(n uint16) ([]*CTunnelKey, error) {
	r := make([]*CTunnelKey, 0)

	if !o.iterReady {
		return r, fmt.Errorf(" Iterator is not ready- reset the iterator")
	}

	if o.iterEpoc != o.epoc {
		return r, fmt.Errorf(" iterator was interupted , reset and start again ")
	}
	cnt := 0
	for {
		if !o.iter.IsCont() {
			o.iterReady = false // require a new reset
			break
		}
		cnt++
		if cnt > int(n) {
			break
		}
		ns := castDlistNSCtx(o.iter.Val())
		r = append(r, &ns.Key)
		fmt.Printf(" %v", ns.Key)
		o.iter.Next()
	}
	return r, nil
}

// TODO add RPC for counters,iterator, vport, tunnel
//
