package core

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/go-playground/validator"
	"github.com/intel-go/fastjson"
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

/* CTunnelDataJson json representation of tunnel data */
type CTunnelDataJson struct {
	Vport uint16   `json:"vport" validate:"required"`
	Tpid  []uint16 `json:"tpid"`
	Tci   []uint16 `json:"tci"   validate:"required" `
}

type RpcCmdTunnel struct {
	Tun CTunnelDataJson `json:"tun" validate:"required"`
}

type CTunnelKey [4 + 4 + 4]byte

func (o *CTunnelKey) DumpHex() {
	fmt.Println(hex.Dump(o[0:]))
}

func (o CTunnelKey) String() string {
	var d CTunnelData
	o.Get(&d)
	s := fmt.Sprintf("%d,", d.Vport)
	for i := 0; i < 2; i++ {
		s += fmt.Sprintf("{%04x:%04x}", ((d.Vlans[i] & 0xffff0000) >> 16), (d.Vlans[i] & 0xffff))
		if i < 1 {
			s += fmt.Sprintf(",")
		}
	}
	s += fmt.Sprintf("\n")
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
	validate   *validator.Validate
}

func NewThreadCtx(Id uint32, serverPort uint16, simulation bool) *CThreadCtx {
	o := new(CThreadCtx)
	o.timerctx = NewTimerCtx(simulation)
	o.portMap = make(MapPortT)
	o.mapNs = make(MapNsT)
	o.MPool.Init(mBUFS_CACHE)
	o.rpc.NewZmqRpc(serverPort)
	o.rpc.SetCtx(o) /* back pointer to interface this */
	o.nsHead.SetSelf()
	o.PluginCtx = NewPluginCtx(nil, nil, o, PLUGIN_LEVEL_THREAD)
	o.validate = validator.New()
	return o
}

func (o *CThreadCtx) MainLoopSim(duration time.Duration) {

	var tick uint32
	maxticks := o.timerctx.DurationToTicks(duration)
	for {
		o.timerctx.HandleTicks()
		tick++
		if tick > maxticks {
			break
		}
		o.Veth.SimulatorCheckRxQueue()
	}
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

func (o *CThreadCtx) GetClientPlugin(params *fastjson.RawMessage, plugin string) (*PluginBase, error) {

	var tun CTunnelKey
	var key MACKey
	err := o.UnmarshalClient(*params, &key, &tun)
	if err != nil {
		return nil, err
	}

	ns := o.GetNs(&tun)
	if ns == nil {
		err = fmt.Errorf(" error there is valid namespace for this tunnel ")
		return nil, err
	}

	client := ns.CLookupByMac(&key)
	if client == nil {
		err = fmt.Errorf(" error there is valid client %v for this MAC ", key)
		return nil, err
	}

	plug := client.PluginCtx.Get(plugin)
	if plug == nil {
		err = fmt.Errorf(" error there is valid plugin %s for this client ", plugin)
		return nil, err
	}
	return plug, nil
}

func (o *CThreadCtx) UnmarshalClient(data []byte, key *MACKey,
	tun *CTunnelKey) error {
	err := o.UnmarshalMacKey(data, key)
	if err != nil {
		return err
	}
	err = o.UnmarshalTunnel(data, tun)
	if err != nil {
		return err
	}
	return nil
}

func (o *CThreadCtx) UnmarshalMacKey(data []byte, key *MACKey) error {
	var rkey RpcCmdMac
	err := o.UnmarshalValidate(data, &rkey)
	if err != nil {
		return err
	}
	*key = rkey.MACKey
	return nil
}

func (o *CThreadCtx) UnmarshalTunnel(data []byte, key *CTunnelKey) error {
	var tun RpcCmdTunnel
	err := o.UnmarshalValidate(data, &tun)
	if err != nil {
		return err
	}
	var t CTunnelData
	t.Vport = tun.Tun.Vport

	if len(tun.Tun.Tci) > 0 {
		tpid := uint16(0x8100)
		if len(tun.Tun.Tpid) > 0 {
			tpid = tun.Tun.Tpid[0]
		}
		t.Vlans[0] = (uint32(tpid) << 16) + uint32((tun.Tun.Tci[0] & 0xfff))
	}

	if len(tun.Tun.Tci) > 1 {
		tpid := uint16(0x8100)
		if len(tun.Tun.Tpid) > 1 {
			tpid = tun.Tun.Tpid[1]
		}
		t.Vlans[1] = (uint32(tpid) << 16) + uint32((tun.Tun.Tci[1] & 0xfff))
	}

	key.Set(&t)
	return nil
}

func (o *CThreadCtx) GetNsPlugin(params *fastjson.RawMessage, plugin string) (*PluginBase, error) {
	var key CTunnelKey
	err := o.UnmarshalTunnel(*params, &key)
	if err != nil {
		return nil, err
	}
	ns := o.GetNs(&key)
	if ns == nil {
		err = fmt.Errorf(" error there is valid namespace for this tunnel ")
		return nil, err
	}
	plug := ns.PluginCtx.Get(plugin)
	if plug == nil {
		err = fmt.Errorf(" error there is valid plugin %s for this tunnel ", plugin)
		return nil, err
	}

	return plug, nil
}

func (o *CThreadCtx) UnmarshalValidate(data []byte, v interface{}) error {
	err := fastjson.Unmarshal(data, v)
	if err != nil {
		return err
	}
	err = o.validate.Struct(v)
	if err != nil {
		return err
	}
	return nil
}

func (o *CThreadCtx) GetTimerCtx() *TimerCtx {
	return o.timerctx
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
	if o.HasNs(key) {
		r, _ := o.mapNs[*key]
		return r
	} else {
		return nil
	}
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

func (o *CThreadCtx) processInternalRx(m *Mbuf) {
	
}

/*ProcessRx handle the processing of incoming packet */
func (o *CThreadCtx) ProcessRx(m *Mbuf) {
	/* for simplicity make sure the mbuf is contiguous in the rx side */
	if !m.IsContiguous() {
		m1 := m.GetContiguous(&o.MPool)
		m.FreeMbuf()
		o.processInternalRx(m1)
	} else {
		o.processInternalRx(m)
	}
}
