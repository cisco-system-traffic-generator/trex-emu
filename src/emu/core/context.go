package core

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

/* Context per thread object

This class include the information per thread
each thread responsible to a port range or vlan range

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
	TimerW  *CNATimerWheel
	portMap MapPortT // valid port for this context
	Id      uint32
	mapNs   MapNsT //map tunnel to namespace
	nsHead  DList  // list of ns
	nsEpoc  uint32 // number of timer adding/removing ns used by RPC
	stats   CThreadCtxStats
}

func NewThreadCtx(Id uint32) *CThreadCtx {
	r := new(CThreadCtx)
	timerw, rc := NewTimerW(1024, 16)
	if rc != RC_HTW_OK {
		panic("can't init timew")
	}
	r.TimerW = timerw
	r.portMap = make(MapPortT)
	r.mapNs = make(MapNsT)
	r.nsHead.SetSelf()
	return r
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
	return nil
}

func (o *CThreadCtx) RemoveNs(key *CTunnelKey) error {
	if !o.HasNs(key) {
		return fmt.Errorf("ns with tunnel %v does not exists, could not remove", *key)
	}
	o.stats.removeNs++
	delete(o.mapNs, *key)
	return nil
}

type Ipv6Key [16]byte
type Ipv4Key [4]byte
type MACKey [6]byte // mac key

type MapClientIPv6 map[Ipv6Key]*CClient
type MapClientIPv4 map[Ipv4Key]*CClient
type MapClientMAC map[MACKey]*CClient
type MapPlugin map[string]interface{}

type CNSCtxStats struct {
	addNs    uint64
	removeNs uint64
	activeNs uint64
}

// CNSCtx network namespace context
type CNSCtx struct {
	dlist      DList      //for self
	Key        CTunnelKey // the key
	mapIpv6    MapClientIPv6
	mapIpv4    MapClientIPv4
	mapMAC     MapClientMAC
	clientHead DList // list of ns
	stats      CNSCtxStats
	plugin     MapPlugin // plugin to the share name-space
}

type CClientStats struct {
	addNs    uint64
	removeNs uint64
	activeNs uint64
}

func NewClientStatsCounterDb(o *CClientStats) *CCounterDb {
	db := NewCCounterDb("client")
	db.Add(&CCounterRec{
		Counter:  &o.addNs,
		Name:     "addNs",
		Help:     "ns add",
		Unit:     "ops",
		DumpZero: false,
		Info:     ScINFO})
	db.Add(&CCounterRec{
		Counter:  &o.removeNs,
		Name:     "removeNs",
		Help:     "removeNs",
		Unit:     "ops",
		DumpZero: false,
		Info:     ScINFO})
	db.Add(&CCounterRec{
		Counter:  &o.activeNs,
		Name:     "activeNs",
		Help:     "activeNs",
		Unit:     "",
		DumpZero: false,
		Info:     ScINFO})
	return db
}

// CClient represent one client
type CClient struct {
	ns             *CNSCtx // pointer to a namespace
	ipv6           Ipv6Key // set the self ipv6
	dgIpv6         Ipv6Key // default gateway
	ipv4           Ipv4Key
	dgIpv4         Ipv4Key // default gateway for ipv4
	mac            MACKey
	ipv4dgMac      MACKey    // default
	ipv4dgResolved bool      // bool in case it is resolved
	ipv6dgMac      MACKey    // default
	ipv6dgResolved bool      // bool in case it is resolved
	plugin         MapPlugin // plugin for the protocol per client information
	stats          CClientStats
}

func TestNs_1() {
	var key CTunnelKey
	key.Set(&CTunnelData{Vport: 12, Vlans: [2]uint32{1, 2}})
	key.DumpHex()
	fmt.Printf("%v  \n", key)

}
