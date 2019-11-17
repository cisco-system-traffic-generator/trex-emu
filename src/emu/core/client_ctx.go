package core

import (
	"encoding/binary"
	"unsafe"
)

type CClientStats struct {
	addClients    uint64
	removeClients uint64
	activeClients uint64
}

func NewClientStatsCounterDb(o *CClientStats) *CCounterDb {
	db := NewCCounterDb("client")
	db.Add(&CCounterRec{
		Counter:  &o.addClients,
		Name:     "addClients",
		Help:     "clients add",
		Unit:     "ops",
		DumpZero: false,
		Info:     ScINFO})
	db.Add(&CCounterRec{
		Counter:  &o.removeClients,
		Name:     "removeClients",
		Help:     "clients remove",
		Unit:     "ops",
		DumpZero: false,
		Info:     ScINFO})
	db.Add(&CCounterRec{
		Counter:  &o.activeClients,
		Name:     "active clients",
		Help:     "active clients",
		Unit:     "",
		DumpZero: false,
		Info:     ScINFO})
	return db
}

func castDlistClient(dlist *DList) *CClient {
	return (*CClient)(unsafe.Pointer(uintptr(unsafe.Pointer(dlist))))
}

type CClientDgIPv4I interface {
	OnDelete(o *CClientDgIPv4)
}

// CClientDgIPv4 default GW
type CClientDgIPv4 struct {
	Ipv4dgResolved bool   // bool in case it is resolved
	Ipv4dgMac      MACKey // default
	Refc           uint32
	O              interface{}
	CB             CClientDgIPv4I
}

func ReduceRef(o *CClientDgIPv4) {
	o.Refc--
	if o.Refc == 0 {
		o.CB.OnDelete(o)
	}
}

// CClient represent one client
type CClient struct {
	dlist  DList   // for adding into list
	Ns     *CNSCtx // pointer to a namespace
	Ipv6   Ipv6Key // set the self ipv6
	DgIpv6 Ipv6Key // default gateway
	Ipv4   Ipv4Key
	DgIpv4 Ipv4Key // default gateway for ipv4
	Mac    MACKey  // immutable over lifetime of client

	DGW            *CClientDgIPv4 /* resolve by ARP */
	ForceDGW       bool           /* true in case we want to enforce default gateway MAC */
	Ipv4ForcedgMac MACKey

	Ipv6dgMac      MACKey // default
	Ipv6dgResolved bool   // bool in case it is resolved
	stats          CClientStats
	PluginCtx      *PluginCtx
}

/* NewClient Create a new client with default information and key */
func NewClient(ns *CNSCtx,
	Mac MACKey,
	Ipv4 Ipv4Key,
	Ipv6 Ipv6Key) *CClient {
	o := new(CClient)
	o.DGW = nil
	o.ForceDGW = false
	o.Ns = ns
	o.Mac = Mac
	o.Ipv4 = Ipv4
	o.Ipv6 = Ipv6
	o.PluginCtx = NewPluginCtx(o, ns, ns.ThreadCtx, PLUGIN_LEVEL_CLIENT)
	return o
}

func (o *CClient) UpdateIPv4(NewIpv4 Ipv4Key) error {
	return o.Ns.UpdateClientIpv4(o, NewIpv4)
}

func (o *CClient) UpdateIPv6(NewIpv6 Ipv6Key) error {
	return o.Ns.UpdateClientIpv6(o, NewIpv6)
}

// GetL2Header get L2 header
func (o *CClient) GetL2Header(broadcast bool, next uint16) []byte {
	var tund CTunnelData
	o.Ns.Key.Get(&tund)
	b := []byte{}
	if broadcast {
		b = append(b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	} else {
		b = append(b, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0)
	}
	b = append(b, o.Mac[:]...)
	for _, val := range tund.Vlans {
		if val != 0 {
			b = append(b, 0, 0, 0, 0)
			binary.BigEndian.PutUint32(b[len(b)-4:], val)
		}
	}
	b = append(b, 0, 0)
	binary.BigEndian.PutUint16(b[len(b)-2:], uint16(next))
	return b
}
