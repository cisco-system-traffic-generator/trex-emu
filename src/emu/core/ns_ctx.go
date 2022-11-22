// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.
// August 2021 Eolo S.p.A. and Altran Italia S.p.A.
// - added RandMACKey function at line 630
// - added String for MACKey at line 652

package core

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"
	"unsafe"
)

/* Context per thread object

This class include the information per thread
each thread responsible to a port range or vlan range

*/

type Ipv6Key [16]byte
type Ipv4Key [4]byte
type MACKey [6]byte // mac key

func (key *Ipv6Key) IsZero() bool {
	if *key == [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} {
		return true
	}
	return false
}

func (o *Ipv6Key) ToIP() net.IP {
	var p net.IP
	p = append(p, o[:]...)
	return p
}

func (o *Ipv4Key) ToIP() net.IP {
	var p net.IP
	p = append(p, o[:]...)
	return p
}

func (key *Ipv4Key) IsZero() bool {

	if *key == [4]byte{0, 0, 0, 0} {
		return true
	}
	return false
}

func (key *Ipv4Key) Uint32() uint32 {
	return binary.BigEndian.Uint32(key[:])
}

func (key *Ipv4Key) SetUint32(v uint32) {
	binary.BigEndian.PutUint32(key[:], v)
}

func (key *MACKey) Clear() {
	*key = [6]byte{0, 0, 0, 0, 0, 0}
}

func (key *MACKey) IsZero() bool {
	if *key == [6]byte{0, 0, 0, 0, 0, 0} {
		return true
	}
	return false
}

func (key *MACKey) IsBroadcast() bool {
	if *key == [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff} {
		return true
	}
	return false
}

func (key *MACKey) IsMulticast() bool {
	return key[0]&0x01 != 0
}

func (key *MACKey) Uint64() uint64 {
	res := uint64(key[0])<<40 | uint64(key[1])<<32 | uint64(key[2])<<24 |
		uint64(key[3])<<16 | uint64(key[4])<<8 | uint64(key[5])
	return res
}

func (key *MACKey) SetUint64(v uint64) {
	for i := 0; i < 6; i++ {
		byte := byte(v & 0xFF)
		key[5-i] = byte
		v >>= 8
	}
}

type RpcCmdMac struct {
	MACKey MACKey `json:"mac" validate:"required"`
}

type RpcCmdMacs struct {
	MACKeys []MACKey `json:"macs" validate:"required"`
}

type MapClientIPv6 map[Ipv6Key]*CClient
type MapClientIPv4 map[Ipv4Key]*CClient
type MapClientMAC map[MACKey]*CClient

type CNSCtxStats struct {
	addClient        uint64
	removeClient     uint64
	activeClient     uint64
	errRemoveIPv4tbl uint64 /* ipv4 does not exits in the IPv4 table */
	errRemoveMactbl  uint64 /* client MAC does not exits in the MAC table */
	errRemoveIPv6tbl uint64 /* ipv4 of client does not exits in the ipv6 table */
	errInvalidMac    uint64 /* mac is zero  */
}

func (o *CNSCtxStats) PreUpdate() {
	if o.addClient > o.removeClient {
		o.activeClient = o.addClient - o.removeClient
	} else {
		o.activeClient = 0
	}
}

func newNsStats(o *CNSCtxStats) *CCounterDb {
	db := NewCCounterDb("ns")

	db.Add(&CCounterRec{
		Counter:  &o.addClient,
		Name:     "addClient",
		Help:     "add client",
		Unit:     "ops",
		DumpZero: false,
		Info:     ScINFO})

	db.Add(&CCounterRec{
		Counter:  &o.removeClient,
		Name:     "removeClient",
		Help:     "remove client",
		Unit:     "ops",
		DumpZero: false,
		Info:     ScINFO})

	db.Add(&CCounterRec{
		Counter:  &o.activeClient,
		Name:     "activeClient",
		Help:     "active client",
		Unit:     "ops",
		DumpZero: false,
		Info:     ScINFO})

	db.Add(&CCounterRec{
		Counter:  &o.errRemoveIPv4tbl,
		Name:     "errRemoveIPv4tbl",
		Help:     "err remove ipv4",
		Unit:     "ops",
		DumpZero: false,
		Info:     ScERROR})

	db.Add(&CCounterRec{
		Counter:  &o.errRemoveMactbl,
		Name:     "errRemoveMactbl",
		Help:     "err remove mac",
		Unit:     "ops",
		DumpZero: false,
		Info:     ScERROR})

	db.Add(&CCounterRec{
		Counter:  &o.errRemoveIPv6tbl,
		Name:     "errRemoveIPv6tbl",
		Help:     "err remove ipv6",
		Unit:     "ops",
		DumpZero: false,
		Info:     ScERROR})

	db.Add(&CCounterRec{
		Counter:  &o.errInvalidMac,
		Name:     "errInvalidMac",
		Help:     "err invalid mac",
		Unit:     "ops",
		DumpZero: false,
		Info:     ScERROR})

	return db
}

func castDlistNSCtx(dlist *DList) *CNSCtx {
	return (*CNSCtx)(unsafe.Pointer(uintptr(unsafe.Pointer(dlist))))
}

// CNSCtx network namespace context
type CNSCtx struct {
	dlist          DList //for thread  ctx dlist
	ThreadCtx      *CThreadCtx
	Key            CTunnelKey // the key tunnel of this namespace
	mapIpv6        MapClientIPv6
	mapIpv4        MapClientIPv4
	mapMAC         MapClientMAC
	clientHead     DList // list of ns
	stats          CNSCtxStats
	PluginCtx      *PluginCtx
	epoc           uint32
	iterEpoc       uint32
	iterReady      bool
	iter           DListIterHead
	cdb            *CCounterDb
	DefClientPlugs *MapJsonPlugs // Default plugins for each new client
}

type CNsInfo struct {
	Port          uint16    `json:"vport" validate:"required"`
	Tci           [2]uint16 `json:"tci"`
	Tpid          [2]uint16 `json:"tpid"`
	ActiveClients uint64    `json:"active_clients"`
	PlugNames     []string  `json:"plug_names"`
}

// NewNSCtx create new one
func NewNSCtx(tctx *CThreadCtx,
	key *CTunnelKey) *CNSCtx {
	o := new(CNSCtx)
	o.ThreadCtx = tctx
	o.Key = *key
	o.cdb = newNsStats(&o.stats)
	o.cdb.IOpt = &o.stats
	o.mapIpv6 = make(MapClientIPv6)
	o.mapIpv4 = make(MapClientIPv4)
	o.mapMAC = make(MapClientMAC)
	o.PluginCtx = NewPluginCtx(nil, o, tctx, PLUGIN_LEVEL_NS)
	o.DefClientPlugs = nil
	o.clientHead.SetSelf()
	o.iterReady = false
	return o
}

//OnRemove called before remove
func (o *CNSCtx) OnRemove() {
	o.PluginCtx.OnRemove()
}

func (o *CNSCtx) GetVport() uint16 {
	var d CTunnelData
	o.Key.Get(&d)
	return d.Vport
}

func (o *CNSCtx) AllocMbuf(len uint16) *Mbuf {
	vport := o.GetVport()
	m := o.ThreadCtx.MPool.Alloc(len)
	m.SetVPort(vport)
	return m
}

// Look for a client by MAC
func (o *CNSCtx) CLookupByMac(mac *MACKey) *CClient {
	if mac.IsZero() {
		return nil
	}
	c, ok := o.mapMAC[*mac]
	if ok {
		return c
	} else {
		return nil
	}
}

func (o *CNSCtx) CLookupByIPv4(ipv4 *Ipv4Key) *CClient {

	if ipv4.IsZero() {
		return nil
	}
	c, ok := o.mapIpv4[*ipv4]
	if ok {
		return c
	} else {
		return nil
	}
}

// look by local and global addr
func (o *CNSCtx) CLookupByIPv6LocalGlobal(ipv6 *Ipv6Key) *CClient {
	ta := net.IPv4(0, 0, 0, 0)

	copy(ta[:], ipv6[:])

	if ta.IsLinkLocalUnicast() || ta.IsGlobalUnicast() {
		var mac MACKey
		if ExtractOnlyMac(ta, &mac) {
			// look for mac
			var tipv6 Ipv6Key
			copy(tipv6[:], ta)

			client := o.CLookupByMac(&mac)
			if client != nil {
				if client.IsValidPrefix(tipv6) {
					return client
				}
			}
		} else {
			var tipv6 Ipv6Key
			copy(tipv6[:], ta)
			client := o.CLookupByIPv6(&tipv6)
			if client != nil {
				return client
			}
		}
	}
	return nil
}

func (o *CNSCtx) CLookupByIPv6(ipv6 *Ipv6Key) *CClient {

	if ipv6.IsZero() {
		return nil
	}
	c, ok := o.mapIpv6[*ipv6]
	if ok {
		return c
	} else {
		return nil
	}
}

// AddClient add a client object to the maps and dlist
func (o *CNSCtx) AddClient(client *CClient) error {

	if client.Mac.IsZero() {
		return fmt.Errorf(" Adding client with invalid zero MAC (zero)")
	}

	var c *CClient
	c = o.CLookupByMac(&client.Mac)
	if c != nil {
		return fmt.Errorf(" client with the same MAC %v already exist", client.Mac)
	}
	// mac is valid
	hasIpv4 := !client.Ipv4.IsZero()

	if hasIpv4 {
		c = o.CLookupByIPv4(&client.Ipv4)
		if c != nil {
			return fmt.Errorf(" client with the same IPv4 %v already exist", client.Ipv4)
		}
	}

	hasIpv6 := !client.Ipv6.IsZero()

	if hasIpv6 {
		c = o.CLookupByIPv6(&client.Ipv6)
		if c != nil {
			return fmt.Errorf(" client with the same IPv6 %v already exist", client.Ipv6)
		}
	}

	hasIpv6D := !client.Dhcpv6.IsZero()

	if hasIpv6D {
		c = o.CLookupByIPv6(&client.Dhcpv6)
		if c != nil {
			return fmt.Errorf(" client with the same IPv6 %v already exist", client.Dhcpv6)
		}
	}

	// Valid client add it
	o.mapMAC[client.Mac] = client
	if hasIpv4 {
		o.mapIpv4[client.Ipv4] = client
	}

	if hasIpv6 {
		o.mapIpv6[client.Ipv6] = client
	}

	if hasIpv6D {
		o.mapIpv6[client.Dhcpv6] = client

	}
	o.clientHead.AddLast(&client.dlist)
	o.epoc++
	o.stats.addClient++
	return nil
}

// RemoveClient remove a client
func (o *CNSCtx) RemoveClient(client *CClient) error {

	if client.Mac.IsZero() {
		o.stats.errInvalidMac++
		return fmt.Errorf(" Removing client with invalid zero MAC (zero)")
	}

	var c *CClient
	c = o.CLookupByMac(&client.Mac)
	if c == nil {
		o.stats.errRemoveMactbl++
		return fmt.Errorf(" client with the MAC %v does not exist", client.Mac)
	}

	/* callback to remove plugin*/
	c.OnRemove()

	delete(o.mapMAC, client.Mac)

	o.clientHead.RemoveNode(&client.dlist)

	if !client.Ipv4.IsZero() {
		if o.CLookupByIPv4(&client.Ipv4) != nil {
			delete(o.mapIpv4, client.Ipv4)
		} else {
			o.stats.errRemoveIPv4tbl++
		}
	}

	if !client.Ipv6.IsZero() {
		if o.CLookupByIPv6(&client.Ipv6) != nil {
			delete(o.mapIpv6, client.Ipv6)
		} else {
			o.stats.errRemoveIPv6tbl++
		}
	}

	if !client.Dhcpv6.IsZero() {
		if o.CLookupByIPv6(&client.Dhcpv6) != nil {
			delete(o.mapIpv6, client.Dhcpv6)
		} else {
			o.stats.errRemoveIPv6tbl++
		}
	}

	o.epoc++
	o.stats.removeClient++
	return nil
}

func (o *CNSCtx) UpdateClientIpv4(client *CClient, NewIpv4 Ipv4Key) error {

	oldIpv4 := client.Ipv4

	var ok bool
	if oldIpv4 == NewIpv4 {
		return nil
	}

	if !oldIpv4.IsZero() {
		_, ok = o.mapIpv4[oldIpv4]
		if !ok {
			client.Ipv4 = [4]byte{0, 0, 0, 0}
			return fmt.Errorf(" Somthing is wrong, couldn't find self ipv4 %v ", oldIpv4)
		}
		delete(o.mapIpv4, oldIpv4)
	}

	if !NewIpv4.IsZero() {
		_, ok = o.mapIpv4[NewIpv4]
		if ok {
			client.Ipv4 = [4]byte{0, 0, 0, 0}
			return fmt.Errorf(" Somthing is wrong, couldn't update client with new ipv4 %v ", NewIpv4)
		}
		o.mapIpv4[NewIpv4] = client
	}
	client.Ipv4 = NewIpv4
	client.PluginCtx.BroadcastMsg(nil, MSG_UPDATE_IPV4_ADDR, oldIpv4, NewIpv4)
	return nil
}

func (o *CNSCtx) UpdateClientIpv6(client *CClient, NewIpv6 Ipv6Key) error {

	oldIpv6 := client.Ipv6
	var ok bool

	if oldIpv6 == NewIpv6 {
		return nil
	}

	if !oldIpv6.IsZero() {
		_, ok = o.mapIpv6[oldIpv6]
		if !ok {
			client.Ipv6 = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
			return fmt.Errorf(" Somthing is wrong, couldn't find self ipv4 %v ", oldIpv6)
		}
		delete(o.mapIpv6, oldIpv6)
	}

	if !NewIpv6.IsZero() {
		_, ok = o.mapIpv6[NewIpv6]
		if ok {
			client.Ipv6 = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
			return fmt.Errorf(" Somthing is wrong, couldn't update client with new ipv4 %v ", NewIpv6)
		}
		o.mapIpv6[NewIpv6] = client
	}
	client.Ipv6 = NewIpv6
	client.PluginCtx.BroadcastMsg(nil, MSG_UPDATE_IPV6_ADDR, oldIpv6, NewIpv6)
	return nil
}

func (o *CNSCtx) UpdateClientDIpv6(client *CClient, NewIpv6 Ipv6Key) error {

	oldIpv6 := client.Dhcpv6
	var ok bool

	if oldIpv6 == NewIpv6 {
		return nil
	}

	if !oldIpv6.IsZero() {
		_, ok = o.mapIpv6[oldIpv6]
		if !ok {
			client.Dhcpv6 = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
			return fmt.Errorf(" Somthing is wrong, couldn't find self ipv6 %v ", oldIpv6)
		}
		delete(o.mapIpv6, oldIpv6)
	}

	if !NewIpv6.IsZero() {
		_, ok = o.mapIpv6[NewIpv6]
		if ok {
			client.Dhcpv6 = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
			return fmt.Errorf(" Somthing is wrong, couldn't update client with new ipv6 %v ", NewIpv6)
		}
		o.mapIpv6[NewIpv6] = client
	}
	client.Dhcpv6 = NewIpv6
	client.PluginCtx.BroadcastMsg(nil, MSG_UPDATE_DIPV6_ADDR, oldIpv6, NewIpv6)
	return nil
}

// IterReset save the rpc epoc and operate only if there wasn't a change
func (o *CNSCtx) IterReset() bool {

	o.iterEpoc = o.epoc
	o.iter.Init(&o.clientHead)
	if o.clientHead.IsEmpty() {
		o.iterReady = false
		return false
	}
	o.iterReady = true
	return true
}

func (o *CNSCtx) IterIsStopped() bool {
	return !o.iterReady
}

func (o *CNSCtx) GetFirstClient() *CClient {
	if o.clientHead.IsEmpty() {
		return nil
	} else {
		client := castDlistClient(o.clientHead.next)
		return client
	}
}

// GetNext return error in case the epoc was changed, use
func (o *CNSCtx) GetNext(n uint16) ([]*MACKey, error) {

	r := make([]*MACKey, 0)

	if !o.iterReady {
		return r, fmt.Errorf(" Iterator is not ready- reset the iterator  ")
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
		client := castDlistClient(o.iter.Val())
		r = append(r, &client.Mac)
		o.iter.Next()
	}
	return r, nil
}

func (o *CNSCtx) GetInfo() *CNsInfo {
	var info CNsInfo
	o.stats.PreUpdate()

	var d CTunnelDataJson
	o.Key.GetJson(&d)
	info.Port = d.Vport
	info.Tci = d.Tci
	info.Tpid = d.Tpid
	info.ActiveClients = o.stats.activeClient
	info.PlugNames = o.PluginCtx.GetAllPlugNames()
	return &info
}

func (o *CNSCtx) HasClient(key *MACKey) bool {
	_, ok := o.mapMAC[*key]
	return ok
}

func (o *CNSCtx) GetClient(key *MACKey) *CClient {
	if o.HasClient(key) {
		r, _ := o.mapMAC[*key]
		return r
	} else {
		return nil
	}
}

func (o *CNSCtx) Dump() {
	o.IterReset()
	fmt.Printf(" clients : %v\n", o.Key)
	for {
		if o.IterIsStopped() {
			break
		}
		obj, err := o.GetNext(1)
		if err != nil {
			fmt.Printf(" %s \n", err.Error())
			break
		}
		fmt.Printf(" MAC : %v \n", obj[0])
	}
}

func (o *CNSCtx) GetL2Header(broadcast bool, next uint16) []byte {
	var tund CTunnelData
	o.Key.Get(&tund)
	b := []byte{}
	if broadcast {
		b = append(b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	} else {
		b = append(b, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0)
	}
	b = append(b, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0)
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

// RandMACKey generates a random MAC address optionally using seed as first bytes
func RandMACKey(seed ...byte) MACKey {

	var token []byte
	var arr [6]byte

	seedLength := len(seed)

	if seedLength > 5 {
		panic("Base seed cannot be higher than 5 bytes!")
	}
	token = make([]byte, 6-seedLength)
	rand.Seed(time.Now().UTC().UnixNano())
	rand.Read(token)

	copy(arr[0:seedLength], seed[:])
	copy(arr[seedLength:], token[:6-seedLength])

	return MACKey(arr)
}

// (core.MACKey).String is printable version of MAC Address
func (key MACKey) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", key[0], key[1], key[2], key[3], key[4], key[5])
}
