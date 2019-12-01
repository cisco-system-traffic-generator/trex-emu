package core

import (
	"encoding/binary"
	"fmt"
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

type RpcCmdMac struct {
	MACKey MACKey `json:"mac" validate:"required"`
}

type MapClientIPv6 map[Ipv6Key]*CClient
type MapClientIPv4 map[Ipv4Key]*CClient
type MapClientMAC map[MACKey]*CClient

type CNSCtxStats struct {
	addNs            uint64
	removeNs         uint64
	activeNs         uint64
	errRemoveIPv4tbl uint64 /* ipv4 does not exits in the IPv4 table */
	errRemoveMactbl  uint64 /* client MAC does not exits in the MAC table */
	errRemoveIPv6tbl uint64 /* ipv4 of client does not exits in the ipv6 table */
	errInvalidMac    uint64 /* mac is zero  */
}

func castDlistNSCtx(dlist *DList) *CNSCtx {
	return (*CNSCtx)(unsafe.Pointer(uintptr(unsafe.Pointer(dlist))))
}

// CNSCtx network namespace context
type CNSCtx struct {
	dlist      DList //for thread  ctx dlist
	ThreadCtx  *CThreadCtx
	Key        CTunnelKey // the key tunnel of this namespace
	mapIpv6    MapClientIPv6
	mapIpv4    MapClientIPv4
	mapMAC     MapClientMAC
	clientHead DList // list of ns
	stats      CNSCtxStats
	PluginCtx  *PluginCtx
	epoc       uint32
	iterEpoc   uint32
	iterReady  bool
	iter       DListIterHead
}

// NewNSCtx create new one
func NewNSCtx(tctx *CThreadCtx,
	key *CTunnelKey) *CNSCtx {
	o := new(CNSCtx)
	o.ThreadCtx = tctx
	o.Key = *key
	o.mapIpv6 = make(MapClientIPv6)
	o.mapIpv4 = make(MapClientIPv4)
	o.mapMAC = make(MapClientMAC)
	o.PluginCtx = NewPluginCtx(nil, o, tctx, PLUGIN_LEVEL_NS)
	o.clientHead.SetSelf()
	o.iterReady = false
	return o
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
	hasIpv6 := !client.Ipv6.IsZero()

	if hasIpv4 {
		c = o.CLookupByIPv4(&client.Ipv4)
		if c != nil {
			return fmt.Errorf(" client with the same IPv4 %v already exist", client.Ipv4)
		}
	}

	if hasIpv6 {
		c = o.CLookupByIPv6(&client.Ipv6)
		if c != nil {
			return fmt.Errorf(" client with the same IPv6 %v already exist", client.Ipv6)
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
	o.clientHead.AddLast(&client.dlist)
	o.epoc++

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
	o.epoc++

	return nil
}

func (o *CNSCtx) UpdateClientIpv4(client *CClient, NewIpv4 Ipv4Key) error {

	oldIpv4 := client.Ipv4
	var ok bool

	if !oldIpv4.IsZero() {
		_, ok = o.mapIpv4[oldIpv4]
		if !ok {
			client.Ipv4 = [4]byte{0, 0, 0, 0}
			return fmt.Errorf(" Somthing is wrong, couldn't find self ipv4 %v ", oldIpv4)
		}
		delete(o.mapIpv4, oldIpv4)
	}

	_, ok = o.mapIpv4[NewIpv4]
	if ok {
		client.Ipv4 = [4]byte{0, 0, 0, 0}
		return fmt.Errorf(" Somthing is wrong, couldn't update client with new ipv4 %v ", NewIpv4)
	}
	o.mapIpv4[NewIpv4] = client
	client.PluginCtx.BroadcastMsg(nil, MSG_UPDATE_IPV4_ADDR, oldIpv4, NewIpv4)
	return nil
}

func (o *CNSCtx) UpdateClientIpv6(client *CClient, NewIpv6 Ipv6Key) error {

	oldIpv6 := client.Ipv6
	var ok bool

	if !oldIpv6.IsZero() {
		_, ok = o.mapIpv6[oldIpv6]
		if !ok {
			client.Ipv6 = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
			return fmt.Errorf(" Somthing is wrong, couldn't find self ipv4 %v ", oldIpv6)
		}
		delete(o.mapIpv6, oldIpv6)
	}

	_, ok = o.mapIpv6[NewIpv6]
	if ok {
		client.Ipv6 = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		return fmt.Errorf(" Somthing is wrong, couldn't update client with new ipv4 %v ", NewIpv6)
	}
	o.mapIpv6[NewIpv6] = client
	client.PluginCtx.BroadcastMsg(nil, MSG_UPDATE_IPV6_ADDR, oldIpv6, NewIpv6)
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
		fmt.Printf(" %x", client.Mac)
		o.iter.Next()
	}
	return r, nil
}
