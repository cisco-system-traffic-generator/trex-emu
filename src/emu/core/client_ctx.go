package core

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

// CClient represent one client
type CClient struct {
	dlist          DList   // for adding into list
	Ns             *CNSCtx // pointer to a namespace
	Ipv6           Ipv6Key // set the self ipv6
	DgIpv6         Ipv6Key // default gateway
	Ipv4           Ipv4Key
	DgIpv4         Ipv4Key // default gateway for ipv4
	Mac            MACKey
	Ipv4dgMac      MACKey // default
	Ipv4dgResolved bool   // bool in case it is resolved
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
