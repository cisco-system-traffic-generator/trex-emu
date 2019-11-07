package core

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
	dlist          DList   // for adding into list
	Ns             *CNSCtx // pointer to a namespace
	Ipv6           Ipv6Key // set the self ipv6
	DgIpv6         Ipv6Key // default gateway
	Ipv4           Ipv4Key
	DgIpv4         Ipv4Key // default gateway for ipv4
	Mac            MACKey
	Ipv4dgMac      MACKey    // default
	Ipv4dgResolved bool      // bool in case it is resolved
	Ipv6dgMac      MACKey    // default
	Ipv6dgResolved bool      // bool in case it is resolved
	plugin         MapPlugin // plugin for the protocol per client information
	stats          CClientStats
}
