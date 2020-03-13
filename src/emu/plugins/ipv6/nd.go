package ipv6

import (
	"emu/core"
	"encoding/binary"
	"external/google/gopacket"
	"external/google/gopacket/layers"
	"fmt"
	"net"
	"time"
	"unsafe"

	"github.com/intel-go/fastjson"
)

/* nd flow table is based on ARP cache table, some minor changes vs the RFC */

var defaultRetryTimerSec = [...]uint8{1, 1, 1, 1, 3, 5, 7, 17}

const (
	defaultCompleteTimer = 10 * time.Minute
	defaultLearnTimer    = 1 * time.Minute
	stateLearned         = 16 /* valid timer in query */
	stateIncomplete      = 17
	stateComplete        = 18
	stateRefresh         = 19 /* re-query wait for results to get back to stateQuery */
	hoplimitmax          = 255
	routeSolSec          = 1  // number of seconds to send routeSol
	routeSolRet          = 20 // number of retries to send routeSol
	advTimerSec          = 29 // every 29 second adv all public ipv6 addr
)

// refresh the time here
// I would like to make this table generic, let try to the table without generic first
// then optimize it

type NdCacheFlow struct {
	dlist  core.DList
	head   core.DList /* pointer to the node that uses this */
	timer  core.CHTimerObj
	ipv6   core.Ipv6Key // key
	state  uint8
	index  uint8
	touch  bool
	refc   uint32
	action core.CClientDg
}

// refresh the time here
// I would like to make this table generic, let try to the table without generic first
// then optimize it

type Ipv6NdInit struct {
	Timer        uint32 `json:"nd_timer"`
	TimerDisable bool   `json:"nd_timer_disable"`
}

func covertToNdCacheFlow(dlist *core.DList) *NdCacheFlow {
	return (*NdCacheFlow)(unsafe.Pointer(dlist))
}

type MapNdTbl map[core.Ipv6Key]*NdCacheFlow

type Ipv6NsStats struct {
	eventsChangeDHCPSrc uint64
	eventsChangeSrc     uint64
	eventsChangeDgIPv6  uint64

	timerEventLearn      uint64
	timerEventIncomplete uint64
	timerEventComplete   uint64
	timerEventRefresh    uint64

	addLearn                   uint64
	addIncomplete              uint64
	moveIncompleteAfterRefresh uint64
	moveComplete               uint64
	moveLearned                uint64

	pktRxErrTooShort             uint64
	pktRxErrNoBroadcast          uint64
	pktRxErrWrongOp              uint64
	pktRxErrWrongHopLimit        uint64
	pktRxRouterLifetimeZero      uint64
	pktRxErrRouterLifetimeTooBig uint64
	pktRxErrRouternotLinklocal   uint64
	pktRxRouterSolicitation      uint64
	pktRxRouterAdvertisement     uint64
	pktRxNeighborAdvertisement   uint64
	pktRxNeighborSolicitation    uint64

	pktRxNeighborSolicitationParserErr        uint64
	pktRxNeighborSolicitationWrongOption      uint64
	pktRxNeighborSolicitationWrongSourceLink  uint64
	pktRxNeighborSolicitationWrongDestination uint64
	pktRxNeighborSolicitationWrongTarget      uint64
	pktRxNeighborSolicitationLocalIpNotFound  uint64
	pktTxNeighborAdvUnicast                   uint64
	pktTxNeighborDADError                     uint64

	pktRxNeighborAdvParserErr   uint64
	pktRxNeighborAdvWrongOption uint64
	pktRxNeighborAdvWithOwnAddr uint64
	pktRxNeighborAdvLearn       uint64
	pktTxNeighborUnsolicitedNA  uint64

	pktTxNeighborUnsolicitedDAD   uint64
	pktTxNeighborUnsolicitedQuery uint64

	tblActive             uint64
	tblAdd                uint64
	tblRemove             uint64
	associateWithClient   uint64
	disasociateWithClient uint64
}

func NewIpv6NsStatsDb(o *Ipv6NsStats) *core.CCounterDb {
	db := core.NewCCounterDb("ipv6nd")

	db.Add(&core.CCounterRec{
		Counter:  &o.eventsChangeDHCPSrc,
		Name:     "eventsChangeDHCPSrc",
		Help:     "change dhcp src ipv6 events",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.eventsChangeSrc,
		Name:     "eventsChangeSrc",
		Help:     "change src ipv6 events",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.eventsChangeDgIPv6,
		Name:     "eventsChangeDgIPv6",
		Help:     "change dgw ipv6 events",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.timerEventLearn,
		Name:     "timerEventLearn",
		Help:     "timer events learn",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.timerEventIncomplete,
		Name:     "timerEventIncomplete",
		Help:     "timer events incomplete",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.timerEventComplete,
		Name:     "timerEventComplete",
		Help:     "timer events complete",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.timerEventRefresh,
		Name:     "timerEventRefresh",
		Help:     "timer events refresh",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.addLearn,
		Name:     "addLearn",
		Help:     "add learn to table ",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.addIncomplete,
		Name:     "addIncomplete",
		Help:     "add incomplete to table ",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.moveIncompleteAfterRefresh,
		Name:     "moveIncompleteAfterRefresh",
		Help:     "move incomplete after refresh  ",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.moveComplete,
		Name:     "moveComplete",
		Help:     "move complete ",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.moveLearned,
		Name:     "moveLearned",
		Help:     "move learn ",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxErrTooShort,
		Name:     "pktRxErrTooShort",
		Help:     "rx error packet is too short",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})
	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxErrNoBroadcast,
		Name:     "pktRxErrNoBroadcast",
		Help:     "rx error packet is no broadcast",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})
	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxErrWrongOp,
		Name:     "pktRxErrWrongOp",
		Help:     "rx error packet with wrong opcode",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tblActive,
		Name:     "tblActive",
		Help:     "ipv6 nd table active",
		Unit:     "entries",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.tblAdd,
		Name:     "tblAdd",
		Help:     "ipv6 nd table add",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.tblRemove,
		Name:     "tblRemove",
		Help:     "ipv6 nd table remove",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.associateWithClient,
		Name:     "associateWithClient",
		Help:     "associate with client",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.disasociateWithClient,
		Name:     "disasociateWithClient",
		Help:     "disassociate with client",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxNeighborSolicitation,
		Name:     "pktRxNeighborSolicitation",
		Help:     "rx neighbor solicitation",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxNeighborAdvertisement,
		Name:     "pktRxNeighborAdvertisement",
		Help:     "Rx neighbor advertisement",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxRouterAdvertisement,
		Name:     "pktRxRouterAdvertisement",
		Help:     "Rx router advertisement",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxRouterSolicitation,
		Name:     "pktRxRouterSolicitation",
		Help:     "Rx router solicitation",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxErrRouternotLinklocal,
		Name:     "pktRxErrRouternotLinklocal",
		Help:     "router advertisement not from local link",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxErrRouterLifetimeTooBig,
		Name:     "pktRxErrRouterLifetimeTooBig",
		Help:     "router advertisement lifetime is too big",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxRouterLifetimeZero,
		Name:     "pktRxRouterLifetimeZero",
		Help:     "router advertisement lifetime is zero not selected router",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxErrWrongHopLimit,
		Name:     "pktRxErrWrongHopLimit",
		Help:     "ipv6 hop limit should be 255",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxNeighborSolicitationParserErr,
		Name:     "pktRxNeighborSolicitationParserErr",
		Help:     "ipv6 neighbor solicitation parse error",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxNeighborSolicitationWrongOption,
		Name:     "pktRxNeighborSolicitationWrongOption",
		Help:     "ipv6 neighbor solicitation wrong option",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxNeighborSolicitationWrongSourceLink,
		Name:     "pktRxNeighborSolicitationWrongSourceLink",
		Help:     "ipv6 neighbor solicitation wrong source link",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxNeighborSolicitationWrongDestination,
		Name:     "pktRxNeighborSolicitationWrongDestination",
		Help:     "ipv6 neighbor solicitation wrong destination addr",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxNeighborSolicitationWrongTarget,
		Name:     "pktRxNeighborSolicitationWrongTarget",
		Help:     "ipv6 neighbor solicitation wrong target addr",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxNeighborSolicitationLocalIpNotFound,
		Name:     "pktRxNeighborSolicitationLocalIpNotFound",
		Help:     "ipv6 neighbor solicitation not found ip",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktTxNeighborAdvUnicast,
		Name:     "pktTxNeighborAdvUnicast",
		Help:     "ipv6 tx neighbor solicitation answer",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktTxNeighborDADError,
		Name:     "pktTxNeighborDADError",
		Help:     "ipv6 tx neighbor solicitation DAD answer",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxNeighborAdvParserErr,
		Name:     "pktRxNeighborAdvParserErr",
		Help:     "ipv6 rx neighbor advertisements parse",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxNeighborAdvWrongOption,
		Name:     "pktRxNeighborAdvWrongOption",
		Help:     "ipv6 rx neighbor advertisements wrong option",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxNeighborAdvWithOwnAddr,
		Name:     "pktRxNeighborAdvWithOwnAddr",
		Help:     "ipv6 rx neighbor advertisements own addr",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxNeighborAdvLearn,
		Name:     "pktRxNeighborAdvLearn",
		Help:     "ipv6 rx neighbor advertisements learn",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktTxNeighborUnsolicitedNA,
		Name:     "pktTxNeighborUnsolicitedNA",
		Help:     "ipv6 rx neighbor unsolicited ",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktTxNeighborUnsolicitedDAD,
		Name:     "pktTxNeighborUnsolicitedDAD",
		Help:     "ipv6 rx neighbor DAD ",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktTxNeighborUnsolicitedQuery,
		Name:     "pktTxNeighborUnsolicitedQuery",
		Help:     "ipv6 rx neighbor solicited query ",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	return db
}

type Ipv6NsCacheRec struct {
	Ipv6    core.Ipv6Key `json:"ipv6"`
	Refc    uint32       `json:"refc"`
	State   uint8        `json:"state"`
	Resolve bool         `json:"resolve"`
	Mac     core.MACKey  `json:"mac"`
}

// Ipv6NsCacheFlowTable manage the ipv6 -> mac with timeout for outside case
// inside are resolved
type Ipv6NsCacheFlowTable struct {
	timerw        *core.TimerCtx
	tbl           MapNdTbl
	head          core.DList
	completeTicks uint32 /* timer to send query */
	learnTimer    uint32
	second        uint32      /* timer to remove */
	activeIter    *core.DList /* iterator */
	stats         *Ipv6NsStats
	iterReady     bool
}

func (o *Ipv6NsCacheFlowTable) Create(timerw *core.TimerCtx) {
	o.timerw = timerw
	o.tbl = make(MapNdTbl)
	o.head.SetSelf()
	o.completeTicks = timerw.DurationToTicks(defaultCompleteTimer)
	o.learnTimer = timerw.DurationToTicks(defaultLearnTimer)
	o.second = timerw.DurationToTicks(time.Second)
}

func (o *Ipv6NsCacheFlowTable) OnRemove() {
	for k := range o.tbl {
		flow := o.tbl[k]
		o.OnRemoveFlow(flow)
	}
}

func (o *Ipv6NsCacheFlowTable) OnRemoveFlow(flow *NdCacheFlow) {
	/* make sure the timer is stopped as it is linked to another resource */
	if flow.timer.IsRunning() {
		o.timerw.Stop(&flow.timer)
	}
}

// OnRemove called when there is no ref to this object
func (o *Ipv6NsCacheFlowTable) OnDeleteFlow(flow *NdCacheFlow) {
	if flow.refc != 0 {
		panic(" Ipv6NsCacheFlowTable ref counter should be zero ")
	}
	if o.activeIter == &flow.dlist {
		// it is going to be removed
		o.activeIter = flow.dlist.Next()
	}

	o.head.RemoveNode(&flow.dlist)
	flow.action.IpdgResolved = false
	flow.action.IpdgMac.Clear()
	_, ok := o.tbl[flow.ipv6]
	if ok {
		delete(o.tbl, flow.ipv6)
		o.stats.tblRemove++
		o.stats.tblActive--
	} else {
		// somthing is wrong here, can't find the flow
		panic(" Ipv6NsCacheFlowTable can't find the flow for removing ")
	}
}

/*AssociateWithClient  associate the flow with a client
and return if this is the first and require to send query*/
func (o *Ipv6NsCacheFlowTable) AssociateWithClient(flow *NdCacheFlow) bool {
	if flow.state == stateLearned {
		if flow.refc != 0 {
			panic("AssociateWithClient ref should be zero in learn mode")
		}
		flow.refc = 1
		o.MoveToComplete(flow)
	} else {
		flow.refc += 1
	}
	return false
}

// AddNew in case it does not found
// state could be  stateLearnedor incomplete
func (o *Ipv6NsCacheFlowTable) AddNew(ipv6 core.Ipv6Key,
	IpdgMac *core.MACKey, state uint8) *NdCacheFlow {
	_, ok := o.tbl[ipv6]
	if ok {
		panic(" ipv6cacheflow  already exits   ")
	}

	o.stats.tblAdd++
	o.stats.tblActive++
	flow := new(NdCacheFlow)
	flow.ipv6 = ipv6
	flow.state = state
	flow.head.SetSelf()
	if IpdgMac != nil {
		flow.action.IpdgResolved = true
		flow.action.IpdgMac = *IpdgMac
	} else {
		flow.action.IpdgResolved = false
	}
	flow.timer.SetCB(o, flow, 0)

	o.tbl[ipv6] = flow
	o.head.AddLast(&flow.dlist)
	if state == stateLearned {
		o.stats.addLearn++
		flow.refc = 0
		o.timerw.StartTicks(&flow.timer, o.learnTimer)
	} else {
		if state == stateIncomplete {
			flow.refc = 1
			o.stats.addIncomplete++
			ticks := o.GetNextTicks(flow)
			o.timerw.StartTicks(&flow.timer, ticks)
		} else {
			panic(" not valid state ")
		}
	}
	return flow
}

func (o *Ipv6NsCacheFlowTable) MoveToLearn(flow *NdCacheFlow) {
	if flow.timer.IsRunning() {
		o.timerw.Stop(&flow.timer)
	} else {
		panic("MoveToLearn timer should always on")
	}
	flow.touch = false
	o.timerw.StartTicks(&flow.timer, o.learnTimer)
	flow.state = stateLearned
	o.stats.moveLearned++
}

func (o *Ipv6NsCacheFlowTable) MoveToComplete(flow *NdCacheFlow) {
	if flow.timer.IsRunning() {
		o.timerw.Stop(&flow.timer)
	} else {
		panic("MoveToComplete timer should always on")
	}
	flow.touch = false
	o.timerw.StartTicks(&flow.timer, o.completeTicks)
	flow.state = stateComplete
	o.stats.moveComplete++
}

func (o *Ipv6NsCacheFlowTable) NdLearn(flow *NdCacheFlow, mac *core.MACKey) {

	flow.action.IpdgResolved = true
	flow.action.IpdgMac = *mac
	switch flow.state {
	case stateLearned:
		flow.touch = true
	case stateIncomplete:
		o.MoveToComplete(flow)
	case stateComplete:
		flow.touch = true
	case stateRefresh:
		o.MoveToComplete(flow)
	default:
		panic("NdLearn ")
	}
}

// Lookup for a resolution
func (o *Ipv6NsCacheFlowTable) Lookup(ipv6 core.Ipv6Key) *NdCacheFlow {
	v, ok := o.tbl[ipv6]
	if ok {
		/* read does not update the timer only packets */
		return v
	}
	return nil
}

/*SendQuery on behalf of the first client */
func (o *Ipv6NsCacheFlowTable) SendQuery(flow *NdCacheFlow) {
	if flow.state == stateRefresh || flow.state == stateIncomplete {
		if flow.head.IsEmpty() {
			panic("SendQuery no valid list  ")
		}
		/* take the first and query */
		cplg := pluginArpClientCastfromDlist(flow.head.Next())
		cplg.ResolveDG()
	} else {
		panic("SendQuery in not valid state ")
	}
}

func (o *Ipv6NsCacheFlowTable) GetNextTicks(flow *NdCacheFlow) uint32 {
	index := flow.index
	maxl := uint8((len(defaultRetryTimerSec) - 1))
	if index < maxl {
		index++
	} else {
		index = maxl
	}
	flow.index = index
	sec := defaultRetryTimerSec[index]
	ticks := o.timerw.DurationToTicks(time.Duration(sec) * time.Second)
	return ticks
}

func (o *Ipv6NsCacheFlowTable) handleRefreshState(flow *NdCacheFlow) {
	ticks := o.GetNextTicks(flow)
	o.timerw.StartTicks(&flow.timer, ticks)
	o.SendQuery(flow)
	if flow.index > 2 {
		/* don't use the old data */
		flow.state = stateIncomplete
		o.stats.moveIncompleteAfterRefresh++
		flow.action.IpdgResolved = false
		flow.action.IpdgMac.Clear()
	}
}

/* OnEvent timer callback */
func (o *Ipv6NsCacheFlowTable) OnEvent(a, b interface{}) {
	flow := a.(*NdCacheFlow)
	switch flow.state {
	case stateLearned:
		o.stats.timerEventLearn++
		if flow.touch {
			flow.touch = false
			o.timerw.StartTicks(&flow.timer, o.learnTimer)
		} else {
			o.OnDeleteFlow(flow)
		}
	case stateIncomplete:
		o.stats.timerEventIncomplete++
		ticks := o.GetNextTicks(flow)
		o.timerw.StartTicks(&flow.timer, ticks)
		o.SendQuery(flow)
	case stateComplete:
		o.stats.timerEventComplete++
		if flow.touch {
			flow.touch = false
			o.timerw.StartTicks(&flow.timer, o.completeTicks)
		} else {
			flow.state = stateRefresh
			flow.index = 0
			o.handleRefreshState(flow)
		}
	case stateRefresh:
		o.stats.timerEventRefresh++
		o.handleRefreshState(flow)

	default:
		panic("Ipv6nd on event  ")
	}
}

func (o *Ipv6NsCacheFlowTable) IterReset() bool {
	o.activeIter = o.head.Next()
	if o.head.IsEmpty() {
		o.iterReady = false
		return true
	}
	o.iterReady = true
	return false
}

func (o *Ipv6NsCacheFlowTable) IterIsStopped() bool {
	return !o.iterReady
}

func (o *Ipv6NsCacheFlowTable) GetNext(n uint16) ([]Ipv6NsCacheRec, error) {
	r := make([]Ipv6NsCacheRec, 0)

	if !o.iterReady {
		return r, fmt.Errorf(" Iterator is not ready- reset the iterator")
	}

	cnt := 0
	for {

		if o.activeIter == &o.head {
			o.iterReady = false // require a new reset
			break
		}
		cnt++
		if cnt > int(n) {
			break
		}

		ent := covertToNdCacheFlow(o.activeIter)
		var jsone Ipv6NsCacheRec
		jsone.Ipv6 = ent.ipv6
		jsone.Refc = ent.refc
		jsone.State = ent.state
		jsone.Resolve = ent.action.IpdgResolved
		jsone.Mac = ent.action.IpdgMac

		r = append(r, jsone)
		o.activeIter = o.activeIter.Next()
	}
	return r, nil
}

func pluginArpClientCastfromDlist(o *core.DList) *NdClientCtx {
	var s NdClientCtx
	return (*NdClientCtx)(unsafe.Pointer(uintptr(unsafe.Pointer(o)) - unsafe.Offsetof(s.dlist)))
}

type NdClientTimer struct {
}

func (o *NdClientTimer) OnEvent(a, b interface{}) {
	c := a.(*NdClientCtx)
	c.onTimerUpdate()
}

// NdClientCtx nd information per client
type NdClientCtx struct {
	base             *PluginIpv6Client
	dlist            core.DList /* to link to NdCacheFlow */
	nsPlug           *NdNsCtx
	mld              *mldNsCtx
	pktOffset        uint16
	naPktTemplate    []byte
	nsPktTemplate    []byte // with source option
	nsDadPktTemplate []byte // no option for DAD
	timer            core.CHTimerObj
	timerCb          NdClientTimer
	timerw           *core.TimerCtx
	timerNASec       uint32
}

func (o *NdClientCtx) AdvIPv6() {
	ipr := o.base.Client.Ipv6Router
	c := o.base.Client

	// try to advertise internal ips
	if ipr != nil {
		if !ipr.IPv6.IsZero() {
			// we have the router IP
			if !c.Ipv6.IsZero() {
				o.SendNS(false, &c.Ipv6, &ipr.IPv6)
			}
			if !c.Dhcpv6.IsZero() {
				o.SendNS(false, &c.Dhcpv6, &ipr.IPv6)
			}

			var l6 core.Ipv6Key
			if c.GetIpv6Slaac(&l6) {
				o.SendNS(false, &l6, &ipr.IPv6)
			}

			c.GetIpv6LocalLink(&l6)
			o.SendNS(false, &l6, &ipr.IPv6)
		}
	}
}

func (o *NdClientCtx) onTimerUpdate() {

	o.AdvIPv6()
	o.timerw.Start(&o.timer, time.Duration(o.timerNASec)*time.Second)
}

func (o *NdClientCtx) preparePacketTemplate() {
	l2 := o.base.Client.GetL2Header(true, uint16(layers.EthernetTypeIPv6))
	o.pktOffset = uint16(len(l2))

	IcmpHeader := core.PacketUtlBuild(
		&layers.IPv6{
			Version:      6,
			TrafficClass: 0,
			FlowLabel:    0,
			Length:       32,
			NextHeader:   layers.IPProtocolICMPv6,
			HopLimit:     255,
			SrcIP:        net.IP{00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x0, 0x0, 0x00, 0x00},
			DstIP:        net.IP{0x0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},

		&layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0)},

		&layers.ICMPv6NeighborAdvertisement{
			Flags:         0,
			TargetAddress: net.IP{0x0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x0, 0x0, 0x00, 0x00},
		},
		gopacket.Payload([]byte{0x02, 0x01, 0x0, 0x00, 0x0, 0x0, 0x00, 0x00}),
	)

	o.naPktTemplate = append(l2, IcmpHeader...)
	ipv6 := layers.IPv6Header(o.naPktTemplate[o.pktOffset : o.pktOffset+40])
	var l6 core.Ipv6Key
	o.base.Client.GetIpv6LocalLink(&l6)
	copy(ipv6.SrcIP()[:], l6[:])

	dadHeader := core.PacketUtlBuild(
		&layers.IPv6{
			Version:      6,
			TrafficClass: 0,
			FlowLabel:    0,
			Length:       24,
			NextHeader:   layers.IPProtocolICMPv6,
			HopLimit:     255,
			SrcIP:        net.IP{00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x0, 0x0, 0x00, 0x00},
			DstIP:        net.IP{0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		},

		&layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborSolicitation, 0)},

		&layers.ICMPv6NeighborSolicitation{
			TargetAddress: net.IP{0x0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x0, 0x0, 0x00, 0x00},
		},
	)
	o.nsDadPktTemplate = append(l2, dadHeader...)

	nsHeader := core.PacketUtlBuild(
		&layers.IPv6{
			Version:      6,
			TrafficClass: 0,
			FlowLabel:    0,
			Length:       32,
			NextHeader:   layers.IPProtocolICMPv6,
			HopLimit:     255,
			SrcIP:        net.IP{00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x0, 0x0, 0x00, 0x00},
			DstIP:        net.IP{0x0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},

		&layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborSolicitation, 0)},

		&layers.ICMPv6NeighborSolicitation{
			TargetAddress: net.IP{0x0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x0, 0x0, 0x00, 0x00},
		},
		gopacket.Payload([]byte{0x01, 0x01, 0x0, 0x00, 0x0, 0x0, 0x00, 0x00}),
	)

	o.nsPktTemplate = append(l2, nsHeader...)
}

func (o *NdClientCtx) Init(base *PluginIpv6Client,
	nsPlug *NdNsCtx,
	ctx *core.CThreadCtx,
	mld *mldNsCtx,
	initJson []byte) {

	var init Ipv6NdInit
	err := fastjson.Unmarshal(initJson, &init)

	o.base = base
	o.mld = mld
	o.dlist.SetSelf()
	o.preparePacketTemplate()
	o.nsPlug = nsPlug

	// set default values
	o.timerNASec = advTimerSec

	if err == nil {
		/* init json was provided */
		if init.Timer > 0 {
			o.timerNASec = init.Timer
		}
		if init.TimerDisable {
			o.timerNASec = 0
		}
	}

	o.timerw = o.base.Tctx.GetTimerCtx()
	o.timer.SetCB(&o.timerCb, o, 0)
	o.timerw.Start(&o.timer, time.Duration(o.timerNASec)*time.Second)

	o.OnCreate()
}

//add Mc
func (o *NdClientCtx) addMc(addr *core.Ipv6Key) {
	var ipv6mc core.Ipv6Key
	IPv6SolicitationMcAddr(addr, &ipv6mc)
	o.mld.addMcInternal([]core.Ipv6Key{ipv6mc})
}

// in case of add
func (o *NdClientCtx) addMcCache(addr *core.Ipv6Key) {
	var ipv6mc core.Ipv6Key
	IPv6SolicitationMcAddr(addr, &ipv6mc)
	o.mld.addMcCache(ipv6mc)
}

//remove Mc
func (o *NdClientCtx) removeMc(addr *core.Ipv6Key) {
	var ipv6mc core.Ipv6Key
	IPv6SolicitationMcAddr(addr, &ipv6mc)
	o.mld.removeMcInternal([]core.Ipv6Key{ipv6mc})
}

/*OnEvent support event change of IP  */
func (o *NdClientCtx) OnEvent(msg string, a, b interface{}) {

	switch msg {
	case core.MSG_UPDATE_DIPV6_ADDR:
		oldIPv6 := a.(core.Ipv6Key)
		newIPv6 := b.(core.Ipv6Key)
		if newIPv6 != oldIPv6 {
			if !oldIPv6.IsZero() {
				o.removeMc(&oldIPv6)
			}

			o.nsPlug.stats.eventsChangeDHCPSrc++
			if !newIPv6.IsZero() {
				o.addMc(&newIPv6) // add it to MC
				var l6 core.Ipv6Key
				l6 = newIPv6
				// send unsolicitate message
				pmac := &o.base.Client.Mac
				o.SendUnsolicitedNaIpv6(&l6, nil, pmac)
				o.SendNS(true, nil, &l6) // dad, not by RFC. assuming it is ok
				o.AdvIPv6()
			}
		}

	case core.MSG_UPDATE_IPV6_ADDR:
		oldIPv6 := a.(core.Ipv6Key)
		newIPv6 := b.(core.Ipv6Key)
		if !oldIPv6.IsZero() {
			o.removeMc(&oldIPv6)
		}
		if newIPv6 != oldIPv6 {
			o.nsPlug.stats.eventsChangeSrc++
			if !newIPv6.IsZero() {
				o.addMc(&newIPv6)
				o.SendUnsolicitedNA()
				o.AdvIPv6()
			}
		}

	case core.MSG_UPDATE_DGIPV6_ADDR:
		oldIPv6 := a.(core.Ipv6Key)
		newIPv6 := b.(core.Ipv6Key)
		if newIPv6 != oldIPv6 {
			o.nsPlug.stats.eventsChangeDgIPv6++
			o.OnChangeDGSrcIPv6(oldIPv6,
				newIPv6)
		}

	}
}

/*OnChangeDGSrcIPv6 - called in case there is a change in Client.DgIpv6 ,
it is called after the change with the old values*/
func (o *NdClientCtx) OnChangeDGSrcIPv6(oldDgIpv6 core.Ipv6Key,
	newDgIpv6 core.Ipv6Key) {

	if !oldDgIpv6.IsZero() {
		o.nsPlug.DisassociateClient(o, oldDgIpv6)
	}

	if !newDgIpv6.IsZero() {
		o.nsPlug.AssociateClient(o)
	}
}

func (o *NdClientCtx) OnRemove(ctx *core.PluginCtx) {
	/* force removing the link to the client */
	// default gateway if provided would be in highest priority
	mac := o.base.Client.Mac

	o.mld.removeMcCache(core.Ipv6Key{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	// solicited node addr
	o.mld.removeMcCache(core.Ipv6Key{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, mac[3], mac[4], mac[5]})

	// in case of static IPv6
	if !o.base.Client.Ipv6.IsZero() {
		o.mld.removeMcCache(o.base.Client.Ipv6)
	}

	o.base.Client.Ipv6Router = nil

	if !o.base.Client.DgIpv6.IsZero() {
		o.nsPlug.DisassociateClient(o, o.base.Client.DgIpv6)
	}

	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}
}

func IPv6SolicitationMcAddr(ipv6 *core.Ipv6Key, ipv6mc *core.Ipv6Key) {
	*ipv6mc = core.Ipv6Key{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, ipv6[13], ipv6[14], ipv6[15]}
}

func (o *NdClientCtx) OnCreate() {

	mac := o.base.Client.Mac
	// set des
	// all nodes
	o.mld.addMcCache(core.Ipv6Key{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	// solicited node addr
	o.mld.addMcCache(core.Ipv6Key{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, mac[3], mac[4], mac[5]})

	if !o.nsPlug.IsRouterSolActive() {
		// if it is not, start it
		o.nsPlug.StartRouterSol(mac)
	}

	o.base.Client.Ipv6Router = &o.nsPlug.routerAd

	// in case of static IPv6
	if !o.base.Client.Ipv6.IsZero() {
		o.addMcCache(&o.base.Client.Ipv6)
	}
	o.SendUnsolicitedNA()
	o.AdvIPv6()

	// resolve the current default GW if exits
	if !o.base.Client.Ipv6ForceDGW {
		if !o.base.Client.DgIpv6.IsZero() {
			// resolve the ipv6 default gateway if exits
			o.nsPlug.AssociateClient(o)
		}
	}

}

// send node solicitation
func (o *NdClientCtx) SendNS(dad bool, sourceipv6 *core.Ipv6Key, target *core.Ipv6Key) {
	mac := o.base.Client.Mac
	if dad {
		// no sourceTarget option
		m := o.base.Ns.AllocMbuf(uint16(len(o.nsDadPktTemplate)))
		m.Append(o.nsDadPktTemplate)
		p := m.GetData()
		l3 := o.pktOffset
		ipv6 := layers.IPv6Header(p[l3 : l3+40])
		l4 := l3 + 40

		var mcipv6 core.Ipv6Key

		IPv6SolicitationMcAddr(target, &mcipv6)

		copy(ipv6.DstIP()[:], mcipv6[:]) //dest ip is the multicast solocitation
		copy(p[l4+8:l4+8+16], target[:]) //target
		copy(p[0:6], []byte{0x33, 0x33, mcipv6[12], mcipv6[13], mcipv6[14], mcipv6[15]})

		o.nsPlug.stats.pktTxNeighborUnsolicitedDAD++
		ipv6.FixIcmpL4Checksum(p[l4:], 0)
		o.base.Tctx.Veth.Send(m)

	} else {

		m := o.base.Ns.AllocMbuf(uint16(len(o.nsPktTemplate)))
		m.Append(o.nsPktTemplate)
		p := m.GetData()
		l3 := o.pktOffset
		ipv6 := layers.IPv6Header(p[l3 : l3+40])
		l4 := l3 + 40

		var mcipv6 core.Ipv6Key

		IPv6SolicitationMcAddr(target, &mcipv6)

		copy(ipv6.SrcIP()[:], sourceipv6[:]) //dest ip is the multicast solocitation
		copy(ipv6.DstIP()[:], mcipv6[:])     //dest ip is the multicast solocitation
		copy(p[l4+8:l4+8+16], target[:])     //target
		copy(p[0:6], []byte{0x33, 0x33, mcipv6[12], mcipv6[13], mcipv6[14], mcipv6[15]})

		oo := l4 + 8 + 16 + 2
		copy(p[oo:oo+6], mac[:]) //mac option as a source

		o.nsPlug.stats.pktTxNeighborUnsolicitedQuery++
		ipv6.FixIcmpL4Checksum(p[l4:], 0)
		o.base.Tctx.Veth.Send(m)
	}

}

func (o *NdClientCtx) SendUnsolicitedSlaac() {
	var l6 core.Ipv6Key
	if o.base.Client.GetIpv6Slaac(&l6) {
		pmac := &o.base.Client.Mac
		var spl6 *core.Ipv6Key
		spl6 = &l6
		o.SendNS(true, spl6, &l6) // dad
		o.SendUnsolicitedNaIpv6(&l6, spl6, pmac)
	}

}

func (o *NdClientCtx) SendUnsolicited(linkLocal bool) {
	var l6 core.Ipv6Key
	var sl6 core.Ipv6Key
	var spl6 *core.Ipv6Key
	pmac := &o.base.Client.Mac
	if linkLocal {
		o.base.Client.GetIpv6LocalLink(&l6)
		spl6 = nil
	} else {
		l6 = o.base.Client.Ipv6
		spl6 = &sl6
		sl6 = o.base.Client.Ipv6
	}
	o.SendNS(true, spl6, &l6) // dad
	o.SendUnsolicitedNaIpv6(&l6, spl6, pmac)
}

func (o *NdClientCtx) SendUnsolicitedNA() {

	o.SendUnsolicited(true)
	o.SendUnsolicitedSlaac()
	if !o.base.Client.Ipv6.IsZero() {
		o.SendUnsolicited(false)
	}
}

func (o *NdClientCtx) SendUnsolicitedNaIpv6(target *core.Ipv6Key, source *core.Ipv6Key, mac *core.MACKey) {

	m := o.base.Ns.AllocMbuf(uint16(len(o.naPktTemplate)))
	m.Append(o.naPktTemplate)
	p := m.GetData()
	l3 := o.pktOffset
	ipv6 := layers.IPv6Header(p[l3 : l3+40])

	l4 := l3 + 40
	copy(p[l4+8:l4+8+16], target[:]) //target
	oo := l4 + 8 + 16 + 2
	copy(p[oo:oo+6], mac[:]) //mac option as an answer

	copy(ipv6.DstIP()[:], net.IPv6linklocalallnodes)
	if source != nil {
		copy(ipv6.SrcIP()[:], source[:])
	}

	copy(p[0:6], []byte{0x33, 0x33, 0, 0, 0, 1})
	p[l4+4] = 0x20
	o.nsPlug.stats.pktTxNeighborUnsolicitedNA++

	ipv6.FixIcmpL4Checksum(p[l4:], 0)

	o.base.Tctx.Veth.Send(m)
}

func (o *NdClientCtx) ResolveDG() {
	// send query for DG
	dg := &o.base.Client.DgIpv6
	if !dg.IsZero() {
		var l6 core.Ipv6Key
		o.base.Client.GetIpv6LocalLink(&l6)
		o.SendNS(false, &l6, dg)
	} else {
		panic("  resolve wasn't sent ")
	}
}

// respond with Neighbor adv
func (o *NdClientCtx) Respond(mac *core.MACKey, ps *core.ParserPacketState) {

	ms := ps.M
	psrc := ms.GetData()
	sipv6 := layers.IPv6Header(psrc[ps.L3 : ps.L3+40])

	m := o.base.Ns.AllocMbuf(uint16(len(o.naPktTemplate)))
	m.Append(o.naPktTemplate)
	p := m.GetData()
	copy(p[0:6], psrc[6:12]) // set the destination TBD need to fix
	l3 := o.pktOffset
	ipv6 := layers.IPv6Header(p[l3 : l3+40])

	sip := net.IP(sipv6.SrcIP()[:])
	l4 := l3 + 40
	copy(p[l4+8:l4+8+16], psrc[ps.L4+8:ps.L4+8+16]) //target
	oo := l4 + 8 + 16 + 2
	copy(p[oo:oo+6], mac[:]) //mac option as an answer

	if sip.IsUnspecified() {
		o.nsPlug.stats.pktTxNeighborDADError++
		copy(ipv6.DstIP()[:], net.IPv6linklocalallnodes)
		copy(p[0:6], []byte{0x33, 0x33, 0, 0, 0, 1})
	} else {
		copy(ipv6.DstIP()[:], sipv6.SrcIP()[:])
		o.nsPlug.stats.pktTxNeighborAdvUnicast++
		p[l4+4] = 0x60
	}

	ipv6.FixIcmpL4Checksum(p[l4:], 0)

	o.base.Tctx.Veth.Send(m)
}

func (o *NdClientCtx) SendRouterSolicitation() {

}

type RouterAdNsTimer struct {
}

func (o *RouterAdNsTimer) OnEvent(a, b interface{}) {
	ns := a.(*NdNsCtx)
	ns.onRouterAdTimerUpdate()
}

// NdNsCtx arp information per namespace
type NdNsCtx struct {
	base           *PluginIpv6Ns
	timerw         *core.TimerCtx
	tbl            Ipv6NsCacheFlowTable
	stats          Ipv6NsStats
	cdb            *core.CCounterDb
	routerAd       core.CClientIpv6Nd
	routeAdTimerCB RouterAdNsTimer
	routerAdTicks  uint32
	routerAdCnt    uint32
	timerRouterSo  core.CHTimerObj // timer to ask solicitation from the router
	routerSoMac    core.MACKey
}

func (o *NdNsCtx) Init(base *PluginIpv6Ns, ctx *core.CThreadCtx, initJson []byte) {
	o.base = base
	o.timerw = ctx.GetTimerCtx()
	o.tbl.Create(o.timerw)
	o.tbl.stats = &o.stats
	o.cdb = NewIpv6NsStatsDb(&o.stats)

	o.timerRouterSo.SetCB(&o.routeAdTimerCB, o, 0) // set the callback to OnEvent
	o.routerAdTicks = o.timerw.DurationToTicks(routeSolSec * time.Second)
}

func (o *NdNsCtx) IsRouterSolActive() bool {
	if !o.routerSoMac.IsZero() {
		return true
	}
	return false
}

func (o *NdNsCtx) StartRouterSol(routerSoMac core.MACKey) {
	o.routerSoMac = routerSoMac
	o.routerAdCnt = 0
	o.timerw.StartTicks(&o.timerRouterSo, o.routerAdTicks)
}

// callback in case of advTimer
func (o *NdNsCtx) onRouterAdTimerUpdate() {
	o.routerAdCnt++
	if o.routerAdCnt < routeSolRet {
		o.SendRouterSolicitation(o.routerSoMac)
		o.timerw.StartTicks(&o.timerRouterSo, o.routerAdTicks)
	}
}

func (o *NdNsCtx) OnRemove(ctx *core.PluginCtx) {
	// stop timers
	if o.timerRouterSo.IsRunning() {
		o.timerw.Stop(&o.timerRouterSo)
	}

	o.tbl.OnRemove()
}

func (o *NdNsCtx) OnEvent(msg string, a, b interface{}) {

}

func (o *NdNsCtx) SendRouterSolicitation(srcMac core.MACKey) {

	// dynamic allocated because it is rare to have this message (once to trigger per namespace)
	l2 := o.base.Ns.GetL2Header(false, uint16(layers.EthernetTypeIPv6))
	ipoffset := len(l2)
	copy(l2[0:6], []byte{0x33, 0x33, 0, 0, 0, 2})
	copy(l2[6:12], srcMac[:])

	rsHeader := core.PacketUtlBuild(

		&layers.IPv6{
			Version:      6,
			TrafficClass: 0,
			FlowLabel:    0,
			Length:       8,
			NextHeader:   layers.IPProtocolICMPv6,
			HopLimit:     255,
			SrcIP:        net.IP{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			DstIP:        net.IP{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		},

		&layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeRouterSolicitation, 0)},

		&layers.ICMPv6RouterSolicitation{},
	)
	ipv6pktrs := append(l2, rsHeader...)

	pktSize := len(ipv6pktrs) + 16
	m := o.base.Ns.AllocMbuf(uint16(pktSize))
	m.Append(ipv6pktrs)
	p := m.GetData()

	ipv6 := layers.IPv6Header(p[ipoffset : ipoffset+IPV6_HEADER_SIZE])
	ipv6.SetPyloadLength(uint16(8))

	rcof := ipoffset + IPV6_HEADER_SIZE

	ipv6.FixIcmpL4Checksum(p[rcof:], 0)

	o.base.Tctx.Veth.Send(m)
}

/*DisassociateClient remove association from the client. client now have the new data
 */
func (o *NdNsCtx) DisassociateClient(c *NdClientCtx,
	oldDgIpv6 core.Ipv6Key) {

	if oldDgIpv6.IsZero() {
		panic("DisassociateClient old ipv6 is not valid")
	}
	flow := o.tbl.Lookup(oldDgIpv6)
	if flow.refc == 0 {
		panic(" ref count can't be zero before remove")
	}
	flow.head.RemoveNode(&c.dlist)
	flow.refc--
	if flow.refc == 0 {
		// move to Learn
		if !flow.head.IsEmpty() {
			panic(" head should be empty ")
		}
		o.tbl.MoveToLearn(flow)
	} else {
		if flow.head.IsEmpty() {
			panic(" head should not be empty ")
		}
	}
	o.stats.disasociateWithClient++
	c.base.Client.Ipv6DGW = nil

}

/*AssociateClient associate a new client object with a NdCacheFlow
  client object should be with valid source ipv6 and valid default gateway
  1. if object NdCacheFlow exists move it's state to complete and add ref counter
  2. if object NdCacheFlow does not exists create new with ref=1 and return it
  3. if this is the first, generate resolution request
*/
func (o *NdNsCtx) AssociateClient(c *NdClientCtx) {

	dgipv6 := &c.base.Client.DgIpv6

	if dgipv6.IsZero() {
		panic("AssociateClient should have valid source ipv6 and default gateway ")
	}

	var firstUnresolve bool
	firstUnresolve = false
	flow := o.tbl.Lookup(*dgipv6)
	if flow != nil {
		firstUnresolve = o.tbl.AssociateWithClient(flow)
	} else {
		flow = o.tbl.AddNew(*dgipv6, nil, stateIncomplete)
		firstUnresolve = true
	}

	o.stats.associateWithClient++
	flow.head.AddLast(&c.dlist)

	if firstUnresolve {
		c.SendUnsolicitedNA()
		var l6 core.Ipv6Key
		c.base.Client.GetIpv6LocalLink(&l6)
		c.SendNS(false, &l6, dgipv6)
	}

	c.base.Client.Ipv6DGW = &flow.action
}

func (o *NdNsCtx) NdLearn(ipv6 core.Ipv6Key, sourceMac *core.MACKey) {

	flow := o.tbl.Lookup(ipv6)

	if flow != nil {
		o.tbl.NdLearn(flow, sourceMac)
	} else {
		o.tbl.AddNew(ipv6, sourceMac, stateLearned)
	}
}

func (o *NdNsCtx) SetTruncated() {

}

//HandleRxIpv6NdPacket there is no need to free  buffer
func (o *NdNsCtx) HandleRxIpv6NdPacket(ps *core.ParserPacketState, code layers.ICMPv6TypeCode) int {

	m := ps.M
	p := m.GetData()
	nd := p[ps.L4+4:]
	ipv6 := layers.IPv6Header(p[ps.L3 : ps.L3+40])

	switch code {

	case layers.CreateICMPv6TypeCode(layers.ICMPv6TypeRouterSolicitation, 0):
		o.stats.pktRxRouterSolicitation++
		return core.PARSER_OK // nothing to do

	case layers.CreateICMPv6TypeCode(layers.ICMPv6TypeRouterAdvertisement, 0):
		o.stats.pktRxRouterAdvertisement++

		var ra layers.ICMPv6RouterAdvertisement
		if len(nd) < 12 {
			o.stats.pktRxErrTooShort++
			return core.PARSER_ERR
		}
		err := ra.DecodeFromBytes(nd, o)
		if err != nil {
			o.stats.pktRxErrTooShort++
			return core.PARSER_ERR
		}

		if ipv6.HopLimit() != hoplimitmax {
			o.stats.pktRxErrWrongHopLimit++
			return core.PARSER_ERR
		}

		ipaddr := net.IP(ipv6.SrcIP())

		if !ipaddr.IsLinkLocalUnicast() {
			o.stats.pktRxErrRouternotLinklocal++
			return core.PARSER_ERR
		}

		if ra.RouterLifetime > 9000 {
			o.stats.pktRxErrRouterLifetimeTooBig++
			return core.PARSER_ERR
		}

		if ra.RouterLifetime == 0 {
			o.stats.pktRxRouterLifetimeZero++
			return core.PARSER_OK // nothing to do
		}

		// we got the first RouterAdv
		if o.timerRouterSo.IsRunning() {
			o.timerw.Stop(&o.timerRouterSo)
		}
		var prefixCnt uint8
		prefixCnt = 0
		copy(o.routerAd.IPv6[:], ipv6.SrcIP()[:])
		for _, opt := range ra.Options {
			switch opt.Type {

			case layers.ICMPv6OptSourceAddress, layers.ICMPv6OptTargetAddress:
				if len(opt.Data) == 6 {
					copy(o.routerAd.DgMac[:], opt.Data[:])
				}
			case layers.ICMPv6OptPrefixInfo:
				if len(opt.Data) == 30 {
					prefixLen := uint8(opt.Data[0])
					//onLink := (opt.Data[1]&0x80 != 0)
					//autonomous := (opt.Data[1]&0x40 != 0)
					validLifetime := binary.BigEndian.Uint32(opt.Data[2:6])
					preferredLifetime := binary.BigEndian.Uint32(opt.Data[6:10])
					prefix := net.IP(opt.Data[14:])

					if prefixLen <= 64 && (validLifetime > 0) && (preferredLifetime > 0) && (prefixCnt == 0) {
						// valid prefix
						prefixCnt = 1
						o.routerAd.PrefixLen = prefixLen
						if len(prefix) == 16 {
							copy(o.routerAd.PrefixIpv6[:], prefix[:])
						}
					}
				}
			case layers.ICMPv6OptRedirectedHeader:
				// could invoke IP decoder on data... probably best not to
				break
			case layers.ICMPv6OptMTU:
				if len(opt.Data) == 6 {
					o.routerAd.MTU = uint16(binary.BigEndian.Uint32(opt.Data[2:]))
				}

			}

		}

	case layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborSolicitation, 0):
		o.stats.pktRxNeighborSolicitation++

		var ra layers.ICMPv6NeighborSolicitation
		if len(nd) < 20 {
			o.stats.pktRxErrTooShort++
			return core.PARSER_ERR
		}

		err := ra.DecodeFromBytes(nd, o)
		if err != nil {
			o.stats.pktRxNeighborSolicitationParserErr++
			return core.PARSER_ERR
		}

		if ipv6.HopLimit() != hoplimitmax {
			o.stats.pktRxErrWrongHopLimit++
			return core.PARSER_ERR
		}

		sipaddr := net.IP(ipv6.SrcIP())
		dipaddr := net.IP(ipv6.DstIP())

		var sourceMac core.MACKey
		var sourceMacExists bool

		for _, opt := range ra.Options {
			switch opt.Type {

			case layers.ICMPv6OptSourceAddress:
				if len(opt.Data) == 6 {
					copy(sourceMac[:], opt.Data[:])
					sourceMacExists = true
				} else {
					o.stats.pktRxNeighborSolicitationWrongOption++
					return core.PARSER_ERR
				}
			default:
				o.stats.pktRxNeighborSolicitationWrongOption++
				return core.PARSER_ERR
			}
		}

		if sourceMacExists {
			if sourceMac.IsZero() {
				o.stats.pktRxNeighborSolicitationWrongSourceLink++
				return core.PARSER_ERR
			}
		}

		if sipaddr.IsUnspecified() && sourceMacExists {
			o.stats.pktRxNeighborSolicitationWrongOption++
			return core.PARSER_ERR
		}

		if sipaddr.IsUnspecified() && !dipaddr.IsMulticast() {
			o.stats.pktRxNeighborSolicitationWrongDestination++
			return core.PARSER_ERR
		}

		if ra.TargetAddress.IsUnspecified() || ra.TargetAddress.IsMulticast() {
			o.stats.pktRxNeighborSolicitationWrongTarget++
			return core.PARSER_ERR
		}

		if sipaddr.IsGlobalUnicast() && sourceMacExists {
			// learn it
			var tipv6 core.Ipv6Key
			copy(tipv6[:], sipaddr)
			client := o.base.Ns.CLookupByIPv6(&tipv6)
			if client == nil {
				// not our global IPv6 learn it
				o.NdLearn(tipv6, &sourceMac)
			}
		}

		global := ra.TargetAddress.IsGlobalUnicast()

		if ra.TargetAddress.IsLinkLocalUnicast() || global {
			// extract the MAC and lookup by MAC and answer
			var mac core.MACKey
			if core.ExtractOnlyMac(ra.TargetAddress, &mac) {
				// found, isEUI48

				var tipv6 core.Ipv6Key
				copy(tipv6[:], ra.TargetAddress)

				var ours bool
				client := o.base.Ns.CLookupByMac(&mac)
				if client != nil {
					if client.IsValidPrefix(tipv6) {
						ours = true
					}
				}
				if !ours {
					o.stats.pktRxNeighborSolicitationLocalIpNotFound++
					return core.PARSER_ERR
				}

				cplg := client.PluginCtx.Get(IPV6_PLUG)
				if cplg != nil {
					cCPlug := cplg.Ext.(*PluginIpv6Client)
					cCPlug.nd.Respond(&mac, ps)
				} else {
					o.stats.pktRxNeighborSolicitationLocalIpNotFound++
					return core.PARSER_ERR
				}
			} else {
				// not EUI48
				if global {
					// need to look into the tables
					var tipv6 core.Ipv6Key
					copy(tipv6[:], ra.TargetAddress)
					client := o.base.Ns.CLookupByIPv6(&tipv6)
					if client == nil {
						o.stats.pktRxNeighborSolicitationLocalIpNotFound++
						return core.PARSER_ERR
					}
					cplg := client.PluginCtx.Get(IPV6_PLUG)
					if cplg != nil {
						o.stats.pktRxNeighborSolicitationLocalIpNotFound++
						cCPlug := cplg.Ext.(*PluginIpv6Client)
						cCPlug.nd.Respond(&client.Mac, ps)
					} else {
						o.stats.pktRxNeighborSolicitationLocalIpNotFound++
						return core.PARSER_ERR
					}
				} else {
					// not ours
					o.stats.pktRxNeighborSolicitationLocalIpNotFound++
					return core.PARSER_ERR
				}
			}

		} else {
			o.stats.pktRxNeighborSolicitationLocalIpNotFound++
			return core.PARSER_ERR
		}

		return core.PARSER_OK

	case layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0):
		o.stats.pktRxNeighborAdvertisement++

		var ra layers.ICMPv6NeighborAdvertisement
		if len(nd) < 20 {
			o.stats.pktRxErrTooShort++
			return core.PARSER_ERR
		}

		err := ra.DecodeFromBytes(nd, o)
		if err != nil {
			o.stats.pktRxNeighborAdvParserErr++
			return core.PARSER_ERR
		}

		if ipv6.HopLimit() != hoplimitmax {
			o.stats.pktRxErrWrongHopLimit++
			return core.PARSER_ERR
		}

		var targetMac core.MACKey
		var targetMacExists bool

		for _, opt := range ra.Options {
			switch opt.Type {

			case layers.ICMPv6OptTargetAddress:
				if len(opt.Data) == 6 {
					copy(targetMac[:], opt.Data[:])
					targetMacExists = true
				} else {
					o.stats.pktRxNeighborAdvWrongOption++
					return core.PARSER_ERR
				}
			default:
				o.stats.pktRxNeighborAdvWrongOption++
				return core.PARSER_ERR
			}
		}

		var over bool
		if ra.Flags&0x20 == 0x20 {
			over = true
		}
		/*
			//var sol bool

			if ra.Flags&0x40 == 0x40 {
				sol = true
			}*/

		if over && targetMacExists {
			// only if it is override
			global := ra.TargetAddress.IsGlobalUnicast()
			if ra.TargetAddress.IsLinkLocalUnicast() || global {
				// extract the MAC and lookup by MAC and answer

				var mac core.MACKey
				if core.ExtractOnlyMac(ra.TargetAddress, &mac) {
					// look for mac
					var tipv6 core.Ipv6Key
					copy(tipv6[:], ra.TargetAddress)

					var ours bool
					client := o.base.Ns.CLookupByMac(&mac)
					if client != nil {
						if client.IsValidPrefix(tipv6) {
							ours = true
						}
					}
					if !ours {
						o.stats.pktRxNeighborAdvLearn++
						o.NdLearn(tipv6, &targetMac)
					}

				} else {
					var tipv6 core.Ipv6Key
					copy(tipv6[:], ra.TargetAddress)
					client := o.base.Ns.CLookupByIPv6(&tipv6)
					if client == nil {
						// not our global IPv6 learn it
						o.stats.pktRxNeighborAdvLearn++
						o.NdLearn(tipv6, &targetMac)
					} else {
						o.stats.pktRxNeighborAdvWithOwnAddr++
					}
				}
			}
		}
		return core.PARSER_OK //

	case layers.CreateICMPv6TypeCode(layers.ICMPv6TypeRedirect, 0):
		o.stats.pktRxErrWrongOp++
		return core.PARSER_OK

	default:
		o.stats.pktRxErrWrongOp++
	}

	return core.PARSER_OK
}
