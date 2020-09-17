package core

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"testing"
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

const (
	PLUGIN_MAX_PPS = 100000
)

const (
	DEF_TPID = 0x8100
)

type CTunnelData struct {
	Vport uint16    // virtual port
	Vlans [2]uint32 // vlan tags include tpid
}

/* CTunnelDataJson json representation of tunnel data */
type CTunnelDataJson struct {
	Vport   uint16        `json:"vport"`
	Tpid    [2]uint16     `json:"tpid"`
	Tci     [2]uint16     `json:"tci"`
	Plugins *MapJsonPlugs `json:"plugs"`
}

type RpcCmdTunnel struct {
	Tun CTunnelDataJson `json:"tun" validate:"required"`
}

type RpcCmdTunnels struct {
	Tunnels []CTunnelDataJson `json:"tunnels" validate:"required"`
}

type CTunnelKey [4 + 4 + 4]byte

func (o *CTunnelKey) DumpHex() {
	fmt.Println(hex.Dump(o[0:]))
}

func (o CTunnelKey) toString(newLine bool) string {
	var d CTunnelData
	o.Get(&d)
	s := fmt.Sprintf("%d,", d.Vport)
	for i := 0; i < 2; i++ {
		s += fmt.Sprintf("{%04x:%04x}", ((d.Vlans[i] & 0xffff0000) >> 16), (d.Vlans[i] & 0xffff))
		if i < 1 {
			s += fmt.Sprintf(",")
		}
	}
	if newLine {
		s += fmt.Sprintf("\n")
	}
	return s
}

func (o CTunnelKey) String() string {
	return o.toString(true)
}

func (o CTunnelKey) StringRpc() string {
	return o.toString(false)
}

func (o *CTunnelKey) Clear() {
	*o = CTunnelKey([12]byte{})
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

func (o *CTunnelKey) GetJson(d *CTunnelDataJson) {
	var t CTunnelData
	o.Get(&t)
	d.Vport = t.Vport
	if t.Vlans[0] != 0 {
		d.Tpid[0] = uint16(((t.Vlans[0] & 0xffff0000) >> 16))
		d.Tci[0] = uint16((t.Vlans[0] & 0xfff))

		if t.Vlans[1] != 0 {
			d.Tpid[1] = uint16(((t.Vlans[1] & 0xffff0000) >> 16))
			d.Tci[1] = uint16((t.Vlans[1] & 0xfff))
		}
	}
}

func (o *CTunnelKey) SetJson(d *CTunnelDataJson) {
	var t CTunnelData

	t.Vport = d.Vport

	for i := 0; i < 2; i++ {
		if d.Tci[i] > 0 {
			tpid := uint16(DEF_TPID)
			if d.Tpid[i] > 0 {
				tpid = d.Tpid[i]
			}
			t.Vlans[i] = (uint32(tpid) << 16) + uint32((d.Tci[i] & 0xfff))
		}
	}

	o.Set(&t)
}

type MapPortT map[uint16]bool
type MapNsT map[CTunnelKey]*CNSCtx

type CThreadCtxStats struct {
	addNs    uint64
	removeNs uint64
	activeNs uint64 // calculated field
}

type MapJsonPlugs map[string]*fastjson.RawMessage

func (o *CThreadCtxStats) PreUpdate() {
	if o.addNs > o.removeNs {
		o.activeNs = o.addNs - o.removeNs
	} else {
		o.activeNs = 0
	}
}

func newThreadCtxStats(o *CThreadCtxStats) *CCounterDb {
	db := NewCCounterDb("ctx")

	db.Add(&CCounterRec{
		Counter:  &o.addNs,
		Name:     "addNs",
		Help:     "add ns",
		Unit:     "ops",
		DumpZero: false,
		Info:     ScINFO})

	db.Add(&CCounterRec{
		Counter:  &o.removeNs,
		Name:     "removeNs",
		Help:     "remove ns",
		Unit:     "ops",
		DumpZero: false,
		Info:     ScINFO})
	db.Add(&CCounterRec{
		Counter:  &o.activeNs,
		Name:     "activeNs",
		Help:     "active ns",
		Unit:     "ops",
		DumpZero: false,
		Info:     ScINFO})

	return db
}

// CThreadCtx network namespace context
type CThreadCtx struct {
	timerctx    *TimerCtx
	Simulation  bool
	MPool       MbufPoll /* mbuf pool */
	portMap     MapPortT // valid port for this cCZmqJsonRPC2t
	Id          uint32
	mapNs       MapNsT // map tunnel to namespaceCZmqJsonRPC2
	nsHead      DList  // list of ns
	PluginCtx   *PluginCtx
	rpc         CZmqJsonRPC2
	apiHandler  string
	stats       CThreadCtxStats
	epoc        uint32 // number of timer adding/removing ns used by RPC
	iterEpoc    uint32
	iterReady   bool
	iter        DListIterHead
	Veth        VethIF
	validate    *validator.Validate
	parser      Parser
	simRecorder []interface{} // record event for simulation
	cdbv        *CCounterDbVec
	clientStats CClientStats
	DefNsPlugs  *MapJsonPlugs // Default plugins for each new namespace
}

func NewThreadCtxProxy() *CThreadCtx {
	o := new(CThreadCtx)
	o.timerctx = NewTimerCtx(false)
	o.MPool.Init(mBUFS_CACHE)
	o.simRecorder = make([]interface{}, 0)

	/* counters */
	o.cdbv = NewCCounterDbVec("ctx")
	o.cdbv.AddVec(o.MPool.Cdbv)
	o.cdbv.Add(o.MPool.Cdb)
	o.cdbv.Add(o.timerctx.Cdb)
	cdb := newThreadCtxStats(&o.stats)
	cdb.IOpt = &o.stats
	o.cdbv.Add(cdb)
	return o
}

func NewThreadCtx(Id uint32, serverPort uint16, simulation bool, simRx *VethIFSim) *CThreadCtx {
	o := new(CThreadCtx)
	o.timerctx = NewTimerCtx(simulation)
	o.portMap = make(MapPortT)
	o.Simulation = simulation
	o.mapNs = make(MapNsT)
	o.MPool.Init(mBUFS_CACHE)
	o.rpc.NewZmqRpc(serverPort, simulation)
	o.rpc.SetCtx(o) /* back pointer to interface this */
	o.nsHead.SetSelf()
	o.PluginCtx = NewPluginCtx(nil, nil, o, PLUGIN_LEVEL_THREAD)
	o.DefNsPlugs = nil
	o.validate = validator.New()
	o.parser.Init(o)
	if simulation {
		var simv VethIFSimulator
		simv.Create(o)
		if simRx == nil && simulation {
			panic(" ERROR in case of simulation mode VethIFSim should be provided ")
		}
		simv.Sim = *simRx
		o.Veth = &simv
	}
	o.simRecorder = make([]interface{}, 0)

	/* counters */
	o.cdbv = NewCCounterDbVec("ctx")
	o.cdbv.AddVec(o.MPool.Cdbv)
	o.cdbv.Add(o.MPool.Cdb)
	o.cdbv.Add(o.parser.Cdb)
	o.cdbv.Add(o.timerctx.Cdb)
	cdb := newThreadCtxStats(&o.stats)
	cdb.IOpt = &o.stats
	o.cdbv.Add(cdb)
	return o
}
func (o *CThreadCtx) SetZmqVeth(veth VethIF) {
	o.Veth = veth
	o.cdbv.Add(o.Veth.GetCdb())
}

func (o *CThreadCtx) SimRecordCompare(filename string, t *testing.T) {
	o.SimRecordExport(filename)
	expFilename := os.Getenv("GOPATH") + "/unit-test/exp/" + filename + ".json"
	genFilename := os.Getenv("GOPATH") + "/unit-test/generated/" + filename + ".json"
	buf, err := ioutil.ReadFile(expFilename)
	buf1, err1 := ioutil.ReadFile(genFilename)

	if err != nil {
		t.Fatalf("Error reading golden file %s %s \n", expFilename, err.Error())
	}
	if err1 != nil {
		t.Fatalf("Error reading generated files %s %s \n", genFilename, err.Error())
	}
	if JsonDeepEqualInc(buf, buf1) == false {
		t.Fatalf("Golden file :%s is not equal to generated file:%s \n", expFilename, genFilename)
	}
}

func (o *CThreadCtx) GetRandNumber(min uint32, max uint32) uint32 {

	if o.Simulation {
		return (max + min) >> 1
	} else {
		return uint32(rand.Intn((int(max - min)))) + min
	}
}

func (o *CThreadCtx) SimRecordExport(filename string) {
	if o.simRecorder == nil {
		return
	}
	o.SimRecordAppend(o.MPool.GetCdb().MarshalValues(false))
	o.SimRecordAppend(o.Veth.GetCdb().MarshalValues(false))
	buf, err := fastjson.MarshalIndent(o.simRecorder, "", "\t")
	if err == nil {
		ioutil.WriteFile(os.Getenv("GOPATH")+"/unit-test/generated/"+filename+".json", buf, 0644)
	}
}

func (o *CThreadCtx) SimRecordClear() {
	if o.simRecorder == nil {
		return
	}
	o.simRecorder = o.simRecorder[:0]
}

func (o *CThreadCtx) SimRecordAppend(obj interface{}) {
	if o.simRecorder == nil {
		return
	}
	o.simRecorder = append(o.simRecorder, obj)
}

func (o *CThreadCtx) RegisterParserCb(protocol string) {
	o.parser.Register(protocol)
}

func (o *CThreadCtx) HandleRxPacket(m *Mbuf) {
	r := o.parser.ParsePacket(m)
	if r < 0 {
		if r == -1 {
			o.parser.stats.errParser++
		} else {
			o.parser.stats.errInternalHandler++
		}
	}
	m.FreeMbuf()
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
	o.Veth.SimulatorCleanup()
	o.MPool.ClearCache() /* clear the cache for simulation */
}

func (o *CThreadCtx) HandleMainTimerTicks() {
	o.timerctx.HandleTicks()
}

func (o *CThreadCtx) MainLoop() {

	for {
		select {
		case req := <-o.rpc.GetC():
			o.rpc.HandleReqToChan(req) // RPC commands
		case <-o.C():
			o.timerctx.HandleTicks()
		case msg := <-o.Veth.GetC(): // batch of rx packets
			o.Veth.OnRxStream(msg)
		}
		o.Veth.FlushTx()
	}
	o.Veth.SimulatorCleanup()
	o.MPool.ClearCache()
}

func (o *CThreadCtx) GetClientsPlugin(params *fastjson.RawMessage, plugin string) ([]*PluginBase, error) {
	var tun CTunnelKey
	var keys []MACKey
	var err error

	err = o.UnmarshalTunnel(*params, &tun)
	if err != nil {
		return nil, err
	}

	keys, err = o.UnmarshalMacKeys(*params)
	if err != nil {
		return nil, err
	}

	ns := o.GetNs(&tun)
	if ns == nil {
		err = fmt.Errorf(" error there is no valid namespace for this tunnel ")
		return nil, err
	}
	var r []*PluginBase
	r = make([]*PluginBase, 0)

	for _, k := range keys {
		client := ns.CLookupByMac(&k)
		if client == nil {
			err = fmt.Errorf("Error there is no valid client %v for this MAC ", &k)
			return nil, err
		}

		plug := client.PluginCtx.Get(plugin)
		if plug == nil {
			err = fmt.Errorf("Error there is no valid plugin %s for this client ", plugin)
			return nil, err
		}
		r = append(r, plug)
	}

	return r, nil
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
		err = fmt.Errorf(" error there is no valid namespace for this tunnel ")
		return nil, err
	}

	client := ns.CLookupByMac(&key)
	if client == nil {
		err = fmt.Errorf("Error there is no valid client %v for this MAC ", key)
		return nil, err
	}

	plug := client.PluginCtx.Get(plugin)
	if plug == nil {
		err = fmt.Errorf("Error there is no valid plugin %s for this client ", plugin)
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

func (o *CThreadCtx) UnmarshalMacKeys(data []byte) ([]MACKey, error) {
	var rkey RpcCmdMacs
	err := o.UnmarshalValidate(data, &rkey)
	if err != nil {
		return nil, err
	}
	return rkey.MACKeys, nil
}

func (o *CThreadCtx) UnmarshalTunnel(data []byte, key *CTunnelKey) error {
	var tun RpcCmdTunnel
	err := o.UnmarshalValidate(data, &tun)
	if err != nil {
		return err
	}
	key.SetJson(&tun.Tun)
	return nil
}

func (o *CThreadCtx) UnmarshalTunnels(data []byte) ([]CTunnelKey, error) {
	var tuns RpcCmdTunnels
	err := o.UnmarshalValidate(data, &tuns)
	if err != nil {
		return nil, err
	}
	keys := make([]CTunnelKey, len(tuns.Tunnels))
	for i, tun := range tuns.Tunnels {
		keys[i].SetJson(&tun)
	}
	return keys, nil
}

func (o *CThreadCtx) UnmarshalTunnelsPlugins(data []byte) ([]*MapJsonPlugs, error) {
	var tuns RpcCmdTunnels
	err := o.UnmarshalValidate(data, &tuns)
	if err != nil {
		return nil, err
	}
	plugs := make([]*MapJsonPlugs, len(tuns.Tunnels))
	for i, tun := range tuns.Tunnels {
		plugs[i] = tun.Plugins
	}
	return plugs, nil
}

func (o *CThreadCtx) RemoveNsRpc(params *fastjson.RawMessage) error {
	var key CTunnelKey
	err := o.UnmarshalTunnel(*params, &key)
	if err != nil {
		return err
	}
	ns := o.GetNs(&key)
	if ns == nil {
		err = fmt.Errorf(" error can't find a  valid namespace for this tunnel")
		return err
	}

	/* add plugin data */
	o.RemoveNs(&key)
	return nil
}

func (o *CThreadCtx) RemoveNsRpcSlice(params *fastjson.RawMessage) error {
	keys, err := o.UnmarshalTunnels(*params)
	if err != nil {
		return err
	}

	for _, key := range keys {
		ns := o.GetNs(&key)
		if ns == nil {
			return fmt.Errorf(" error can't find a valid namespace for this tunnel")
		}

		/* add plugin data */
		err := o.RemoveNs(&key)
		if err != nil {
			return err
		}
	}

	return nil
}

func (o *CThreadCtx) AddNsRpc(params *fastjson.RawMessage) (*CNSCtx, error) {
	var key CTunnelKey
	err := o.UnmarshalTunnel(*params, &key)
	if err != nil {
		return nil, err
	}
	ns := o.GetNs(&key)
	if ns != nil {
		err = fmt.Errorf(" error there is valid namespace for this tunnel, can't add it ")
		return nil, err
	}

	ns = NewNSCtx(o, &key)
	/* add plugin data */
	o.AddNs(&key, ns)
	return ns, nil
}

func (o *CThreadCtx) AddNsRpcSlice(params *fastjson.RawMessage) error {
	keys, err := o.UnmarshalTunnels(*params)
	if err != nil {
		return err
	}

	plugs, err := o.UnmarshalTunnelsPlugins(*params)
	if err != nil {
		return err
	}

	for i, key := range keys {
		ns := o.GetNs(&key)
		if ns != nil {
			err = fmt.Errorf(" error there is a valid namespace for this tunnel: %s, can't add it ", key)
			return err
		}

		ns = NewNSCtx(o, &key)
		err := o.AddNs(&key, ns)
		if err != nil {
			return err
		}

		if err = o.addPluginsNs(ns, plugs[i]); err != nil {
			return err
		}
	}

	return nil
}

func (o *CThreadCtx) addPluginsNs(ns *CNSCtx, plugs *MapJsonPlugs) error {
	var plugMap *MapJsonPlugs

	if plugs == nil {
		/* ns didn't supply plugins, use ctx defaults */
		plugMap = o.DefNsPlugs
	} else {
		/* ns supply plugins, use them */
		plugMap = plugs
	}

	if plugMap != nil {
		for plName, plData := range *plugMap {
			if err := ns.PluginCtx.addPlugin(plName, *plData); err != nil {
				return err
			}
		}
	}

	return nil
}

func (o *CThreadCtx) GetNsRpc(params *fastjson.RawMessage) (*CNSCtx, error) {
	var key CTunnelKey
	err := o.UnmarshalTunnel(*params, &key)
	if err != nil {
		return nil, err
	}
	ns := o.GetNs(&key)
	if ns == nil {
		err = fmt.Errorf(" error there is no valid namespace for this tunnel ")
		return nil, err
	}
	return ns, nil
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

func (o *CThreadCtx) GetJSONValidator() *validator.Validate {
	return o.validate
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
	ns := o.GetNs(key)
	ns.stats.PreUpdate()
	if ns.stats.activeClient > 0 {
		return fmt.Errorf("ns with tunnel %v still has active clients, remove them", *key)
	}
	ns.OnRemove()
	o.stats.removeNs++
	o.epoc++
	o.nsHead.RemoveNode(&ns.dlist)
	delete(o.mapNs, *key)
	return nil
}

// GetNsPlugin gets the wanted plugin object named `plugName`
func (o *CThreadCtx) GetNsPlugin(params *fastjson.RawMessage, plugin string) (*PluginBase, error) {
	var key CTunnelKey
	err := o.UnmarshalTunnel(*params, &key)
	if err != nil {
		return nil, err
	}
	ns := o.GetNs(&key)
	if ns == nil {
		err = fmt.Errorf(" error there is no valid namespace for this tunnel ")
		return nil, err
	}
	plug := ns.PluginCtx.Get(plugin)
	if plug == nil {
		err = fmt.Errorf(" error there is no valid plugin %s for this tunnel ", plugin)
		return nil, err
	}

	return plug, nil
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
		o.iter.Next()
	}
	return r, nil
}

func (o *CThreadCtx) IterIsStopped() bool {
	return !o.iterReady
}

func (o *CThreadCtx) Dump() {
	o.IterReset()
	fmt.Printf(" namespace  \n")
	for {
		if o.IterIsStopped() {
			break
		}
		obj, err := o.GetNext(1)
		if err != nil {
			fmt.Printf(" %s \n", err.Error())
			break
		}
		fmt.Printf(" KEY : %v \n", obj[0])
	}
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

func (o *CThreadCtx) GetTickSim() uint64 {
	return o.timerctx.Ticks
}

func (o *CThreadCtx) GetTickSimInSec() float64 {
	return o.timerctx.TicksInSec()
}

func (o *CThreadCtx) GetCounterDbVec() *CCounterDbVec {
	return o.cdbv
}

func (o *CThreadCtx) SetVerbose(v bool) {
	o.rpc.mr.Verbose = v
}
