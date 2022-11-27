package ipfix

import (
	"emu/core"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/intel-go/fastjson"
)

type DevicesAutoTrigger struct {
	deviceMac        core.MACKey
	deviceIpv4       core.Ipv4Key
	devicesNum       uint32
	rampupTime       time.Duration
	devicesPerTenant uint32
	totalRatePps     uint32
	deviceInit       *fastjson.RawMessage

	init                       bool                                            // Indicates wether this module is initialized
	triggeredDevicesDb         map[*core.CClient]*DevicesAutoTriggerDeviceInfo // DB of triggered devices
	triggeredDevicesNum        uint32                                          // Number of devices triggered until now
	currDeviceId               uint32                                          // Current device ID
	currTenantId               uint32                                          // Current tenant ID
	timerTickNum               uint32                                          // Timer tick number
	timerTicksTriggerPeriod    uint32                                          // Number of timer ticks to wait between triggers
	deviceTriggersPerTimerTick uint32                                          // Number of devices to trigger in a single timer tick
	startTime                  time.Time

	ipfixNsPlugin *IpfixNsPlugin
	timer         core.CHTimerObj
	timerCtx      *core.TimerCtx
	counters      DevicesAutoTriggerCounters
	countersDb    *core.CCounterDb
}

const (
	devicesAutoTriggerCountersDbName = "Devices auto trigger"
	defaultDevicesNum                = 1
	rampupTimerInterval              = 100 * time.Millisecond
)

type DevicesAutoTriggerParams struct {
	DeviceMac        core.MACKey          `json:"device_mac" validate:"required"`
	DeviceIpv4       core.Ipv4Key         `json:"device_ipv4" validate:"required"`
	DevicesNum       uint32               `json:"devices_num" validate:"required"`
	RampupTime       Duration             `json:"rampup_time"`
	DevicesPerTenant uint32               `json:"devices_per_tenant"`
	TotalRatePps     uint32               `json:"total_rate_pps"`
	DeviceInit       *fastjson.RawMessage `json:"device_init" validate:"required"`
}

type DevicesAutoTriggerCounters struct {
	rampupTime       uint64
	rampupTimeSoFar  uint64
	devicesToTrigger uint32
	devicesTriggered uint32
}

type DevicesAutoTriggerDeviceInfo struct {
	index     uint32       `json:"index"`
	timestamp time.Time    `json:"timestamp"`
	mac       core.MACKey  `json:"mac"`
	ipv4      core.Ipv4Key `json:"ipv4"`
	deviceId  uint32       `json:"device_id"`
	tenantId  uint32       `json:"tenant_id"`
}

func (p *DevicesAutoTriggerDeviceInfo) String() string {
	s := fmt.Sprintln("\nAuto triggered device info: ")
	s += fmt.Sprintln("\tindex -", p.index)
	s += fmt.Sprintln("\tmac -", p.mac)
	s += fmt.Sprintln("\tipv4 -", p.ipv4.ToIP())
	s += fmt.Sprintln("\tdeviceId -", p.deviceId)
	s += fmt.Sprintln("\ttenantId -", p.tenantId)
	return s
}

func NewDevicesAutoTrigger(ipfixNsPlugin *IpfixNsPlugin, initJson *fastjson.RawMessage) (*DevicesAutoTrigger, error) {
	if initJson == nil {
		return nil, errors.New("Invalid initJson parameter")
	}

	if ipfixNsPlugin == nil {
		return nil, errors.New("Invalid NS context parameter")
	}

	params := &DevicesAutoTriggerParams{
		DevicesNum: defaultDevicesNum,
	}

	err := ipfixNsPlugin.Tctx.UnmarshalValidate(*initJson, params)
	if err != nil {
		return nil, err
	}

	if params.DeviceInit == nil {
		return nil, errors.New("Missing deviceInit field in init json")
	}

	p := new(DevicesAutoTrigger)

	p.newCountersDb()

	p.ipfixNsPlugin = ipfixNsPlugin

	p.deviceMac = params.DeviceMac
	p.deviceIpv4 = params.DeviceIpv4
	p.devicesNum = params.DevicesNum
	p.rampupTime = params.RampupTime.Duration
	p.devicesPerTenant = params.DevicesPerTenant
	p.totalRatePps = params.TotalRatePps
	p.deviceInit = params.DeviceInit

	if p.rampupTime < time.Second {
		p.rampupTime = time.Second
	}

	p.timerCtx = ipfixNsPlugin.Tctx.GetTimerCtx()
	p.timer.SetCB(p, 0, 0)

	p.triggeredDevicesNum = 0
	p.triggeredDevicesDb = make(map[*core.CClient]*DevicesAutoTriggerDeviceInfo)

	var devTriggerRate float64
	devTriggerRate = float64(float64(p.devicesNum) / float64(p.rampupTime))
	devTriggersPerTick := devTriggerRate * float64(rampupTimerInterval)
	if devTriggersPerTick < 1.0 {
		p.timerTicksTriggerPeriod = uint32(1 / devTriggersPerTick)
		p.deviceTriggersPerTimerTick = 1
	} else {
		p.timerTicksTriggerPeriod = 1
		p.deviceTriggersPerTimerTick = uint32(devTriggersPerTick)
	}

	p.counters.devicesToTrigger = p.devicesNum
	p.counters.rampupTime = uint64(p.rampupTime.Seconds())

	p.startTime = currentTime()
	p.timerCtx.Start(&p.timer, rampupTimerInterval)

	log.Info("\nIPFIX DevicesAutoTrigger object created with the following parameters: ",
		"\n\tdeviceMac -", p.deviceMac,
		"\n\tdeviceIpv4 -", p.deviceIpv4.ToIP(),
		"\n\tdevicesNum -", p.devicesNum,
		"\n\trampupTime -", p.rampupTime,
		"\n\tdevicesPerTenant -", p.devicesPerTenant,
		"\n\ttotalRatePps -", p.totalRatePps,
		"\n\tdeviceTriggersPerTimerTick -", p.deviceTriggersPerTimerTick,
		"\n\ttimerTicksTriggerPeriod -", p.timerTicksTriggerPeriod,
	)

	p.init = true

	return p, nil
}

func (p *DevicesAutoTrigger) Delete() {
	p.init = false
}

func (p *DevicesAutoTrigger) GetTriggeredDeviceInfo(client *core.CClient) (*DevicesAutoTriggerDeviceInfo, error) {
	if p.init == false {
		return nil, errors.New("DevicesAutoTrigger module is uninitialized")
	}

	if deviceInfo, ok := p.triggeredDevicesDb[client]; ok {
		return deviceInfo, nil
	}

	return nil, errors.New("Device not found in DB")
}

func (p *DevicesAutoTrigger) DumpTriggeredDevicesDb() {
	if p.init == false {
		return
	}

	bs, _ := json.Marshal(p.triggeredDevicesDb)
	fmt.Println(string(bs))
}

func (p *DevicesAutoTrigger) GetCountersDbVec() *core.CCounterDbVec {
	db := core.NewCCounterDbVec(devicesAutoTriggerCountersDbName)
	db.Add(p.countersDb)
	return db
}

func (p *DevicesAutoTrigger) newCountersDb() {
	p.countersDb = core.NewCCounterDb(devicesAutoTriggerCountersDbName)

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.rampupTime,
		Name:     "rampupTime",
		Help:     "Time duration to trigger all devices",
		Unit:     "seconds",
		DumpZero: true,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.rampupTimeSoFar,
		Name:     "rampupTimeSoFar",
		Help:     "Triggering time so far",
		Unit:     "seconds",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.devicesToTrigger,
		Name:     "devicesToTrigger",
		Help:     "Number of devices to trigger",
		Unit:     "devices",
		DumpZero: true,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.devicesTriggered,
		Name:     "devicesTriggered",
		Help:     "Number of devices triggered so far",
		Unit:     "devices",
		DumpZero: true,
		Info:     core.ScINFO})
}

func (p *DevicesAutoTrigger) OnEvent(a, b interface{}) {
	if p.init == false {
		return
	}

	p.counters.rampupTimeSoFar = uint64(time.Now().Sub(p.startTime).Seconds())

	if p.timerTickNum%p.timerTicksTriggerPeriod == 0 {
		p.triggerDevices(p.deviceTriggersPerTimerTick)
	}

	p.timerTickNum++

	if p.triggeredDevicesNum < p.devicesNum {
		p.timerCtx.Start(&p.timer, rampupTimerInterval)
	}
}

func (p *DevicesAutoTrigger) triggerDevices(numDevices uint32) {
	for i := uint32(1); i <= numDevices; i++ {
		p.triggerDevice()
	}
}

func (p *DevicesAutoTrigger) triggerDevice() {
	var mac core.MACKey
	var ipv4 core.Ipv4Key
	var device_init [][]byte

	mac.SetUint64(p.deviceMac.Uint64() + uint64(p.triggeredDevicesNum))
	ipv4.SetUint32(p.deviceIpv4.Uint32() + p.triggeredDevicesNum)
	device_init = [][]byte{*p.deviceInit}

	client := core.NewClient(p.ipfixNsPlugin.Ns, mac, ipv4, core.Ipv6Key{}, core.Ipv4Key{0, 0, 0, 0})
	p.ipfixNsPlugin.Ns.AddClient(client)

	deviceInfo := new(DevicesAutoTriggerDeviceInfo)
	deviceInfo.index = p.triggeredDevicesNum
	deviceInfo.timestamp = currentTime()
	deviceInfo.mac = mac
	deviceInfo.ipv4 = ipv4
	deviceInfo.deviceId = p.currDeviceId
	deviceInfo.tenantId = p.currTenantId

	p.triggeredDevicesDb[client] = deviceInfo

	// Create client IPFIX plugin. This must be done after device info was inserted to the DB.
	client.PluginCtx.CreatePlugins([]string{IPFIX_PLUG}, device_init)

	p.triggeredDevicesNum += 1
	p.currDeviceId += 1
	if p.devicesPerTenant != 0 && p.currDeviceId%p.devicesPerTenant == 0 {
		p.currDeviceId = 0
		p.currTenantId += 1
	}

	log.Info(deviceInfo)

	p.counters.devicesTriggered++
}
