package ipfix

import (
	"emu/core"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/intel-go/fastjson"
)

type DevicesAutoTrigger struct {
	deviceMac        core.MACKey
	deviceIpv4       core.Ipv4Key
	deviceDomainId   uint32
	devicesNum       uint32
	rampupTime       time.Duration
	sitesPerTenant   uint32
	devicesPerSite   uint32
	totalRatePps     uint32
	clientsGenParams *ClientsGenParams
	deviceInit       *fastjson.RawMessage

	init                       bool                                            // Indicates wether this module is initialized
	triggeredDevicesDb         map[*core.CClient]*DevicesAutoTriggerDeviceInfo // DB of triggered devices
	triggeredDevicesNum        uint32                                          // Number of devices triggered until now
	currTenantId               uint32                                          // Current tenant ID
	currSiteId                 uint32                                          // Current site ID
	currDeviceId               uint32                                          // Current device ID
	tenantUuidDb               map[uint32]string                               // Map containing uuid per tenant ID
	siteUuidDb                 map[uint32]string                               // Map containing uuid per site ID
	deviceUuidDb               map[uint32]string                               // Map containing uuid per device ID
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
	DeviceDomainId   uint32               `json:"device_domain_id"` // Initial domain-id. If zero this param is ignored.
	DevicesNum       uint32               `json:"devices_num" validate:"required"`
	RampupTime       Duration             `json:"rampup_time"`
	SitesPerTenant   uint32               `json:"sites_per_tenant"`
	DevicesPerSite   uint32               `json:"devices_per_site"`
	TotalRatePps     uint32               `json:"total_rate_pps"`
	ClientsGenerator *fastjson.RawMessage `json:"clients_generator"`
	DeviceInit       *fastjson.RawMessage `json:"device_init" validate:"required"`
}

type DevicesAutoTriggerCounters struct {
	rampupTime       uint64
	rampupTimeSoFar  uint64
	devicesToTrigger uint32
	devicesTriggered uint32
}

type DevicesAutoTriggerDeviceInfo struct {
	index            uint32
	timestamp        time.Time
	mac              core.MACKey
	ipv4             core.Ipv4Key
	domainId         uint32 // Domain ID to be used by triggered device (ignored if zero)
	tenantId         string // Tenant ID
	tenantUuid       string // Tenant UUID
	siteId           string // Site ID per tenant
	siteUuid         string // Site UUID per tenant
	deviceId         string // Device ID per site
	deviceUuid       string // Device UUID per site
	uuid             string // UUID per device
	clientsGenParams *ClientsGenParams
}

func (p *DevicesAutoTriggerDeviceInfo) String() string {
	s := fmt.Sprintln("\nAuto triggered device info: ")
	s += fmt.Sprintln("\tindex -", p.index)
	s += fmt.Sprintln("\tmac -", p.mac)
	s += fmt.Sprintln("\tipv4 -", p.ipv4.ToIP())
	s += fmt.Sprintln("\tdomainId -", p.domainId)
	s += fmt.Sprintln("\ttenantId -", p.tenantId)
	s += fmt.Sprintln("\ttenantUuid -", p.tenantUuid)
	s += fmt.Sprintln("\tsiteId -", p.siteId)
	s += fmt.Sprintln("\tsiteUuid -", p.siteUuid)
	s += fmt.Sprintln("\tdeviceId -", p.deviceId)
	s += fmt.Sprintln("\tdeviceUuid -", p.deviceUuid)
	s += fmt.Sprintln("\tuuid -", p.uuid)

	if p.clientsGenParams != nil {
		s += p.clientsGenParams.String()
	}

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

	err := ipfixNsPlugin.Tctx.UnmarshalValidateDisallowUnknownFields(*initJson, params)
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
	p.deviceDomainId = params.DeviceDomainId
	p.devicesNum = params.DevicesNum
	p.rampupTime = params.RampupTime.Duration
	p.sitesPerTenant = params.SitesPerTenant
	p.devicesPerSite = params.DevicesPerSite
	p.totalRatePps = params.TotalRatePps
	p.deviceInit = params.DeviceInit

	if p.rampupTime < time.Second {
		p.rampupTime = time.Second
	}

	if params.ClientsGenerator != nil {
		p.clientsGenParams, err = UnmarshalClientsGenParams(ipfixNsPlugin, params.ClientsGenerator)
		if err != nil {
			return nil, err
		}
	}

	p.tenantUuidDb = make(map[uint32]string)
	p.siteUuidDb = make(map[uint32]string)
	p.deviceUuidDb = make(map[uint32]string)

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
		"\n\tdeviceDomainId -", p.deviceDomainId,
		"\n\tdevicesNum -", p.devicesNum,
		"\n\trampupTime -", p.rampupTime,
		"\n\tsitesPerTenant -", p.sitesPerTenant,
		"\n\tdevicesPerSite -", p.devicesPerSite,
		"\n\ttotalRatePps -", p.totalRatePps,
		"\n\tdeviceTriggersPerTimerTick -", p.deviceTriggersPerTimerTick,
		"\n\ttimerTicksTriggerPeriod -", p.timerTicksTriggerPeriod,
		"\n\tratePerDevicePps -", p.GetRatePerDevicePps(),
	)

	if p.clientsGenParams != nil {
		log.Info("\nIPFIX DevicesAutoTrigger clients generator parameters: \n", p.clientsGenParams.String())
	}

	p.init = true

	return p, nil
}

func (p *DevicesAutoTrigger) Delete() {
	p.init = false
}

func (p *DevicesAutoTrigger) GetRatePerDevicePps() float32 {
	return float32(p.totalRatePps) / float32(p.devicesNum)
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

func (p *DevicesAutoTrigger) getUuids(tenantId, siteId, deviceId uint32) (tenantUuid, siteUuid, deviceUuid string) {
	var isExist bool

	tenantUuid, isExist = p.tenantUuidDb[tenantId]
	if !isExist {
		tenantUuid = uuid.NewString()
		p.tenantUuidDb[p.currTenantId] = tenantUuid
	}

	siteUuid, isExist = p.siteUuidDb[siteId]
	if !isExist {
		siteUuid = uuid.NewString()
		p.siteUuidDb[p.currSiteId] = siteUuid
	}

	deviceUuid, isExist = p.deviceUuidDb[deviceId]
	if !isExist {
		deviceUuid = uuid.NewString()
		p.deviceUuidDb[p.currDeviceId] = deviceUuid
	}

	return tenantUuid, siteUuid, deviceUuid
}

func (p *DevicesAutoTrigger) triggerDevice() {
	var mac core.MACKey
	var ipv4 core.Ipv4Key
	var domainId uint32
	var deviceInit [][]byte

	if p.triggeredDevicesNum >= p.devicesNum {
		return
	}

	mac.SetUint64(p.deviceMac.Uint64() + uint64(p.triggeredDevicesNum))
	ipv4.SetUint32(p.deviceIpv4.Uint32() + p.triggeredDevicesNum)
	if p.deviceDomainId > 0 {
		domainId = p.deviceDomainId + p.triggeredDevicesNum
	}

	deviceInit = [][]byte{*p.deviceInit}

	client := core.NewClient(p.ipfixNsPlugin.Ns, mac, ipv4, core.Ipv6Key{}, core.Ipv4Key{0, 0, 0, 0})
	p.ipfixNsPlugin.Ns.AddClient(client)

	deviceInfo := new(DevicesAutoTriggerDeviceInfo)
	deviceInfo.index = p.triggeredDevicesNum
	deviceInfo.timestamp = currentTime()
	deviceInfo.mac = mac
	deviceInfo.ipv4 = ipv4
	deviceInfo.domainId = domainId
	deviceInfo.tenantId = strconv.FormatUint(uint64(p.currTenantId), 10)
	deviceInfo.siteId = strconv.FormatUint(uint64(p.currSiteId), 10)
	deviceInfo.deviceId = strconv.FormatUint(uint64(p.currDeviceId), 10)
	deviceInfo.uuid = uuid.NewString()
	deviceInfo.tenantUuid, deviceInfo.siteUuid, deviceInfo.deviceUuid =
		p.getUuids(p.currTenantId, p.currSiteId, p.currDeviceId)

	if p.clientsGenParams != nil {
		var clientIpv4 core.Ipv4Key
		params := p.clientsGenParams
		// Each triggered device will be assigned a different range of client IPs
		clientIpv4.SetUint32(params.ClientIpv4.Uint32() + p.triggeredDevicesNum*params.ClientsPerDevice)
		deviceInfo.clientsGenParams = &ClientsGenParams{
			ClientIpv4FieldName:  params.ClientIpv4FieldName,
			ClientIpv4:           clientIpv4,
			ClientsPerDevice:     params.ClientsPerDevice,
			DataRecordsPerClient: params.DataRecordsPerClient}
	}

	p.triggeredDevicesDb[client] = deviceInfo

	// Create client IPFIX plugin. This must be done after device info was inserted to the DB.
	client.PluginCtx.CreatePlugins([]string{IPFIX_PLUG}, deviceInit)

	// Create new Tenant/Site/Device ids
	p.triggeredDevicesNum++
	p.currDeviceId++
	if p.devicesPerSite != 0 && p.currDeviceId%p.devicesPerSite == 0 {
		p.currDeviceId = 0
		p.currSiteId++
		if p.sitesPerTenant != 0 && p.currSiteId%p.sitesPerTenant == 0 {
			p.currSiteId = 0
			p.currTenantId++
		}
	}

	log.Info(deviceInfo)

	p.counters.devicesTriggered++
}
