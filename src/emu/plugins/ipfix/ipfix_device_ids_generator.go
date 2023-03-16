package ipfix

import (
	"fmt"
	"strconv"

	"github.com/google/uuid"
)

type DeviceIdsGen struct {
	devicesPerSite       uint32
	sitesPerTenant       uint32
	deviceIdsFromIndexDb map[uint32]*DeviceIds
	tenantUuidDb         map[uint32]string // Map containing uuid per tenant ID
	siteUuidDb           map[uint32]string // Map containing uuid per site ID
	deviceUuidDb         map[uint32]string // Map containing uuid per device ID
	uuidDb               map[uint32]string
}

type DeviceIds struct {
	tenantId   string // Tenant ID
	tenantUuid string // Tenant UUID
	siteId     string // Site ID per tenant
	siteUuid   string // Site UUID per tenant
	deviceId   string // Device ID per site
	deviceUuid string // Device UUID per site
	uuid       string // UUID per device
}

func (p *DeviceIds) String() string {
	s := fmt.Sprintln("\nDevices ids: ")
	s += fmt.Sprintln("\ttenantId -", p.tenantId)
	s += fmt.Sprintln("\ttenantUuid -", p.tenantUuid)
	s += fmt.Sprintln("\tsiteId -", p.siteId)
	s += fmt.Sprintln("\tsiteUuid -", p.siteUuid)
	s += fmt.Sprintln("\tdeviceId -", p.deviceId)
	s += fmt.Sprintln("\tdeviceUuid -", p.deviceUuid)
	s += fmt.Sprintln("\tuuid -", p.uuid)

	return s
}

func NewDeviceIdsGen(devicesPerSite, sitesPerTenant uint32) (*DeviceIdsGen, error) {
	idsGen := new(DeviceIdsGen)
	idsGen.devicesPerSite = devicesPerSite
	idsGen.sitesPerTenant = sitesPerTenant

	idsGen.deviceIdsFromIndexDb = make(map[uint32]*DeviceIds)
	idsGen.tenantUuidDb = make(map[uint32]string)
	idsGen.siteUuidDb = make(map[uint32]string)
	idsGen.deviceUuidDb = make(map[uint32]string)
	idsGen.uuidDb = make(map[uint32]string)

	return idsGen, nil
}

func (p *DeviceIdsGen) GetDeviceIds(deviceIndex uint32) *DeviceIds {
	var isExist bool
	var ids *DeviceIds

	ids, isExist = p.deviceIdsFromIndexDb[deviceIndex]
	if isExist {
		return ids
	}

	tenantId, siteId, deviceId := p.getTenantSiteDeviceIds(deviceIndex)
	tenantUuid, siteUuid, deviceUuid, indexUuid := p.getUuids(tenantId, siteId, deviceId, deviceIndex)

	ids = &DeviceIds{
		tenantId:   strconv.FormatUint(uint64(tenantId), 10),
		tenantUuid: tenantUuid,
		siteId:     strconv.FormatUint(uint64(siteId), 10),
		siteUuid:   siteUuid,
		deviceId:   strconv.FormatUint(uint64(deviceId), 10),
		deviceUuid: deviceUuid,
		uuid:       indexUuid,
	}

	p.deviceIdsFromIndexDb[deviceIndex] = ids

	return ids
}

func (p *DeviceIdsGen) getTenantSiteDeviceIds(deviceIndex uint32) (tenantId, siteId, deviceId uint32) {
	if p.devicesPerSite > 0 {
		deviceId = deviceIndex % p.devicesPerSite
		if p.sitesPerTenant > 0 {
			siteId = (deviceIndex / p.devicesPerSite) % p.sitesPerTenant
			tenantId = (deviceIndex / p.devicesPerSite) / (p.sitesPerTenant)
		}
	} else {
		deviceId = deviceIndex
	}

	return tenantId, siteId, deviceId
}

func (p *DeviceIdsGen) getUuids(tenantId, siteId, deviceId, deviceIndex uint32) (tenantUuid, siteUuid, deviceUuid, indexUuid string) {
	var isExist bool

	tenantUuid, isExist = p.tenantUuidDb[tenantId]
	if !isExist {
		tenantUuid = uuid.NewString()
		p.tenantUuidDb[tenantId] = tenantUuid
	}

	siteUuid, isExist = p.siteUuidDb[siteId]
	if !isExist {
		siteUuid = uuid.NewString()
		p.siteUuidDb[siteId] = siteUuid
	}

	deviceUuid, isExist = p.deviceUuidDb[deviceId]
	if !isExist {
		deviceUuid = uuid.NewString()
		p.deviceUuidDb[deviceId] = deviceUuid
	}

	indexUuid, isExist = p.deviceUuidDb[deviceIndex]
	if !isExist {
		indexUuid = uuid.NewString()
		p.deviceUuidDb[deviceIndex] = indexUuid
	}

	return tenantUuid, siteUuid, deviceUuid, indexUuid
}
