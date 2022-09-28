package ipfix

import (
	"emu/core"
	"emu/plugins/transport"
	"errors"
	"fmt"
	"strconv"
)

type EmuUdpExporterStats struct {
	apiWrites       uint64
	apiWritesFailed uint64
	txBytes         uint64
	txTempRecords   uint64
	txDataRecords   uint64
}

type EmuUdpExporter struct {
	socket     transport.SocketApi
	counters   EmuUdpExporterStats
	countersDb *core.CCounterDb
	init       bool
	enabled    bool
}

type EmuUdpExporterInfoJson struct {
	ExporterType string `json:"exporter_type"`
	Enabled      string `json:"enabled"`
}

const (
	emuUdpExporterType           = "emu-udp"
	emuUdpExporterCountersDbName = "IPFIX emu-udp exporter"
)

func NewEmuUdpExporter(hostport string, c *core.CClient, cb transport.ISocketCb) (*EmuUdpExporter, error) {
	transportCtx := transport.GetTransportCtx(c)
	if transportCtx == nil {
		return nil, errors.New("Failed to get client's transport layer")
	}

	socket, err := transportCtx.Dial("udp", hostport, cb, nil, nil, 0)
	if err != nil {
		return nil, errors.New("Failed to create emu-udp socket")
	}

	p := new(EmuUdpExporter)

	kernelMode := c.PluginCtx.Tctx.GetKernelMode()
	if kernelMode != p.GetKernelMode() {
		return nil, ErrExporterWrongKernelMode
	}

	p.newEmuUdpExporterCountersDb()

	p.socket = socket
	p.enabled = true
	p.init = true

	log.Info("\nIPFIX EMU-UDP exporter created with the following parameters: ",
		"\n\thostport - ", hostport)

	return p, nil
}

func (p *EmuUdpExporter) newEmuUdpExporterCountersDb() {
	p.countersDb = core.NewCCounterDb(emuUdpExporterCountersDbName)

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.apiWrites,
		Name:     "apiWrites",
		Help:     "Num of API calls to write",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.apiWritesFailed,
		Name:     "apiWritesFailed",
		Help:     "Num of failed API calls to write",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.txBytes,
		Name:     "txBytes",
		Help:     "Num of bytes transmitted",
		Unit:     "bytes",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.txTempRecords,
		Name:     "txTempRecords",
		Help:     "Num of template records transmitted",
		Unit:     "records",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.txDataRecords,
		Name:     "txDataRecords",
		Help:     "Num of data records transmitted",
		Unit:     "records",
		DumpZero: false,
		Info:     core.ScINFO})
}

func (p *EmuUdpExporter) Write(b []byte, tempRecordsNum uint32, dataRecordsNum uint32) (int, error) {
	if p.init == false {
		return 0, fmt.Errorf("Failed to write - file exporter object is uninitialized")
	}

	if p.enabled == false {
		return 0, nil
	}

	p.counters.apiWrites++

	serr, _ := p.socket.Write(b)
	if serr != transport.SeOK {
		p.counters.apiWritesFailed++
		return 0, errors.New(string(serr))
	}

	p.counters.txBytes += uint64(len(b))
	p.counters.txTempRecords += uint64(tempRecordsNum)
	p.counters.txDataRecords += uint64(dataRecordsNum)

	return len(b), nil
}

func (p *EmuUdpExporter) Close() error {
	if p.init == false {
		return nil
	}

	err := p.socket.Close()
	if err != transport.SeOK {
		return errors.New(string(err))
	}

	p.init = false

	return nil
}

func (p *EmuUdpExporter) Enable(enable bool) error {
	p.enabled = enable
	return nil
}

func (p *EmuUdpExporter) GetMaxSize() int {
	if p.init == false {
		return 0
	}

	return int(p.socket.GetL7MTU())
}

func (p *EmuUdpExporter) GetType() string {
	return emuUdpExporterType
}

func (p *EmuUdpExporter) GetCountersDbVec() *core.CCounterDbVec {
	db := core.NewCCounterDbVec(emuUdpExporterCountersDbName)
	db.Add(p.countersDb)
	return db
}

func (p *EmuUdpExporter) GetKernelMode() bool {
	return false
}

func (p *EmuUdpExporter) GetInfoJson() interface{} {
	var res EmuUdpExporterInfoJson

	res.ExporterType = p.GetType()
	res.Enabled = strconv.FormatBool(p.enabled)

	return &res
}
