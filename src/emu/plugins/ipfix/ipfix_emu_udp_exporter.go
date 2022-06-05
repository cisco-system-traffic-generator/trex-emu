package ipfix

import (
	"emu/core"
	"emu/plugins/transport"
	"errors"
	"fmt"
)

type EmuUdpExporterStats struct {
	writes       uint64
	writesFailed uint64
	txBytes      uint64
}

type EmuUdpExporter struct {
	socket     transport.SocketApi
	counters   EmuUdpExporterStats
	countersDb *core.CCounterDb
	init       bool
}

type EmuUdpExporterInfoJson struct {
	ExporterType string `json:"exporter_type"`
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
	p.init = true

	log.Info("\nIPFIX EMU-UDP exporter created with the following parameters: ",
		"\n\thostport - ", hostport)

	return p, nil
}

func (p *EmuUdpExporter) newEmuUdpExporterCountersDb() {
	p.countersDb = core.NewCCounterDb(emuUdpExporterCountersDbName)

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.writes,
		Name:     "writes",
		Help:     "Num of writes",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.writesFailed,
		Name:     "writesFailed",
		Help:     "Num of failed writes",
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
}

func (p *EmuUdpExporter) Write(b []byte) (int, error) {
	if p.init == false {
		return 0, fmt.Errorf("Failed to write - file exporter object is uninitialized")
	}

	p.counters.writes++

	var serr transport.SocketErr
	serr, _ = p.socket.Write(b)
	if serr != transport.SeOK {
		p.counters.writesFailed++
		return 0, errors.New(string(serr))
	}

	p.counters.txBytes += uint64(len(b))

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

	return &res
}
