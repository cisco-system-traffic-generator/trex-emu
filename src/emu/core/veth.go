package core

type VethStats struct {
	TxPkts           uint64
	TxBytes          uint64
	RxPkts           uint64
	RxBytes          uint64
	TxDropNotResolve uint64 /* no resolved dg */
}

/*VethIF represent a way to send and receive packet */
type VethIF interface {

	/* Flush the tx buffer and send the packets */
	FlushTx()

	/* the mbuf should be ready for sending*/
	Send(m *Mbuf)

	// SendBuffer get a buffer as input, should allocate mbuf and call send
	SendBuffer(unicast bool, c *CClient, b []byte)

	// get
	OnRx(m *Mbuf)

	/* get the veth stats */
	GetStats() *VethStats

	SimulatorCheckRxQueue()
}

type VethIFSim interface {

	/* Simulate a DUT that gets a mbuf and response with mbuf if needed or nil if there is no need to response */
	ProcessTxToRx(m *Mbuf) *Mbuf
}

type VethIFSimulator struct {
	vec   []*Mbuf
	stats VethStats
	tctx  *CThreadCtx
	Sim   VethIFSim /* interface per test to simulate DUT */
}

func (o *VethIFSimulator) Create(ctx *CThreadCtx) {
	o.vec = make([]*Mbuf, 0)
	o.tctx = ctx
}

func (o *VethIFSimulator) FlushTx() {

}

func (o *VethIFSimulator) Send(m *Mbuf) {

	o.stats.TxPkts++
	o.stats.TxBytes += uint64(m.PktLen())
	if !m.IsContiguous() {
		m1 := m.GetContiguous(&o.tctx.MPool)
		m.FreeMbuf()
		o.vec = append(o.vec, m1)
	} else {
		o.vec = append(o.vec, m)
	}
}

// SendBuffer get a buffer as input, should allocate mbuf and call send
func (o *VethIFSimulator) SendBuffer(unicast bool, c *CClient, b []byte) {
	var vport uint16
	vport = c.Ns.GetVport()
	m := o.tctx.MPool.Alloc(uint16(len(b)))
	m.SetVPort(vport)
	m.Append(b)
	if unicast {
		if c.DGW == nil {
			m.FreeMbuf()
			o.stats.TxDropNotResolve++
			return
		}
		if !c.DGW.Ipv4dgResolved {
			m.FreeMbuf()
			o.stats.TxDropNotResolve++
			return
		}
		p := m.GetData()
		copy(p[6:12], c.Mac[:])
	}
	o.Send(m)
}

// get the packet
func (o *VethIFSimulator) OnRx(m *Mbuf) {
	o.stats.RxPkts++
	o.stats.RxBytes += uint64(m.PktLen())
	o.tctx.HandleRxPacket(m)
}

/* get the veth stats */
func (o *VethIFSimulator) GetStats() *VethStats {
	return &o.stats
}

func (o *VethIFSimulator) SimulatorCheckRxQueue() {

	for _, m := range o.vec {
		mrx := o.Sim.ProcessTxToRx(m)
		m.FreeMbuf()
		if mrx != nil {
			o.OnRx(mrx)
		}
	}
	o.vec = o.vec[:0]
}
