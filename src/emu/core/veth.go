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
