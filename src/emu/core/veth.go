package core

type VethStats struct {
	txPkts           uint64
	txBytes          uint64
	rxPkts           uint64
	rxBytes          uint64
	txDropNotResolve uint64 /* no resolved dg */

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
}
