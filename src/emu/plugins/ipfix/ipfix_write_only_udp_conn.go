package ipfix

import (
	"errors"
	"external/google/gopacket"
	"external/google/gopacket/layers"
	"fmt"
	"net"
	"os"
	"syscall"
)

const (
	defRawWriteOnlyUdpConnIfName = "lo"
)

type WriteOnlyUdpConn interface {
	Write(b []byte) (int, error)
	Close() error
}

func WriteOnlyUdpConnDial(srcUdpAddr *net.UDPAddr, dstUdpAddr net.UDPAddr, rawSocketInterfaceName string) (WriteOnlyUdpConn, error) {
	var err error
	var p WriteOnlyUdpConn

	if srcUdpAddr == nil {
		var conn *GoNetWriteOnlyUdpConn
		conn = new(GoNetWriteOnlyUdpConn)
		err = conn.Init(dstUdpAddr)
		if err != nil {
			return nil, err
		}

		p = conn
	} else {
		var conn *RawWriteOnlyUdpConn
		conn = new(RawWriteOnlyUdpConn)
		err = conn.Init(*srcUdpAddr, dstUdpAddr, rawSocketInterfaceName)
		if err != nil {
			return nil, err
		}

		p = conn
	}
	return p, err
}

// GoNetWriteOnlyUdpConn //
type GoNetWriteOnlyUdpConn struct {
	isInit bool
	conn   net.Conn
}

func (p *GoNetWriteOnlyUdpConn) Init(dstUdpAddr net.UDPAddr) error {
	conn, err := net.Dial("udp", dstUdpAddr.String())
	if err != nil {
		return err
	}

	p.conn = conn
	p.isInit = true

	return nil
}

func (p *GoNetWriteOnlyUdpConn) Write(b []byte) (int, error) {
	if p.isInit == false {
		return 0, errors.New("Udp connection is not initialized")
	}

	return p.conn.Write(b)
}

func (p *GoNetWriteOnlyUdpConn) Close() error {
	if p.isInit == false {
		return errors.New("Udp connection is not initialized")
	}

	return p.conn.Close()
}

///////////////////////////

// RawWriteOnlyUdpConn //
type RawWriteOnlyUdpConn struct {
	isInit        bool
	conn          net.PacketConn
	srcIpAddr     *net.IPAddr
	dstIpAddr     *net.IPAddr
	srcPort       uint16
	dstPort       uint16
	interfaceName string
}

const (
	defUdpConnSrcUdpPort = 12345
)

func (p *RawWriteOnlyUdpConn) Init(srcUdpAddr net.UDPAddr, dstUdpAddr net.UDPAddr, interfaceName string) error {
	p.interfaceName = defRawWriteOnlyUdpConnIfName
	if len(interfaceName) > 0 {
		p.interfaceName = interfaceName
	}

	conn, err := p.createPacketConn()
	if err != nil {
		return err
	}

	p.conn = conn
	p.srcIpAddr = &net.IPAddr{IP: srcUdpAddr.IP}
	p.srcPort = uint16(srcUdpAddr.Port)
	if p.srcPort == 0 {
		p.srcPort = defUdpConnSrcUdpPort
	}
	p.dstIpAddr = &net.IPAddr{IP: dstUdpAddr.IP}
	p.dstPort = uint16(dstUdpAddr.Port)
	p.isInit = true

	return nil

}

func (p *RawWriteOnlyUdpConn) Write(b []byte) (int, error) {
	if p.isInit == false {
		return 0, errors.New("Udp connection is not initialized")
	}

	packetBuf, err := p.buildUdpPacket(b)
	if err != nil {
		return 0, err
	}

	wlen, err := p.conn.WriteTo(packetBuf, p.dstIpAddr)
	if err != nil {
		return 0, err
	}

	return wlen, err
}

func (p *RawWriteOnlyUdpConn) Close() error {
	if p.isInit == false {
		return errors.New("Udp connection is not initialized")
	}

	return p.conn.Close()
}

func (p *RawWriteOnlyUdpConn) createPacketConn() (net.PacketConn, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("Failed open socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW): %s", err)
	}
	syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)

	if p.interfaceName != "" {
		_, err := net.InterfaceByName(p.interfaceName)
		if err != nil {
			return nil, fmt.Errorf("Failed to find interface: %s: %s", p.interfaceName, err)
		}
		syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, p.interfaceName)
	}

	conn, err := net.FilePacketConn(os.NewFile(uintptr(fd), fmt.Sprintf("fd %d", fd)))
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (p *RawWriteOnlyUdpConn) buildUdpPacket(b []byte) ([]byte, error) {
	buffer := gopacket.NewSerializeBuffer()
	payload := gopacket.Payload(b)
	ip := &layers.IPv4{
		DstIP:    p.dstIpAddr.IP,
		SrcIP:    p.srcIpAddr.IP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(p.srcPort),
		DstPort: layers.UDPPort(p.dstPort),
	}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, fmt.Errorf("Failed calc checksum: %s", err)
	}
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, ip, udp, payload); err != nil {
		return nil, fmt.Errorf("Failed serialize packet: %s", err)
	}
	return buffer.Bytes(), nil
}

/////////////////////////
