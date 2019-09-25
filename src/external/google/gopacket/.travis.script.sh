#!/bin/bash

set -ev

go test external/google/gopacket
go test external/google/gopacket/layers
go test external/google/gopacket/tcpassembly
go test external/google/gopacket/reassembly
go test external/google/gopacket/pcapgo 
go test external/google/gopacket/pcap
