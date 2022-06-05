module github.com/my/repo

go 1.13

replace emu => ../src/emu

replace external => ../src/external

replace external/google/gopacket => ../src/external/google/gopacket

require (
	emu v0.0.0-00010101000000-000000000000
	external v0.0.0-00010101000000-000000000000 // indirect
	external/google/gopacket v0.0.0-00010101000000-000000000000 // indirect
	github.com/akamensky/argparse v1.2.0
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7
	github.com/pebbe/zmq4 v1.2.9 // indirect
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8
)
