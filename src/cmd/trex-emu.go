package main

import (
	"emu/core"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/akamensky/argparse"

	"emu/plugins/arp"
	dhcp "emu/plugins/dhcpv4"
	"emu/plugins/dhcpv6"
	"emu/plugins/icmp"
	"emu/plugins/igmp"
	"emu/plugins/ipv6"
)

func RegisterPlugins(tctx *core.CThreadCtx) {
	arp.Register(tctx)
	icmp.Register(tctx)
	igmp.Register(tctx)
	ipv6.Register(tctx)
	dhcp.Register(tctx)
	dhcpv6.Register(tctx)
}

type MainArgs struct {
	port      int
	verbose   bool
	sim       bool
	capture   bool
	monitor   bool
	time      time.Duration
	file      string
	dummyVeth bool
	vethPort  int
	zmqServer string
}

func parseMainArgs() *MainArgs {
	var args MainArgs
	parser := argparse.NewParser("Emu Server", "Emu server emulates clients and namespaces")

	args.port = *parser.Int("p", "rpc port", &argparse.Options{Default: 4510, Help: "RPC Port for server"})
	args.vethPort = *parser.Int("l", "veth zmq port", &argparse.Options{Default: 4511, Help: "Veth Port for server"})
	args.verbose = *parser.Flag("v", "verbose", &argparse.Options{Default: false, Help: "Run server in verbose mode"})
	args.sim = *parser.Flag("s", "simulator", &argparse.Options{Default: false, Help: "Run server in simulator mode"})
	args.zmqServer = *parser.String("S", "zmq-server", &argparse.Options{Default: "127.0.0.1", Help: "zmq server ip"})
	args.capture = *parser.Flag("c", "capture", &argparse.Options{Default: false, Help: "Run server in capture mode"})
	args.monitor = *parser.Flag("m", "monitor", &argparse.Options{Default: false, Help: "Run server in K12 monitor mode"})
	args.time = time.Duration(*parser.Int("t", "time", &argparse.Options{Default: 10, Help: "Time of the simulation in sec"}))
	args.file = *parser.String("f", "file", &argparse.Options{Default: "emu_file", Help: "Path to save the pcap file"})
	args.dummyVeth = *parser.Flag("d", "dummy-veth", &argparse.Options{Default: false, Help: "Run server with a dummy veth, all packets to rx will be dropped"})

	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
	}

	args.time = args.time * time.Second

	return &args
}

func RunCoreZmq(args *MainArgs) {

	var zmqVeth core.VethIFZmq

	port := uint16(args.port)
	fmt.Printf("run zmq server on [%d:rx:%d:tx:%d] \n", port, args.vethPort, args.vethPort+1)
	rand.Seed(time.Now().UnixNano())

	var simrx core.VethIFSim
	if args.dummyVeth {
		var simVeth core.VethSink
		simrx = &simVeth
	}

	tctx := core.NewThreadCtx(0, port, args.sim, &simrx)

	if !args.sim {
		zmqVeth.Create(tctx, uint16(args.vethPort), args.zmqServer)
		zmqVeth.StartRxThread()
		tctx.SetZmqVeth(&zmqVeth)
	}

	RegisterPlugins(tctx)

	tctx.SetVerbose(args.verbose)
	tctx.Veth.SetDebug(args.monitor, args.capture)
	tctx.StartRxThread()
	defer tctx.Delete()

	if !args.sim {
		tctx.MainLoop()
	} else {
		tctx.MainLoopSim(args.time)
	}
	if args.capture {
		tctx.SimRecordExport(args.file)
	}
}

func main() {
	RunCoreZmq(parseMainArgs())
}
