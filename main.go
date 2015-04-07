package main

import (
	"encoding/hex"
	"flag"
	"github.com/ChrisRx/gopacket"
	"github.com/ChrisRx/gopacket/layers"
	"github.com/ChrisRx/gopacket/pcap"
	"github.com/ChrisRx/gopacket/tcpassembly"
	"hash/fnv"
	"log"
	"time"
)

var iface = flag.String("i", "eth0", "Interface to get packets from")
var fname = flag.String("r", "", "Filename to read from, overrides -i")
var snaplen = flag.Int("S", 65535, "SnapLen for pcap packet capture")
var filter = flag.String("f", "tcp or udp", "BPF filter for pcap")
var verbose = flag.Bool("v", false, "Logs every packet in great detail")
var debugLog = flag.Bool("d", false, "Log debug information")

type MongooseStruct struct {
	sniffer   *pcap.Handle
	assembler *tcpassembly.Assembler
}

var Mongoose MongooseStruct

func Hash(text ...string) string {
	h := fnv.New64()
	for _, s := range text {
		h.Write([]byte(s))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func handlePacket(packet gopacket.Packet) error {
	index := Hash(packet.String())
	switch packet.TransportLayer().LayerType() {
	case layers.LayerTypeUDP:
		//udp := packet.TransportLayer().(*layers.UDP)
		_ = packet.TransportLayer().(*layers.UDP)
	case layers.LayerTypeTCP:
		tcp := packet.TransportLayer().(*layers.TCP)
		Mongoose.assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp,
			index, packet.Metadata().Timestamp)
	default:
		if *debugLog {
			log.Println("Unknown Layer 3")
		}
	}
	return nil
}

func main() {
	flag.Parse()
	var handle *pcap.Handle
	var err error

	if *fname != "" {
		log.Printf("Reading from pcap dump %q", *fname)
		handle, err = pcap.OpenOffline(*fname)
	} else {
		log.Printf("Starting capture on interface %q", *iface)
		handle, err = pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
	}

	if err != nil {
		log.Fatal(err)
	}

	if err := handle.SetBPFFilter(*filter); err != nil {
		log.Fatal(err)
	}

	streamFactory := tcpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(&streamFactory)
	Mongoose.assembler = tcpassembly.NewAssembler(streamPool)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(time.Minute)
	for {
		select {
		case packet := <-packets:
			if packet == nil {
				Mongoose.assembler.FlushAll()
				return
			}

			if *verbose {
				log.Println(packet)
			}

			if packet.NetworkLayer() == nil {
				log.Println("Packet does not have layer 2")
				continue
			}

			_ = handlePacket(packet)

		case <-ticker:
			Mongoose.assembler.FlushOlderThan(time.Now().Add(time.Minute * -1))
		}
	}
}
