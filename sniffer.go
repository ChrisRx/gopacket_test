package main

import (
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

type Config struct {
	filename      string
	iface         string
	filter        string
	flushInterval time.Duration
}

type Sniffer struct {
	assembler    *tcpassembly.Assembler
	c            *Config
	handle       *pcap.Handle
	packetSource *gopacket.PacketSource
}

func NewSniffer(c *Config) *Sniffer {
	var handle *pcap.Handle
	var err error
	if c.filename != "" {
		log.Printf("Reading from pcap dump %q", c.filename)
		handle, err = pcap.OpenOffline(c.filename)
	} else {
		log.Printf("Starting capture on interface %q", c.iface)
		handle, err = pcap.OpenLive(c.iface, 65535, true, pcap.BlockForever)
	}
	if err != nil {
		log.Fatal(err)
	}

	if err := handle.SetBPFFilter(c.filter); err != nil {
		log.Fatal(err)
	}
	assembler := tcpassembly.NewAssembler(tcpassembly.NewStreamPool(&streamFactory{}))
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	return &Sniffer{
		assembler:    assembler,
		handle:       handle,
		c:            c,
		packetSource: packetSource,
	}
}

func (s *Sniffer) Packets() chan gopacket.Packet {
	return s.packetSource.Packets()
}

func (s *Sniffer) Run() {
	ticker := time.Tick(time.Minute)
	for {
		select {
		case packet := <-s.Packets():
			if packet == nil {
				s.assembler.FlushAll()
				return
			}

			if packet.NetworkLayer() == nil {
				log.Println("Packet does not have layer 2")
				continue
			}

			switch packet.TransportLayer().LayerType() {
			case layers.LayerTypeUDP:
				_ = packet.TransportLayer().(*layers.UDP)
			case layers.LayerTypeTCP:
				s.assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(),
					packet.TransportLayer().(*layers.TCP), packet.Metadata().Timestamp)
			default:
				log.Println("Unknown Layer 3")
			}

		case <-ticker:
			s.assembler.FlushOlderThan(time.Now().Add(s.c.flushInterval * -1))
		}
	}
}
