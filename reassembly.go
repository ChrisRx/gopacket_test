package main

import (
	"github.com/ChrisRx/gopacket"
	"github.com/ChrisRx/gopacket/tcpassembly"
	"log"
	"time"
)

type tcpStreamFactory struct{}

type tcpStream struct {
	net, transport                       gopacket.Flow
	bytes, npackets, outOfOrder, skipped int64
	start, end                           time.Time
	sawStart, sawEnd                     bool
	payload                              []byte
	first, last                          string
	previous                             string
	packets                              []string
}

func (factory *tcpStreamFactory) New(net, transport gopacket.Flow, index string) tcpassembly.Stream {
	s := &tcpStream{
		net:       net,
		transport: transport,
		start:     time.Now(),
	}
	s.first = index
	s.last = s.first
	s.previous = s.last
	s.end = s.start
	s.packets = append(s.packets, index)
	return s
}

func (s *tcpStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	for _, reassembly := range reassemblies {
		if reassembly.Seen.Before(s.end) {
			s.outOfOrder++
		} else {
			s.end = reassembly.Seen
		}
		s.bytes += int64(len(reassembly.Bytes))
		s.payload = append(s.payload, reassembly.Bytes...)
		s.npackets += 1
		if reassembly.Skip > 0 {
			s.skipped += int64(reassembly.Skip)
		}
		s.sawStart = s.sawStart || reassembly.Start
		s.sawEnd = s.sawEnd || reassembly.End
	}
}

func (s *tcpStream) ReassemblyComplete() {
	if *debugLog {
		log.Printf("Reassembled: %v:%v", s.net, s.transport)
		log.Printf("Stream finished: %v -> %v", s.first, s.last)
	}
	log.Printf("Payload Length: %v\n", len(s.payload))
	log.Printf("Payload: %s\n", s.payload)
}
