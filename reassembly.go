package main

import (
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
)

type streamFactory struct{}

func (f *streamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	s := &stream{
		net:       net,
		transport: transport,
		start:     time.Now(),
	}
	s.end = s.start
	return s
}

type stream struct {
	net, transport                       gopacket.Flow
	bytes, npackets, outOfOrder, skipped int64
	start, end                           time.Time
	sawStart, sawEnd                     bool
	payload                              []byte
}

func (s *stream) Reassembled(rs []tcpassembly.Reassembly) {
	for _, r := range rs {
		if r.Seen.Before(s.end) {
			s.outOfOrder++
		} else {
			s.end = r.Seen
		}
		s.bytes += int64(len(r.Bytes))
		s.payload = append(s.payload, r.Bytes...)
		s.npackets += 1
		if r.Skip > 0 {
			s.skipped += int64(r.Skip)
		}
		s.sawStart = s.sawStart || r.Start
		s.sawEnd = s.sawEnd || r.End
	}
}

func (s *stream) ReassemblyComplete() {
	if len(s.payload) > 0 {
		log.Printf("Payload Length: %v\n", len(s.payload))
		log.Printf("Payload: %+q\n", s.payload)
	}
}
