// Copyright 2017-2024 National Technology & Engineering Solutions of Sandia, LLC (NTESS).
// Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains certain
// rights in this software.

package main

import (
	"math/rand"
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	log "github.com/sandia-minimega/minimega/v2/pkg/minilog"
)

// This works on Linux, and should work on Darwin (MacOS)
func icmpClient() {
	log.Infoln("Starting icmpClient")

	// TODO: windows support. use ping.exe?
	// TODO: icmp server

	// IPv4
	var v4conn *icmp.PacketConn
	if *f_v4 {
		// udp4 allows for unprivileged ping, icmp requires root ("ip4:icmp")
		v4conn, err := icmp.ListenPacket("udp4", "0.0.0.0")
		if err != nil {
			log.Fatal("failed icmp listen on IPv4: %s", err.Error())
		}
		defer v4conn.Close()
	} else {
		v4conn = nil
	}

	// IPv6
	var v6conn *icmp.PacketConn
	if *f_v6 {
		log.Debug("f_v6: %v", *f_v6)
		v6conn, err := icmp.ListenPacket("udp6", "::")
		if err != nil {
			log.Fatal("failed icmp listen on IPv6: %s", err.Error())
		}
		defer v6conn.Close()
	} else {
		v6conn = nil
	}

	rand.Seed(time.Now().UnixNano())
	t := NewEventTicker(*f_mean, *f_stddev, *f_min, *f_max)

	for {
		t.Tick()
		h, _ := randomHost()

		if ip := net.ParseIP(h); ip != nil {
			if ip.To4() != nil && v4conn != nil {
				sendICMP(ip, *v4conn, true)
				// TODO: should we listen?
				// listenICMPReply4(*v4conn)
			} else if v6conn != nil {
				sendICMP(ip, *v6conn, false)
				// TODO: should we listen?
				// listenICMPReply6(*v6conn)
			} else {
				log.Fatal("IP protocol for address '%v' is not enabled for ICMP client", ip)
			}
		} else {
			// Resolve the DNS name to IP addresses
			ips, err := net.LookupIP(h)
			if err != nil {
				log.Fatal("Failed to resolve DNS name for host '%s': %v", h, err)
			}

			// Separate and print IPv4 and IPv6 addresses
			// TODO: if both a v4 and v6 address is resolved, prioritize v4 address? or use based on what protocols are enabled?
			for _, ip := range ips {
				if ip.To4() != nil {
					log.Debug("Resolved IPv4 address: %s (host: %s)", ip.String(), h)
					sendICMP(ip, *v4conn, true)
					// TODO: should we listen?
					// listenICMPReply4(*v4conn)
				} else {
					log.Debug("Resolved IPv6 address: %s (host: %s)", ip.String(), h)
					sendICMP(ip, *v6conn, false)
					// TODO: should we listen?
					// listenICMPReply6(*v6conn)
				}
			}
		}
	}
}

func sendICMP(targetIP net.IP, conn icmp.PacketConn, is_v4 bool) {
	// TODO: increment sequence number per-client?
	seq := 1
	if *f_icmp_ran_seq {
		seq = rand.Intn(65000)
	}

	var m_type icmp.Type
	if is_v4 {
		m_type = ipv4.ICMPTypeEcho
	} else {
		m_type = ipv6.ICMPTypeEchoRequest
	}

	wm := icmp.Message{
		Type: m_type,
		Code: 0,
		Body: &icmp.Echo{
			ID:   rand.Intn(65000),
			Seq:  seq,
			Data: []byte("abcdefghijklmnopqrstuvwabcdefghi"), // This string is Window's ICMP behavior
		},
	}

	wb, err := wm.Marshal(nil)
	if err != nil {
		log.Fatalln(err)
	}

	var addr net.UDPAddr
	if is_v4 {
		addr = net.UDPAddr{IP: targetIP}
	} else {
		// TODO: figure out what interface name to use dynamically
		addr = net.UDPAddr{IP: targetIP, Zone: "eno1"}
	}

	log.Debug("sending icmp to %s", addr.String())
	if _, err := conn.WriteTo(wb, &addr); err != nil {
		log.Fatal("WriteTo failed for icmp to '%s': %s", addr.String(), err.Error())
	}

	icmpReportChan <- 1
}

// func sendICMP4(targetIP net.IP, c icmp.PacketConn) {
// 	// TODO: increment sequence number per-client?
// 	seq := 1
// 	if *f_icmp_ran_seq {
// 		seq = rand.Intn(65000)
// 	}

// 	wm := icmp.Message{
// 		Type: ipv4.ICMPTypeEcho,
// 		Code: 0,
// 		Body: &icmp.Echo{
// 			ID:   rand.Intn(65000),
// 			Seq:  seq,
// 			Data: []byte("abcdefghijklmnopqrstuvwabcdefghi"), // This string is Window's behavior
// 		},
// 	}

// 	wb, err := wm.Marshal(nil)
// 	if err != nil {
// 		log.Fatalln(err)
// 	}

// 	// addr := net.IPAddr{IP: targetIP}
// 	addr := net.UDPAddr{IP: targetIP}
// 	log.Debug("sending icmp4 to %s", addr.String())

// 	if _, err := c.WriteTo(wb, &addr); err != nil {
// 		log.Fatal("WriteTo err for icmp4 to %s: %s", addr.String(), err.Error())
// 	}

// 	icmpReportChan <- 1
// }

// func sendICMP6(targetIP net.IP, c icmp.PacketConn) {
// 	wm := icmp.Message{
// 		Type: ipv6.ICMPTypeEchoRequest,
// 		Code: 0,
// 		Body: &icmp.Echo{
// 			ID:   rand.Intn(65000),
// 			Seq:  1,                                          // TODO: randomize sequence num? make random behavior user-configurable?
// 			Data: []byte("abcdefghijklmnopqrstuvwabcdefghi"), // This string is Window's behavior
// 		},
// 	}

// 	wb, err := wm.Marshal(nil)
// 	if err != nil {
// 		log.Fatalln(err)
// 	}

// 	addr := net.UDPAddr{IP: targetIP, Zone: "eno1"}
// 	log.Debug("sending icmp6 to %s", addr.String())

// 	if _, err := c.WriteTo(wb, &addr); err != nil {
// 		log.Fatal("WriteTo err for icmp6 to %s: %s", addr.String(), err.Error())
// 	}

// 	icmpReportChan <- 1
// }

// func listenICMPReply4(c icmp.PacketConn) {
// 	rb := make([]byte, 1500)
// 	n, peer, err := c.ReadFrom(rb)
// 	if err != nil {
// 		log.Fatalln(err)
// 	}

// 	rm, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), rb[:n])
// 	if err != nil {
// 		log.Fatalln(err)
// 	}

// 	switch rm.Type {
// 	case ipv4.ICMPTypeEchoReply:
// 		log.Debug("got reflection from %v", peer)
// 	case ipv4.ICMPTypeDestinationUnreachable:
// 		log.Warn("got destination unreachable from %v", peer)
// 	default:
// 		log.Debug("got %+v; want echo reply", rm)
// 	}
// }

// func listenICMPReply6(c icmp.PacketConn) {
// 	rb := make([]byte, 1500)
// 	n, peer, err := c.ReadFrom(rb)
// 	if err != nil {
// 		log.Fatalln(err)
// 	}

// 	rm, err := icmp.ParseMessage(ipv6.ICMPTypeEchoReply.Protocol(), rb[:n])
// 	if err != nil {
// 		log.Fatalln(err)
// 	}

// 	switch rm.Type {
// 	case ipv6.ICMPTypeEchoReply:
// 		log.Debug("got reflection from %v", peer)
// 	case ipv6.ICMPTypeDestinationUnreachable:
// 		log.Warn("got destination unreachable from %v", peer)
// 	default:
// 		log.Debug("got %+v; want echo reply", rm)
// 	}
// }
