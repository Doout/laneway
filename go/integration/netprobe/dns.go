package main

import (
	"flag"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func dnsProbe(args []string) error {
	fs := flag.NewFlagSet("dns", flag.ContinueOnError)
	address := fs.String("address", "127.0.0.1:5354", "loopback resolver")
	name := fs.String("name", "", "fully qualified question name")
	qtype := fs.String("type", "A", "A or AAAA")
	answer := fs.String("answer", "", "expected address for a successful lookup")
	code := fs.Uint("rcode", 0, "expected DNS response code")
	if err := fs.Parse(args); err != nil {
		return err
	}
	endpoint, err := netip.ParseAddrPort(*address)
	if err != nil || !endpoint.Addr().IsLoopback() || endpoint.Port() == 0 || *name == "" || *code > 15 || fs.NArg() != 0 {
		return fmt.Errorf("dns requires a loopback resolver, a name and an expected response")
	}
	qname, err := dnsmessage.NewName(strings.TrimSuffix(*name, ".") + ".")
	if err != nil {
		return err
	}
	typ := dnsmessage.TypeA
	switch *qtype {
	case "A":
	case "AAAA":
		typ = dnsmessage.TypeAAAA
	default:
		return fmt.Errorf("unsupported DNS query type %q", *qtype)
	}
	q := dnsmessage.Question{Name: qname, Type: typ, Class: dnsmessage.ClassINET}
	request := dnsmessage.Message{Header: dnsmessage.Header{ID: 18455, RecursionDesired: true}, Questions: []dnsmessage.Question{q}}
	packet, err := request.Pack()
	if err != nil {
		return err
	}
	c, err := net.DialTimeout("udp", endpoint.String(), time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	if err = c.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		return err
	}
	if _, err := c.Write(packet); err != nil {
		return err
	}
	buf := make([]byte, 513)
	n, err := c.Read(buf)
	if err != nil {
		return err
	}
	var reply dnsmessage.Message
	if n > 512 || reply.Unpack(buf[:n]) != nil || !reply.Response || reply.ID != request.ID || reply.RecursionAvailable || len(reply.Questions) != 1 || reply.Questions[0] != q {
		return fmt.Errorf("invalid private DNS reply")
	}
	if uint(reply.RCode) != *code || (reply.RCode == dnsmessage.RCodeSuccess && !reply.Authoritative) {
		return fmt.Errorf("private DNS reply code=%d authoritative=%t, expected code=%d", reply.RCode, reply.Authoritative, *code)
	}
	if *answer == "" && len(reply.Answers) == 0 {
		return nil
	}
	if *answer == "" || len(reply.Answers) != 1 {
		return fmt.Errorf("unexpected private DNS answer count: %d", len(reply.Answers))
	}
	resource := reply.Answers[0]
	var ip netip.Addr
	switch p := resource.Body.(type) {
	case *dnsmessage.AResource:
		ip = netip.AddrFrom4(p.A)
	case *dnsmessage.AAAAResource:
		ip = netip.AddrFrom16(p.AAAA)
	}
	if resource.Header.TTL > 5 || resource.Header.Type != typ || resource.Header.Name != qname || ip.String() != *answer {
		return fmt.Errorf("unexpected private DNS answer: %s (TTL %d)", ip, resource.Header.TTL)
	}
	return nil
}
