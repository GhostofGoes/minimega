// Copyright 2026 National Technology & Engineering Solutions of Sandia, LLC (NTESS).
// Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains certain
// rights in this software.

package main

import (
	"bytes"
	"strings"
	"testing"
	"text/template"

	"github.com/sandia-minimega/minimega/v2/pkg/minicli"
)

func TestDnsmasqCustom(t *testing.T) {
	defer func() {
		dnsmasqData = &Dnsmasq{DHCP: map[string]*Dhcp{}, DNS: map[string][]string{}, RAD: map[string]bool{}}
	}()

	// lines as minimega's router writeConfig quotes them
	for _, cmd := range []string{
		"dnsmasq flush",
		`dnsmasq custom "address=/test.com/1.0.0.1"`,
		`dnsmasq custom "txt-record=a.live,\"x # y \\ z\""`,
	} {
		r, err := minicli.ProcessString(cmd, false)
		if err != nil {
			t.Fatalf("%v: %v", cmd, err)
		}
		for range r {
		}
	}

	want := []string{"address=/test.com/1.0.0.1", `txt-record=a.live,"x # y \ z"`}
	if strings.Join(dnsmasqData.Custom, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got %q, want %q", dnsmasqData.Custom, want)
	}

	var b bytes.Buffer
	if err := template.Must(template.New("dnsmasq").Parse(dnsmasqTmpl)).Execute(&b, dnsmasqData); err != nil {
		t.Fatal(err)
	}
	for _, line := range want {
		if !strings.Contains(b.String(), "\n"+line+"\n") {
			t.Errorf("config missing %q:\n%s", line, b.String())
		}
	}

	r, _ := minicli.ProcessString("dnsmasq flush", false)
	for range r {
	}
	if len(dnsmasqData.Custom) != 0 {
		t.Errorf("flush kept custom lines: %q", dnsmasqData.Custom)
	}
}

func TestDnsmasqTemplateRelay(t *testing.T) {
	data := &Dnsmasq{
		DHCP: map[string]*Dhcp{
			"10.0.1.1": {Addr: "10.0.1.1", Relay: []string{"10.0.0.2", "10.0.0.3"}, Static: map[string]string{}},
			"10.0.2.1": {Addr: "10.0.2.1", Low: "10.0.2.100", High: "10.0.2.200", Netmask: "255.255.255.0", Static: map[string]string{}},
			"10.0.3.1": {Addr: "10.0.3.1", Netmask: "255.255.255.0", Static: map[string]string{"00:11:22:33:44:55": "10.0.3.10"}},
			"10.0.4.1": {Addr: "10.0.4.1", Low: "10.0.4.100", High: "10.0.4.200", Static: map[string]string{}},
		},
		DNS: map[string][]string{},
		RAD: map[string]bool{},
	}

	var b bytes.Buffer
	if err := template.Must(template.New("dnsmasq").Parse(dnsmasqTmpl)).Execute(&b, data); err != nil {
		t.Fatal(err)
	}
	got := b.String()

	for _, want := range []string{
		"dhcp-relay=10.0.1.1,10.0.0.2\n",
		"dhcp-relay=10.0.1.1,10.0.0.3\n",
		"dhcp-range=set:10.0.2.1,10.0.2.100,10.0.2.200,255.255.255.0\n",
		"dhcp-range=set:10.0.3.1,10.0.3.1,static,255.255.255.0\n",
		"dhcp-range=set:10.0.4.1,10.0.4.100,10.0.4.200\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("config missing %q:\n%s", want, got)
		}
	}
	// a relayed address must not also be served
	if strings.Contains(got, "set:10.0.1.1") {
		t.Errorf("relayed address also has a DHCP range:\n%s", got)
	}
}
