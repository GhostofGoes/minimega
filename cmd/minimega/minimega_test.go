// Copyright 2026 National Technology & Engineering Solutions of Sandia, LLC (NTESS).
// Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains certain
// rights in this software.

package main

import (
	"strings"
	"testing"
)

func TestValidVMName(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	// three 63 character labels, one of 61 and three dots make 253 characters
	name253 := strings.Join([]string{label63, label63, label63, label63[:61]}, ".")

	valid := []string{
		"web1",
		"ab",
		"a0",
		"a.b",
		"1web",
		"Web-1",
		"web--1",
		"web1.example.com",
		"host.leaf-1.net",
		"10.0.0.1",
		label63,
		label63 + "." + label63,
		name253,
	}

	invalid := []string{
		"",
		"a",
		"0",
		"web_1",
		"web_server",
		"_web",
		"web_",
		"-web",
		"web-",
		"web.-lan",
		"web-.lan",
		".",
		"..",
		".web",
		"web.",
		"web..lan",
		"web 1",
		"web/1",
		"/web",
		"web/",
		`web\1`,
		`\web`,
		`web\`,
		"wéb",
		label63 + "a",
		"web." + label63 + "a",
		name253 + "a",
	}

	if len(name253) != 253 {
		t.Fatalf("test name has %v characters, want 253", len(name253))
	}

	for _, name := range valid {
		if err := validVMName(name); err != nil {
			t.Errorf("validVMName(%q) = %v, want nil", name, err)
		}
	}

	for _, name := range invalid {
		err := validVMName(name)
		if err == nil {
			t.Errorf("validVMName(%q) = nil, want error", name)
			continue
		}

		// the error must name the VM and tell the rule
		if !strings.Contains(err.Error(), "`"+name+"`") || !strings.Contains(err.Error(), "RFC 1123") {
			t.Errorf("validVMName(%q) error does not tell the name and the rule: %v", name, err)
		}
	}
}
