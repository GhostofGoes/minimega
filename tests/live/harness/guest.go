// Copyright 2026 National Technology & Engineering Solutions of Sandia, LLC (NTESS).
// Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains certain
// rights in this software.

package harness

import (
	"encoding/binary"
	"regexp"
)

// This file holds guest-side data that the tests generate instead of storing
// binary files in the repository, and parsers for guest and QEMU output.

var qemuVersionRe = regexp.MustCompile(`\d+\.\d+\.\d+`)

// QemuVersion returns the first major.minor.micro version in s, or "".
// It accepts "QEMU emulator version 11.1.3 (...)", "v11.1.3", and "11.1.3".
func QemuVersion(s string) string {
	return qemuVersionRe.FindString(s)
}

// ArmBootMessage is the line that ArmBootImage writes to its serial port.
const ArmBootMessage = "MINIMEGA-ARM-OK\n"

// armBootCode is a bare-metal AArch64 program for the QEMU "virt" machine.
// QEMU loads a raw (non-ELF) kernel image at 0x40080000 and jumps to it at
// EL1 with the MMU off. The program enables the PL011 UART at 0x09000000,
// writes ArmBootMessage to it, waits, and repeats forever. A serial socket
// drops the output while no client is connected, so the repetition lets
// "vm serial" read the message at any time.
//
// Assembled with GNU as (binutils 2.40) and run under qemu-system-aarch64
// 11.1.3 (-M virt -cpu cortex-a57); see TestArmBootImage.
var armBootCode = []uint32{
	0xd2a12001, // 0x00:        movz x1, #0x0900, lsl #16  // x1 = 0x09000000, PL011 base
	0x52806022, // 0x04:        mov  w2, #0x301            // UARTEN | TXE | RXE
	0xb9003022, // 0x08:        str  w2, [x1, #0x30]       // UARTCR
	0x10000163, // 0x0c: loop:  adr  x3, msg               // msg = 0x38
	0x38401464, // 0x10: next:  ldrb w4, [x3], #1
	0x340000a4, // 0x14:        cbz  w4, delay             // delay = 0x28
	0xb9401825, // 0x18: wait:  ldr  w5, [x1, #0x18]       // UARTFR
	0x372fffe5, // 0x1c:        tbnz w5, #5, wait          // TXFF: transmit FIFO full
	0xb9000024, // 0x20:        str  w4, [x1]              // UARTDR
	0x17fffffb, // 0x24:        b    next
	0xd2a00206, // 0x28: delay: movz x6, #0x10, lsl #16    // x6 = 0x100000
	0xf10004c6, // 0x2c: spin:  subs x6, x6, #1
	0x54ffffe1, // 0x30:        b.ne spin
	0x17fffff6, // 0x34:        b    loop
	// 0x38: msg: .asciz ArmBootMessage
}

// ArmBootImage returns the raw image of armBootCode followed by the
// NUL-terminated ArmBootMessage, for "vm config kernel" of a bare-metal VM.
func ArmBootImage() []byte {
	b := make([]byte, 0, 4*len(armBootCode)+len(ArmBootMessage)+1)
	for _, w := range armBootCode {
		b = binary.LittleEndian.AppendUint32(b, w)
	}
	b = append(b, ArmBootMessage...)
	return append(b, 0)
}
