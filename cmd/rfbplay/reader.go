// Copyright 2015-2023 National Technology & Engineering Solutions of Sandia, LLC (NTESS).
// Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains certain
// rights in this software.

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type RecordingReader struct {
	reader *bufio.Reader
	buf    bytes.Buffer
	err    error
	offset int64
}

func NewRecordingReader(r *bufio.Reader) *RecordingReader {
	return &RecordingReader{reader: r}
}

func (r *RecordingReader) Offset() int64 {
	return r.offset
}

func (r *RecordingReader) readChunk() error {
	line, isPrefix, err := r.reader.ReadLine()
	if err != nil {
		return err
	}

	if isPrefix {
		return errors.New("malformed chunk header line (too long)")
	}

	parts := strings.Split(string(line), " ")
	if len(parts) != 2 {
		return errors.New("malformed chunk header line (not two parts)")
	}

	r.offset, err = strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return errors.New("malformed chunk header line (non-integer offset)")
	}

	n, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return errors.New("malformed chunk header line (non-integer length)")
	}

	written, err := io.CopyN(&r.buf, r.reader, int64(n))
	if err != nil {
		return err
	}

	if written != n {
		return fmt.Errorf("malformed chunk: wrote %d/%d bytes", written, n)
	}

	// Read the trailing "\r\n"
	c, err := r.reader.ReadByte()
	if err != nil || c != 0x0d {
		return fmt.Errorf("malformed chunk: missing `\\r`")
	}
	c, err = r.reader.ReadByte()
	if err != nil || c != 0x0a {
		return fmt.Errorf("malformed chunk: missing `\\n`")
	}

	return nil
}

// Read reads the data of the chunks. At the end of the file, or after an
// error, it returns the bytes that are left before it returns the error.
func (r *RecordingReader) Read(dst []byte) (int, error) {
	if len(dst) > r.buf.Len() && r.err == nil {
		r.err = r.readChunk()
		for r.err == nil && r.buf.Len() == 0 {
			r.err = r.readChunk()
		}
	}

	if r.buf.Len() > 0 || len(dst) == 0 {
		n, _ := r.buf.Read(dst)
		return n, nil
	}

	return 0, r.err
}
