// Copyright 2026 Ihor Dvoretskyi
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package ssh

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// TestBytesReaderReturnsIOEOF verifies that bytesReader signals end-of-stream
// with io.EOF (not a wrapped or custom error). The ssh package's stdin handling
// treats any non-io.EOF error as a transport failure, which caused uploads to
// abort with "EOF" before the agent binary was fully transferred.
func TestBytesReaderReturnsIOEOF(t *testing.T) {
	data := []byte("hello world")
	r := newBytesReader(data)

	// Drain all data.
	buf := make([]byte, len(data))
	n, err := r.Read(buf)
	if err != nil {
		t.Fatalf("first Read: unexpected error: %v", err)
	}
	if n != len(data) {
		t.Fatalf("first Read: got %d bytes, want %d", n, len(data))
	}
	if !bytes.Equal(buf, data) {
		t.Fatalf("first Read: content mismatch: got %q, want %q", buf, data)
	}

	// Next read must return exactly io.EOF.
	n2, err2 := r.Read(buf)
	if n2 != 0 {
		t.Errorf("read past EOF: expected 0 bytes, got %d", n2)
	}
	if !errors.Is(err2, io.EOF) {
		t.Errorf("read past EOF: expected io.EOF, got %v (type %T)", err2, err2)
	}
}

func TestBytesReaderEmptyData(t *testing.T) {
	r := newBytesReader([]byte{})
	buf := make([]byte, 10)
	n, err := r.Read(buf)
	if n != 0 {
		t.Errorf("empty reader: expected 0 bytes, got %d", n)
	}
	if !errors.Is(err, io.EOF) {
		t.Errorf("empty reader: expected io.EOF, got %v", err)
	}
}

func TestBytesReaderPartialReads(t *testing.T) {
	data := []byte("abcdefghij")
	r := newBytesReader(data)

	var got []byte
	buf := make([]byte, 3)
	for {
		n, err := r.Read(buf)
		got = append(got, buf[:n]...)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("unexpected error during partial reads: %v", err)
		}
	}

	if !bytes.Equal(got, data) {
		t.Errorf("partial reads: got %q, want %q", got, data)
	}
}

// TestBytesReaderCompatibleWithIOReadAll verifies that io.ReadAll (which
// standard library uses internally) works correctly with bytesReader, since
// io.ReadAll relies on io.EOF being the exact sentinel value.
func TestBytesReaderCompatibleWithIOReadAll(t *testing.T) {
	data := []byte("binary\x00data\xff here")
	r := newBytesReader(data)

	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("io.ReadAll: unexpected error: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("io.ReadAll: got %q, want %q", got, data)
	}
}
