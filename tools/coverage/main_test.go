package main

import (
	"os"
	"testing"
)

func TestParseProfile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "profile")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("mode: atomic\nexample/a.go:1.1,2.2 3 1\nexample/b.go:3.1,4.2 2 0\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	covered, total, err := parseProfile(f)
	if closeErr := f.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	if covered != 3 || total != 5 {
		t.Fatalf("got %d/%d, want 3/5", covered, total)
	}
}

func TestParseProfileRejectsMalformed(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "profile")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("not a profile\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	_, _, parseErr := parseProfile(f)
	if closeErr := f.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if parseErr == nil {
		t.Fatal("expected error")
	}
}
