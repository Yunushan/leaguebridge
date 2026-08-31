package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yunushan/leaguebridge/internal/readiness"
)

func TestReadRegularBoundedRejectsMissingOversizeAndDirectory(t *testing.T) {
	root := t.TempDir()
	if _, err := readRegularBounded(filepath.Join(root, "missing"), 10); err == nil {
		t.Fatal("missing scorecard unexpectedly succeeded")
	}
	path := filepath.Join(root, "scorecard.json")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularBounded(path, 4); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize error = %v", err)
	}
	if _, err := readRegularBounded(root, 100); err == nil || !strings.Contains(err.Error(), "regular") {
		t.Fatalf("directory error = %v", err)
	}
}

func TestReadRegularBoundedRejectsSymlinkedParent(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "scorecard.json"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if _, err := readRegularBounded(filepath.Join(link, "scorecard.json"), 100); err == nil || !strings.Contains(err.Error(), "parent") {
		t.Fatalf("symlinked parent error = %v", err)
	}
}

func TestVerifyRejectsMissingPublicScorecard(t *testing.T) {
	if err := verify(t.TempDir()); err == nil || !strings.Contains(err.Error(), "public readiness scorecard") {
		t.Fatalf("verify error = %v", err)
	}
}

func TestVerifyRejectsSemanticallyEquivalentReformattedScorecard(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "readiness")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	reformatted := append([]byte(" \n"), readiness.EmbeddedJSON()...)
	if err := os.WriteFile(filepath.Join(directory, "scorecard.json"), reformatted, 0o600); err != nil {
		t.Fatal(err)
	}
	err := verify(root)
	if err == nil || !strings.Contains(err.Error(), "byte-identical") {
		t.Fatalf("reformatted scorecard error = %v", err)
	}
}

func TestVerifyAcceptsCurrentRepository(t *testing.T) {
	if err := verify(filepath.Join("..", "..")); err != nil {
		t.Fatalf("current repository verification failed: %v", err)
	}
}
