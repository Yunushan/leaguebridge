package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativePackageSmokeScriptsDelegateSemanticVersionValidation(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"native-package-linux-smoke.sh",
		"native-package-bsd-smoke.sh",
	} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(filepath.Join("..", "..", "scripts", name))
			if err != nil {
				t.Fatal(err)
			}
			script := string(data)
			prefixGuard := "case \"$version\" in\n  v*) ;;"
			if !strings.Contains(script, prefixGuard) {
				t.Fatalf("%s must keep the shell version guard limited to the v prefix", name)
			}
			if strings.Contains(script, "v[0-9]*.[0-9]*.[0-9]*)") {
				t.Fatalf("%s must not duplicate SemVer grammar in a shell glob", name)
			}
			checker := "versioncheck \"$version\""
			if !strings.Contains(script, checker) {
				t.Fatalf("%s must invoke the repository semantic-version checker", name)
			}
			if strings.Index(script, checker) < strings.Index(script, prefixGuard) {
				t.Fatalf("%s invokes the semantic-version checker before its prefix guard", name)
			}
		})
	}
}

func TestVerifyInstallDelegatesSemanticVersionValidation(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", "scripts", "verify-install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	prefixGuard := "case \"$expected_version\" in\n\tv*) ;;"
	if !strings.Contains(script, prefixGuard) {
		t.Fatal("verify-install.sh must keep the shell version guard limited to the v prefix")
	}
	if strings.Contains(script, "v[0-9]*.[0-9]*.[0-9]*)") {
		t.Fatal("verify-install.sh must not duplicate SemVer grammar in a shell glob")
	}
}
