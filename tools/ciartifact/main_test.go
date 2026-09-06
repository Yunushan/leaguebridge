package main

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Yunushan/leaguebridge/internal/nativepackage"
	"github.com/Yunushan/leaguebridge/internal/packageinfo"
)

func TestTransportRoundTripPreservesNativePackageVerification(t *testing.T) {
	// These are the same byte/mode contracts consumed by the production package
	// verifier. Losing executable permissions during ZIP transport used to make
	// that verifier reject otherwise valid signed artifacts.
	input := t.TempDir()
	members, err := inventory("package", "linux", "amd64", "debian")
	if err != nil {
		t.Fatal(err)
	}
	fixture(t, input, members)
	names, err := packageinfo.ExpectedPayloadNames("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	bodies := make(map[string][]byte)
	for _, name := range names {
		bodies[name] = []byte("transport fixture " + name)
	}
	source, err := packageinfo.Build("v0.0.0-ci", "linux", "amd64", 1787702400, strings.Repeat("0", 40), strings.Repeat("1", 40), "go1.27.1", bodies)
	if err != nil {
		t.Fatal(err)
	}
	sourceData, err := packageinfo.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	staging, err := nativepackage.Build(source, sourceData, strings.Repeat("a", 64), nativepackage.FamilyDebian)
	if err != nil {
		t.Fatal(err)
	}
	stagingData, err := nativepackage.Marshal(staging)
	if err != nil {
		t.Fatal(err)
	}
	stagingDir := filepath.Join(input, "native-package-staging", "debian")
	write(t, filepath.Join(stagingDir, nativepackage.StagingManifestName), stagingData, 0644)
	for _, item := range staging.Payload {
		body := sourceData
		if item.SourcePath != "PACKAGE-MANIFEST.json" {
			body = bodies[item.SourcePath]
		}
		mode := os.FileMode(0644)
		if item.Mode == "0755" {
			mode = 0755
		}
		write(t, filepath.Join(stagingDir, "root", filepath.FromSlash(strings.TrimPrefix(item.InstallPath, "/"))), body, mode)
	}
	archive := filepath.Join(t.TempDir(), "transport.tar")
	if err := pack(input, archive, members); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(archive, 0644); err != nil {
		t.Fatal(err)
	} // GitHub ZIP download mode.
	output := filepath.Join(t.TempDir(), "restored")
	if err := restore(archive, output, members); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(filepath.Join(output, "native-package-staging", "debian"))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := nativepackage.VerifyStagingRoot(root); err != nil {
		t.Fatalf("transport broke native package verification: %v", err)
	}
	// Reproduction control: raw ZIP transport loses executable bits and fails.
	if runtime.GOOS != "windows" {
		if err := os.Chmod(filepath.Join(output, "native-package-staging", "debian", "root", "usr", "bin", "leaguebridge"), 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := nativepackage.VerifyStagingRoot(root); err == nil {
			t.Fatal("raw transport control should fail after losing executable bits")
		}
	}
}

func TestEveryCITargetRoundTripsWithExecutableModes(t *testing.T) {
	for _, goos := range []string{"linux", "freebsd", "openbsd", "netbsd", "dragonfly"} {
		for _, arch := range []string{"amd64", "arm64"} {
			if goos == "dragonfly" && arch == "arm64" {
				continue
			}
			t.Run(goos+"/"+arch, func(t *testing.T) {
				members, err := inventory("runtime", goos, arch, "")
				if err != nil {
					t.Fatal(err)
				}
				input := t.TempDir()
				fixture(t, input, members)
				archive := filepath.Join(t.TempDir(), "transport.tar")
				if err := pack(input, archive, members); err != nil {
					t.Fatal(err)
				}
				output := filepath.Join(t.TempDir(), "restored")
				if err := restore(archive, output, members); err != nil {
					t.Fatal(err)
				}
				for _, item := range members {
					actual, err := os.ReadFile(filepath.Join(output, filepath.FromSlash(item.name)))
					if err != nil || string(actual) != "fixture "+item.name {
						t.Fatalf("member bytes: %s: %v", item.name, err)
					}
					info, err := os.Stat(filepath.Join(output, filepath.FromSlash(item.name)))
					if err != nil {
						t.Fatal(err)
					}
					if runtime.GOOS != "windows" && int64(info.Mode().Perm()) != item.mode {
						t.Fatalf("%s mode=%04o want=%04o", item.name, info.Mode().Perm(), item.mode)
					}
				}
				if err := restore(archive, output, members); err == nil {
					t.Fatal("restore overwrote an existing directory")
				}
			})
		}
	}
}

func TestPackageInventoryMatchesEveryPublishedCIArtifactPath(t *testing.T) {
	workflow, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range [][3]string{
		{"linux", "amd64", "debian"}, {"linux", "amd64", "rpm"},
		{"freebsd", "amd64", "freebsd-pkg"}, {"freebsd", "arm64", "freebsd-pkg"},
		{"openbsd", "amd64", "openbsd-pkg"}, {"openbsd", "arm64", "openbsd-pkg"},
		{"netbsd", "amd64", "pkgsrc"}, {"netbsd", "arm64", "pkgsrc"},
		{"dragonfly", "amd64", "dports"},
	} {
		t.Run(strings.Join(target[:], "/"), func(t *testing.T) {
			members, err := inventory("package", target[0], target[1], target[2])
			if err != nil {
				t.Fatal(err)
			}
			if len(members) != 11 {
				t.Fatalf("package transport inventory has %d members, want 11", len(members))
			}
			for _, item := range members {
				if strings.HasPrefix(item.name, "native-package-output/") && !strings.Contains(string(workflow), filepath.Base(item.name)) {
					t.Fatalf("transport filename %s differs from the workflow's actual package artifact", item.name)
				}
			}
			input := t.TempDir()
			fixture(t, input, members)
			archive := filepath.Join(t.TempDir(), "package.tar")
			if err := pack(input, archive, members); err != nil {
				t.Fatal(err)
			}
			if err := restore(archive, filepath.Join(t.TempDir(), "restored"), members); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRestoreRejectsMaliciousOrIncompleteArchiveBeforeWriting(t *testing.T) {
	members, _ := inventory("runtime", "linux", "amd64", "")
	bodies := make(map[string][]byte)
	for _, item := range members {
		bodies[item.name] = []byte("fixture")
	}
	canonical, err := encode(members, bodies)
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(edit func(*tar.Header)) []byte {
		var out bytes.Buffer
		w := tar.NewWriter(&out)
		r := tar.NewReader(bytes.NewReader(canonical))
		first := true
		for {
			h, err := r.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			if first {
				edit(h)
				first = false
			}
			if h.Typeflag != tar.TypeReg {
				body = nil
				h.Size = 0
			}
			if err := w.WriteHeader(h); err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(body); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return out.Bytes()
	}
	tests := map[string][]byte{
		"parent traversal":     mutate(func(h *tar.Header) { h.Name = "../escape" }),
		"absolute path":        mutate(func(h *tar.Header) { h.Name = "/escape" }),
		"symlink":              mutate(func(h *tar.Header) { h.Typeflag = tar.TypeSymlink; h.Linkname = "/tmp" }),
		"hardlink":             mutate(func(h *tar.Header) { h.Typeflag = tar.TypeLink; h.Linkname = "/tmp/escape" }),
		"FIFO":                 mutate(func(h *tar.Header) { h.Typeflag = tar.TypeFifo }),
		"lost executable mode": mutate(func(h *tar.Header) { h.Mode = 0644 }),
		"owner metadata":       mutate(func(h *tar.Header) { h.Uid = 1234 }),
		"duplicate member":     mutate(func(h *tar.Header) { h.Name = members[1].name }),
		"missing member":       canonical[:512],
		"trailing data":        append(bytes.Clone(canonical), []byte("hidden")...),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			archive := filepath.Join(dir, "input.tar")
			write(t, archive, data, 0644)
			output := filepath.Join(dir, "restored")
			if err := restore(archive, output, members); err == nil {
				t.Fatal("unsafe archive accepted")
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("failed validation published output: %v", err)
			}
		})
	}
	oversized := bytes.Clone(canonical)
	// Header-only declared size is rejected before allocating/reading its body.
	var declared bytes.Buffer
	w := tar.NewWriter(&declared)
	if err := w.WriteHeader(&tar.Header{Name: members[0].name, Mode: members[0].mode, Typeflag: tar.TypeReg, Size: members[0].limit + 1}); err != nil {
		t.Fatal(err)
	}
	oversized = declared.Bytes()
	if _, err := decode(oversized, members); err == nil {
		t.Fatal("oversized declaration accepted")
	}
}

func TestPackRejectsMissingOrSymlinkedInputAndExistingOutput(t *testing.T) {
	members, _ := inventory("runtime", "linux", "amd64", "")
	input := t.TempDir()
	fixture(t, input, members)
	archive := filepath.Join(t.TempDir(), "transport.tar")
	write(t, archive, []byte("keep"), 0644)
	if err := pack(input, archive, members); err == nil {
		t.Fatal("pack overwrote output")
	}
	got, _ := os.ReadFile(archive)
	if string(got) != "keep" {
		t.Fatal("output changed")
	}
	first := filepath.Join(input, filepath.FromSlash(members[0].name))
	if err := os.Remove(first); err != nil {
		t.Fatal(err)
	}
	if err := pack(input, filepath.Join(t.TempDir(), "new.tar"), members); err == nil {
		t.Fatal("missing input accepted")
	}
	outside := filepath.Join(t.TempDir(), "outside")
	write(t, outside, []byte("outside"), 0755)
	if err := os.Symlink(outside, first); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := pack(input, filepath.Join(t.TempDir(), "new.tar"), members); err == nil {
		t.Fatal("symlink input accepted")
	}
}

func TestInventoryRejectsUnsupportedCombinations(t *testing.T) {
	for _, tc := range [][4]string{{"other", "linux", "amd64", ""}, {"runtime", "windows", "amd64", ""}, {"runtime", "dragonfly", "arm64", ""}, {"runtime", "linux", "amd64", "debian"}, {"package", "linux", "arm64", "debian"}, {"package", "freebsd", "amd64", "debian"}} {
		if _, err := inventory(tc[0], tc[1], tc[2], tc[3]); err == nil {
			t.Errorf("invalid inventory accepted: %v", tc)
		}
	}
}

func fixture(t *testing.T, root string, members []member) {
	t.Helper()
	for _, item := range members {
		write(t, filepath.Join(root, filepath.FromSlash(item.name)), []byte("fixture "+item.name), os.FileMode(item.mode))
	}
}
func write(t *testing.T, name string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, mode); err != nil {
		t.Fatal(err)
	}
}
