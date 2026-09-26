package productionpackage

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

type bsdFixtureEntry struct {
	name string
	data []byte
	mode int64
	kind byte
}

func bsdFixturePayload() []bsdFixtureEntry {
	return []bsdFixtureEntry{
		{"bin/leaguebridge", []byte("executable"), 0o755, tar.TypeReg},
		{"libexec/leaguebridge/linux-bsd-client-smoke.sh", []byte("client"), 0o755, tar.TypeReg},
		{"libexec/leaguebridge/linux-bsd-remote-session.sh", []byte("remote"), 0o755, tar.TypeReg},
		{"share/doc/leaguebridge/LICENSE", []byte("license"), 0o644, tar.TypeReg},
		{"share/doc/leaguebridge/README.md", []byte("readme"), 0o644, tar.TypeReg},
		{"share/doc/leaguebridge/SBOM.spdx.json", []byte("sbom"), 0o644, tar.TypeReg},
		{"share/doc/leaguebridge/PACKAGE-MANIFEST.json", []byte("manifest"), 0o644, tar.TypeReg},
	}
}

func bsdFixtureTar(t *testing.T, entries []bsdFixtureEntry, goos string) []byte {
	t.Helper()
	var raw bytes.Buffer
	writer := tar.NewWriter(&raw)
	for _, entry := range entries {
		kind := entry.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		header := &tar.Header{Name: entry.name, Mode: entry.mode, Size: int64(len(entry.data)), Typeflag: kind,
			Uname: "root", Gname: "wheel"}
		if goos == "freebsd" {
			header.Uid, header.Gid = 65534, 65534
		}
		if goos == "openbsd" && !strings.HasPrefix(entry.name, "+") && kind == tar.TypeReg {
			header.Mode |= 0o100000
		}
		if goos == "netbsd" && entry.name == "+CONTENTS" {
			header.PAXRecords = map[string]string{"hdrcharset": "BINARY"}
		}
		if kind == tar.TypeSymlink {
			header.Size = 0
			header.Linkname = "/tmp/forbidden"
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if kind != tar.TypeSymlink {
			if _, err := writer.Write(entry.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if goos == "freebsd" || goos == "dragonfly" {
		command := exec.Command("/usr/bin/xz", "-zc")
		command.Stdin = bytes.NewReader(raw.Bytes())
		output, err := command.Output()
		if err != nil {
			t.Fatal(err)
		}
		return output
	}
	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)
	if _, err := gzipWriter.Write(raw.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func bsdFixtureFreeBSD(t *testing.T, goos, arch string, mutate func(map[string]any, *[]bsdFixtureEntry)) []byte {
	t.Helper()
	payload := bsdFixturePayload()
	files := make(map[string]map[string]string)
	for _, entry := range payload {
		files["/usr/local/"+entry.name] = map[string]string{
			"sum": "3$" + strings.Repeat("a", 52), "uname": "root", "gname": "wheel", "perm": fmt.Sprintf("%04o", entry.mode),
		}
	}
	platform := "FreeBSD"
	if goos == "dragonfly" {
		platform = "DragonFly"
	}
	manifest := map[string]any{
		"name": "leaguebridge", "version": "1.2.3", "arch": platform + ":15:" + arch,
		"prefix": "/usr/local", "origin": "sysutils/leaguebridge", "files": files,
		"directories": map[string]map[string]string{
			"/usr/local/libexec/leaguebridge":   {"uname": "root", "gname": "wheel", "perm": "0755"},
			"/usr/local/share/doc/leaguebridge": {"uname": "root", "gname": "wheel", "perm": "0755"},
		},
	}
	if mutate != nil {
		mutate(manifest, &payload)
	}
	manifestData, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	compactData, err := json.Marshal(map[string]any{"name": manifest["name"], "version": manifest["version"], "arch": manifest["arch"]})
	if err != nil {
		t.Fatal(err)
	}
	entries := []bsdFixtureEntry{
		{"+COMPACT_MANIFEST", compactData, 0o644, tar.TypeReg},
		{"+MANIFEST", manifestData, 0o644, tar.TypeReg},
	}
	for _, item := range payload {
		item.name = "/usr/local/" + item.name
		entries = append(entries, item)
	}
	entries = append(entries,
		bsdFixtureEntry{"/usr/local/libexec/leaguebridge", nil, 0o755, tar.TypeDir},
		bsdFixtureEntry{"/usr/local/share/doc/leaguebridge", nil, 0o755, tar.TypeDir},
	)
	return bsdFixtureTar(t, entries, goos)
}

func bsdFixturePacking(t *testing.T, goos string, mutate func(*string, *[]bsdFixtureEntry)) []byte {
	t.Helper()
	payload := bsdFixturePayload()
	lines := []string{}
	if goos == "openbsd" {
		lines = append(lines, "@name leaguebridge-1.2.3-openbsd-amd64", "@arch amd64", "@owner root", "@group wheel")
	} else {
		lines = append(lines, "@name leaguebridge-1.2.3", "@owner root", "@group wheel")
	}
	lines = append(lines, "@cwd /usr/local")
	lastMode := int64(-1)
	for _, entry := range payload {
		if entry.mode != lastMode {
			lines = append(lines, "@mode "+fmt.Sprintf("%04o", entry.mode))
			lastMode = entry.mode
		}
		lines = append(lines, entry.name)
		if goos == "openbsd" {
			hash := sha256.Sum256(entry.data)
			lines = append(lines, "@sha "+base64.StdEncoding.EncodeToString(hash[:]))
			lines = append(lines, "@size "+fmt.Sprint(len(entry.data)))
			lines = append(lines, "@ts 1720000000")
		}
	}
	packing := strings.Join(lines, "\n") + "\n"
	if mutate != nil {
		mutate(&packing, &payload)
	}
	entries := []bsdFixtureEntry{{"+CONTENTS", []byte(packing), 0o644, tar.TypeReg}}
	if goos == "netbsd" {
		entries = append(entries,
			bsdFixtureEntry{"+COMMENT", []byte("LeagueBridge remote handoff controller\n"), 0o644, tar.TypeReg},
			bsdFixtureEntry{"+DESC", []byte("A bounded, read-only compatibility and remote handoff controller.\n"), 0o644, tar.TypeReg},
			bsdFixtureEntry{"+BUILD_INFO", []byte("OPSYS=NetBSD\nOS_VERSION=11.0\nMACHINE_ARCH=x86_64\nPKGTOOLS_VERSION=20260227\n"), 0o644, tar.TypeReg},
		)
	} else {
		entries = append(entries, bsdFixtureEntry{"+DESC", []byte("A bounded, read-only compatibility and remote handoff controller.\n"), 0o644, tar.TypeReg})
	}
	entries = append(entries, payload...)
	return bsdFixtureTar(t, entries, goos)
}

func TestInspectBSDPackageFormats(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		data    []byte
		inspect func(context.Context, []byte) (inspectedPackage, error)
		arch    string
	}{
		{"freebsd-amd64", bsdFixtureFreeBSD(t, "freebsd", "x86:64", nil), func(ctx context.Context, data []byte) (inspectedPackage, error) {
			return inspectFreeBSDPkg(ctx, data, "freebsd")
		}, "amd64"},
		{"freebsd-arm64", bsdFixtureFreeBSD(t, "freebsd", "aarch64:64", nil), func(ctx context.Context, data []byte) (inspectedPackage, error) {
			return inspectFreeBSDPkg(ctx, data, "freebsd")
		}, "aarch64"},
		{"dragonfly", bsdFixtureFreeBSD(t, "dragonfly", "x86:64", nil), func(ctx context.Context, data []byte) (inspectedPackage, error) {
			return inspectFreeBSDPkg(ctx, data, "dragonfly")
		}, "amd64"},
		{"openbsd", bsdFixturePacking(t, "openbsd", nil), inspectOpenBSDPkg, "amd64"},
		{"netbsd", bsdFixturePacking(t, "netbsd", nil), inspectNetBSDPkg, "amd64"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.inspect(ctx, test.data)
			if err != nil {
				t.Fatal(err)
			}
			if got.Name != "leaguebridge" || got.Version != "v1.2.3" || got.Architecture != test.arch || len(got.Files) != 7 {
				t.Fatalf("invalid inspected BSD package: %+v", got)
			}
			for _, file := range got.Files {
				if !strings.HasPrefix(file.Path, "/usr/local/") || file.Size <= 0 || len(file.SHA256) != 64 || (file.Mode != "0644" && file.Mode != "0755") {
					t.Fatalf("invalid inspected file: %+v", file)
				}
			}
		})
	}
}

func TestDragonFlyPkgAcceptsLegacyChecksumOnlyFiles(t *testing.T) {
	legacyFiles := func(mutatePath, mutateSum string) func(map[string]any, *[]bsdFixtureEntry) {
		return func(manifest map[string]any, _ *[]bsdFixtureEntry) {
			current := manifest["files"].(map[string]map[string]string)
			legacy := make(map[string]string, len(current))
			for installed, attrs := range current {
				legacy[installed] = attrs["sum"]
			}
			if mutatePath != "" {
				legacy[mutatePath] = mutateSum
			}
			manifest["files"] = legacy
		}
	}
	valid := bsdFixtureFreeBSD(t, "dragonfly", "x86:64", legacyFiles("", ""))
	got, err := inspectFreeBSDPkg(context.Background(), valid, "dragonfly")
	if err != nil || got.Architecture != "amd64" || len(got.Files) != 7 {
		t.Fatalf("legacy DragonFly package: %+v, %v", got, err)
	}
	invalid := bsdFixtureFreeBSD(t, "dragonfly", "x86:64", legacyFiles("/usr/local/bin/leaguebridge", "not:a:checksum"))
	if _, err := inspectFreeBSDPkg(context.Background(), invalid, "dragonfly"); err == nil {
		t.Fatal("malformed legacy DragonFly checksum was accepted")
	}
}

func TestBSDInspectorsAcceptReviewedCIPreReleaseVersion(t *testing.T) {
	freeBSD := bsdFixtureFreeBSD(t, "freebsd", "amd64", func(manifest map[string]any, _ *[]bsdFixtureEntry) {
		manifest["version"] = "0.0.0-ci"
	})
	openBSD := bsdFixturePacking(t, "openbsd", func(packing *string, _ *[]bsdFixtureEntry) {
		*packing = strings.ReplaceAll(*packing, "1.2.3", "0.0.0-ci")
	})
	netBSD := bsdFixturePacking(t, "netbsd", func(packing *string, _ *[]bsdFixtureEntry) {
		*packing = strings.ReplaceAll(*packing, "1.2.3", "0.0.0-ci")
	})
	for _, test := range []struct {
		name    string
		data    []byte
		inspect func(context.Context, []byte) (inspectedPackage, error)
	}{
		{"freebsd", freeBSD, func(ctx context.Context, data []byte) (inspectedPackage, error) {
			return inspectFreeBSDPkg(ctx, data, "freebsd")
		}},
		{"openbsd", openBSD, inspectOpenBSDPkg},
		{"netbsd", netBSD, inspectNetBSDPkg},
	} {
		value, err := test.inspect(context.Background(), test.data)
		if err != nil || value.Version != "v0.0.0-ci" {
			t.Fatalf("%s CI version = %q, %v", test.name, value.Version, err)
		}
	}
}

func TestBSDPackingListAllowsRepeatedFixedInstallRoot(t *testing.T) {
	packageData := bsdFixturePacking(t, "openbsd", func(packing *string, _ *[]bsdFixtureEntry) {
		*packing = strings.Replace(*packing, "@mode 0755\n", "@cwd /usr/local\n@mode 0755\n", 1)
	})
	if _, err := inspectOpenBSDPkg(context.Background(), packageData); err != nil {
		t.Fatalf("repeated fixed install root was rejected: %v", err)
	}
}

func TestOpenBSDPackingListUsesVerifiedArchiveModesWhenUnspecified(t *testing.T) {
	packageData := bsdFixturePacking(t, "openbsd", func(packing *string, _ *[]bsdFixtureEntry) {
		*packing = strings.ReplaceAll(*packing, "@mode 0755\n", "")
		*packing = strings.ReplaceAll(*packing, "@mode 0644\n", "")
	})
	if _, err := inspectOpenBSDPkg(context.Background(), packageData); err != nil {
		t.Fatalf("OpenBSD archive modes were rejected without packing-list modes: %v", err)
	}
}

func TestInspectBSDPackagesRejectInstallSideEffectsAndInventoryChanges(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		data    []byte
		inspect func(context.Context, []byte) (inspectedPackage, error)
	}{
		{"pkg-script", bsdFixtureFreeBSD(t, "freebsd", "amd64", func(m map[string]any, _ *[]bsdFixtureEntry) {
			m["scripts"] = map[string]string{"post-install": "touch /tmp/unsafe"}
		}), func(ctx context.Context, data []byte) (inspectedPackage, error) {
			return inspectFreeBSDPkg(ctx, data, "freebsd")
		}},
		{"pkg-empty-script-map", bsdFixtureFreeBSD(t, "freebsd", "amd64", func(m map[string]any, _ *[]bsdFixtureEntry) {
			m["scripts"] = map[string]string{}
		}), func(ctx context.Context, data []byte) (inspectedPackage, error) {
			return inspectFreeBSDPkg(ctx, data, "freebsd")
		}},
		{"pkg-extra-file", bsdFixtureFreeBSD(t, "freebsd", "amd64", func(_ map[string]any, files *[]bsdFixtureEntry) {
			*files = append(*files, bsdFixtureEntry{"bin/extra", []byte("extra"), 0o755, tar.TypeReg})
		}), func(ctx context.Context, data []byte) (inspectedPackage, error) {
			return inspectFreeBSDPkg(ctx, data, "freebsd")
		}},
		{"pkg-wrong-os", bsdFixtureFreeBSD(t, "freebsd", "amd64", nil), func(ctx context.Context, data []byte) (inspectedPackage, error) {
			return inspectFreeBSDPkg(ctx, data, "dragonfly")
		}},
		{"pkg-symlink", bsdFixtureFreeBSD(t, "freebsd", "amd64", func(_ map[string]any, files *[]bsdFixtureEntry) { (*files)[0].kind = tar.TypeSymlink }), func(ctx context.Context, data []byte) (inspectedPackage, error) {
			return inspectFreeBSDPkg(ctx, data, "freebsd")
		}},
		{"pkg-unmatched-sha256", bsdFixtureFreeBSD(t, "freebsd", "amd64", func(manifest map[string]any, _ *[]bsdFixtureEntry) {
			files := manifest["files"].(map[string]map[string]string)
			files["/usr/local/bin/leaguebridge"]["sum"] = strings.Repeat("f", 64)
		}), func(ctx context.Context, data []byte) (inspectedPackage, error) {
			return inspectFreeBSDPkg(ctx, data, "freebsd")
		}},
		{"openbsd-exec", bsdFixturePacking(t, "openbsd", func(packing *string, _ *[]bsdFixtureEntry) { *packing += "@exec touch /tmp/unsafe\n" }), inspectOpenBSDPkg},
		{"openbsd-wrong-sha", bsdFixturePacking(t, "openbsd", func(_ *string, files *[]bsdFixtureEntry) { (*files)[0].data = []byte("changed") }), inspectOpenBSDPkg},
		{"netbsd-exec", bsdFixturePacking(t, "netbsd", func(packing *string, _ *[]bsdFixtureEntry) { *packing += "@exec touch /tmp/unsafe\n" }), inspectNetBSDPkg},
		{"netbsd-unlisted", bsdFixturePacking(t, "netbsd", func(_ *string, files *[]bsdFixtureEntry) {
			*files = append(*files, bsdFixtureEntry{"bin/extra", []byte("extra"), 0o755, tar.TypeReg})
		}), inspectNetBSDPkg},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.inspect(ctx, test.data)
			if err == nil || len(got.Files) != 0 {
				t.Fatalf("unsafe BSD package accepted: %+v", got)
			}
		})
	}
}

func TestBSDPackageInspectorsRejectCorruptAndCancelledSnapshots(t *testing.T) {
	good := bsdFixturePacking(t, "netbsd", nil)
	corrupt := append([]byte(nil), good...)
	corrupt[len(corrupt)-1] ^= 0xff
	if _, err := inspectNetBSDPkg(context.Background(), corrupt); err == nil {
		t.Fatal("corrupt gzip checksum was accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := inspectNetBSDPkg(ctx, good); err == nil {
		t.Fatal("cancelled inspection context was accepted")
	}
}

func TestBSDArchiveRejectsUnreviewedOwnershipAndExtendedMetadata(t *testing.T) {
	for _, test := range []struct {
		name, goos string
		modify     func(*tar.Header)
	}{
		{"nonroot-uid", "netbsd", func(header *tar.Header) { header.Uid = 1000 }},
		{"dragonfly-nonroot-uid", "dragonfly", func(header *tar.Header) { header.Uid = 1000 }},
		{"nonroot-uname", "netbsd", func(header *tar.Header) { header.Uname = "runner" }},
		{"nonwheel-gname", "netbsd", func(header *tar.Header) { header.Gname = "staff" }},
		{"xattr", "netbsd", func(header *tar.Header) { header.Xattrs = map[string]string{"user.hook": "value"} }},
		{"pax-unreviewed", "netbsd", func(header *tar.Header) { header.PAXRecords = map[string]string{"vendor.hook": "value"} }},
		{"pax-unknown-charset", "netbsd", func(header *tar.Header) { header.PAXRecords = map[string]string{"hdrcharset": "ASCII"} }},
		{"pax-charset-outside-netbsd", "openbsd", func(header *tar.Header) { header.PAXRecords = map[string]string{"hdrcharset": "BINARY"} }},
		{"openbsd-wrong-file-type-bits", "openbsd", func(header *tar.Header) { header.Mode = 0o40755 }},
		{"openbsd-setuid-file", "openbsd", func(header *tar.Header) { header.Mode = 0o104755 }},
		{"openbsd-control-type-bits", "openbsd", func(header *tar.Header) {
			header.Name = "+CONTENTS"
			header.Mode = 0o100644
		}},
		{"openbsd-dir-type-bits", "openbsd", func(header *tar.Header) {
			header.Typeflag = tar.TypeDir
			header.Mode = 0o40755
			header.Size = 0
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var raw bytes.Buffer
			writer := tar.NewWriter(&raw)
			header := &tar.Header{Name: "bin/leaguebridge", Mode: 0o755, Size: 4, Typeflag: tar.TypeReg,
				Format: tar.FormatPAX, Uname: "root", Gname: "wheel"}
			test.modify(header)
			if err := writer.WriteHeader(header); err != nil {
				t.Fatal(err)
			}
			if header.Typeflag != tar.TypeDir {
				if _, err := writer.Write([]byte("data")); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			var compressed []byte
			if test.goos == "dragonfly" {
				command := exec.Command("/usr/bin/xz", "-zc")
				command.Stdin = bytes.NewReader(raw.Bytes())
				var err error
				compressed, err = command.Output()
				if err != nil {
					t.Fatal(err)
				}
			} else {
				var buf bytes.Buffer
				gz := gzip.NewWriter(&buf)
				if _, err := gz.Write(raw.Bytes()); err != nil {
					t.Fatal(err)
				}
				if err := gz.Close(); err != nil {
					t.Fatal(err)
				}
				compressed = buf.Bytes()
			}
			if _, err := bsdArchive(context.Background(), compressed, test.goos); err == nil {
				t.Fatal("BSD archive with unreviewed owner or metadata was accepted")
			}
		})
	}
}
