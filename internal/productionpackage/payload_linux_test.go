package productionpackage

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"testing"
)

func nativeTestTar(t *testing.T, entries []tar.Header, contents [][]byte) []byte {
	t.Helper()
	var raw bytes.Buffer
	w := tar.NewWriter(&raw)
	for i := range entries {
		if err := w.WriteHeader(&entries[i]); err != nil {
			t.Fatal(err)
		}
		if len(contents[i]) > 0 {
			if _, err := w.Write(contents[i]); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return raw.Bytes()
}

func nativeTestGzip(t *testing.T, raw []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	if _, err := w.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func nativeTestAr(members ...debMember) []byte {
	var out bytes.Buffer
	out.WriteString("!<arch>\n")
	for _, item := range members {
		fmt.Fprintf(&out, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", item.name, 0, 0, 0, "100644", len(item.data))
		out.Write(item.data)
		if len(item.data)%2 != 0 {
			out.WriteByte('\n')
		}
	}
	return out.Bytes()
}

func nativeTestDeb(t *testing.T, control, payload []byte) []byte {
	t.Helper()
	controlTar := nativeTestTar(t,
		[]tar.Header{{Name: "./", Typeflag: tar.TypeDir, Mode: 0o755}, {Name: "./control", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(control))}},
		[][]byte{nil, control})
	return nativeTestAr(
		debMember{"debian-binary", []byte("2.0\n")},
		debMember{"control.tar.gz", nativeTestGzip(t, controlTar)},
		debMember{"data.tar.gz", nativeTestGzip(t, payload)},
	)
}

const nativeDebControl = "Package: leaguebridge\nVersion: 1.2.3\nArchitecture: amd64\nMaintainer: LeagueBridge contributors\nDescription: Remote controller\n"

func nativeTestPayloadTar(t *testing.T) []byte {
	t.Helper()
	return nativeTestTar(t,
		[]tar.Header{
			{Name: "./", Typeflag: tar.TypeDir, Mode: 0o755},
			{Name: "./usr/", Typeflag: tar.TypeDir, Mode: 0o755},
			{Name: "./usr/bin/", Typeflag: tar.TypeDir, Mode: 0o755},
			{Name: "./usr/bin/leaguebridge", Typeflag: tar.TypeReg, Mode: 0o755, Size: 6},
		},
		[][]byte{nil, nil, nil, []byte("binary")},
	)
}

func TestInspectDebActualArchive(t *testing.T) {
	data := nativeTestDeb(t, []byte(nativeDebControl), nativeTestPayloadTar(t))
	got, err := inspectDeb(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	wantSHA := sha256.Sum256([]byte("binary"))
	if got.Name != "leaguebridge" || got.Version != "v1.2.3" || got.Architecture != "amd64" ||
		len(got.Files) != 1 || got.Files[0] != (inspectedFile{"/usr/bin/leaguebridge", "0755", 6, hex.EncodeToString(wantSHA[:])}) {
		t.Fatalf("unexpected Debian package observation: %+v", got)
	}
}

func TestInspectDebCIPrerelease(t *testing.T) {
	control := strings.Replace(nativeDebControl, "1.2.3", "0.0.0~ci", 1)
	got, err := inspectDeb(context.Background(), nativeTestDeb(t, []byte(control), nativeTestPayloadTar(t)))
	if err != nil || got.Version != "v0.0.0-ci" {
		t.Fatalf("CI Debian version normalization: %+v, %v", got, err)
	}
}

func TestInspectDebRejectsUnreviewedContent(t *testing.T) {
	valid := nativeTestPayloadTar(t)
	for _, tc := range []struct {
		name    string
		control string
		payload []byte
	}{
		{"invalid version", strings.Replace(nativeDebControl, "1.2.3", "1.2.3~", 1), valid},
		{"control dependency", nativeDebControl + "Depends: bash\n", valid},
		{"payload traversal", nativeDebControl, nativeTestTar(t, []tar.Header{{Name: "../evil", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1}}, [][]byte{[]byte("x")})},
		{"payload symlink", nativeDebControl, nativeTestTar(t, []tar.Header{{Name: "./usr/bin/leaguebridge", Typeflag: tar.TypeSymlink, Linkname: "/tmp/evil", Mode: 0o777}}, [][]byte{nil})},
		{"payload setuid", nativeDebControl, nativeTestTar(t, []tar.Header{{Name: "./usr/bin/leaguebridge", Typeflag: tar.TypeReg, Mode: 0o4755, Size: 1}}, [][]byte{[]byte("x")})},
		{"payload duplicate", nativeDebControl, nativeTestTar(t, []tar.Header{{Name: "./usr/bin/leaguebridge", Typeflag: tar.TypeReg, Mode: 0o755, Size: 1}, {Name: "./usr/bin/leaguebridge", Typeflag: tar.TypeReg, Mode: 0o755, Size: 1}}, [][]byte{[]byte("x"), []byte("y")})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := inspectDeb(context.Background(), nativeTestDeb(t, []byte(tc.control), tc.payload)); err == nil {
				t.Fatal("unsafe Debian package accepted")
			}
		})
	}
	controlTar := nativeTestTar(t,
		[]tar.Header{{Name: "./control", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(nativeDebControl))}, {Name: "./postinst", Typeflag: tar.TypeReg, Mode: 0o755, Size: 7}},
		[][]byte{[]byte(nativeDebControl), []byte("echo hi")},
	)
	withScript := nativeTestAr(debMember{"debian-binary", []byte("2.0\n")}, debMember{"control.tar.gz", nativeTestGzip(t, controlTar)}, debMember{"data.tar.gz", nativeTestGzip(t, valid)})
	if _, err := inspectDeb(context.Background(), withScript); err == nil {
		t.Fatal("Debian maintainer script accepted")
	}
	withExtra := nativeTestAr(debMember{"debian-binary", []byte("2.0\n")}, debMember{"control.tar.gz", nativeTestGzip(t, controlTar)}, debMember{"data.tar.gz", nativeTestGzip(t, valid)}, debMember{"extra", []byte("x")})
	if _, err := inspectDeb(context.Background(), withExtra); err == nil {
		t.Fatal("extra Debian ar member accepted")
	}
}

func TestInspectDebXZ(t *testing.T) {
	if _, err := exec.LookPath("xz"); err != nil {
		t.Skip("xz is unavailable")
	}
	pack := func(input []byte) []byte {
		cmd := exec.Command("xz", "--compress", "--stdout")
		cmd.Stdin = bytes.NewReader(input)
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	controlTar := nativeTestTar(t, []tar.Header{{Name: "./control", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(nativeDebControl))}}, [][]byte{[]byte(nativeDebControl)})
	data := nativeTestAr(debMember{"debian-binary", []byte("2.0\n")}, debMember{"control.tar.xz", pack(controlTar)}, debMember{"data.tar.xz", pack(nativeTestPayloadTar(t))})
	if got, err := inspectDeb(context.Background(), data); err != nil || len(got.Files) != 1 {
		t.Fatalf("inspect xz Debian package: %+v, %v", got, err)
	}
}

type nativeRPMTag struct {
	id    uint32
	typ   uint32
	value []byte
	count uint32
}

func nativeRPMString(id uint32, value string) nativeRPMTag {
	return nativeRPMTag{id, 6, append([]byte(value), 0), 1}
}
func nativeRPMStrings(id uint32, values ...string) nativeRPMTag {
	var data []byte
	for _, value := range values {
		data = append(data, value...)
		data = append(data, 0)
	}
	return nativeRPMTag{id, 8, data, uint32(len(values))}
}
func nativeRPMInt32s(id uint32, values ...uint32) nativeRPMTag {
	data := make([]byte, len(values)*4)
	for i, value := range values {
		binary.BigEndian.PutUint32(data[i*4:], value)
	}
	return nativeRPMTag{id, 4, data, uint32(len(values))}
}
func nativeRPMInt16s(id uint32, values ...uint16) nativeRPMTag {
	data := make([]byte, len(values)*2)
	for i, value := range values {
		binary.BigEndian.PutUint16(data[i*2:], value)
	}
	return nativeRPMTag{id, 3, data, uint32(len(values))}
}

func nativeRPMHeader(tags ...nativeRPMTag) []byte {
	sort.Slice(tags, func(i, j int) bool { return tags[i].id < tags[j].id })
	index := make([]byte, len(tags)*16)
	var data []byte
	for i, tag := range tags {
		if tag.typ == 3 && len(data)%2 != 0 {
			data = append(data, 0)
		}
		if tag.typ == 4 {
			for len(data)%4 != 0 {
				data = append(data, 0)
			}
		}
		binary.BigEndian.PutUint32(index[i*16:], tag.id)
		binary.BigEndian.PutUint32(index[i*16+4:], tag.typ)
		binary.BigEndian.PutUint32(index[i*16+8:], uint32(len(data)))
		binary.BigEndian.PutUint32(index[i*16+12:], tag.count)
		data = append(data, tag.value...)
	}
	out := append([]byte{0x8e, 0xad, 0xe8, 1, 0, 0, 0, 0}, make([]byte, 8)...)
	binary.BigEndian.PutUint32(out[8:], uint32(len(tags)))
	binary.BigEndian.PutUint32(out[12:], uint32(len(data)))
	out = append(out, index...)
	return append(out, data...)
}

func nativeCPIOEntry(name string, mode uint32, content []byte) []byte {
	fields := []uint32{1, mode, 0, 0, 1, 0, uint32(len(content)), 0, 0, 0, 0, uint32(len(name) + 1), 0}
	var out bytes.Buffer
	out.WriteString("070701")
	for _, value := range fields {
		fmt.Fprintf(&out, "%08x", value)
	}
	out.WriteString(name)
	out.WriteByte(0)
	for out.Len()%4 != 0 {
		out.WriteByte(0)
	}
	out.Write(content)
	for out.Len()%4 != 0 {
		out.WriteByte(0)
	}
	return out.Bytes()
}

func nativeTestRPM(t *testing.T, extra []nativeRPMTag, cpio []byte) []byte {
	return nativeTestRPMVersion(t, "1.2.3", "1", false, extra, cpio)
}

func nativeTestRPMWithFile(t *testing.T, filePath string, flags uint32) []byte {
	t.Helper()
	separator := strings.LastIndex(filePath, "/")
	if separator <= 0 || separator == len(filePath)-1 || filePath[0] != '/' {
		t.Fatalf("invalid test RPM path %q", filePath)
	}
	content := []byte("binary")
	sha := sha256.Sum256(content)
	mode := uint32(0o100644)
	if strings.HasPrefix(filePath, "/usr/bin/") {
		mode = 0o100755
	}
	tags := []nativeRPMTag{
		nativeRPMString(1000, "leaguebridge"), nativeRPMString(1001, "1.2.3"), nativeRPMString(1002, "1"),
		nativeRPMString(1021, "linux"), nativeRPMString(1022, "x86_64"),
		nativeRPMInt32s(1028, uint32(len(content))), nativeRPMInt16s(1030, uint16(mode)),
		nativeRPMStrings(1035, hex.EncodeToString(sha[:])), nativeRPMInt32s(1037, flags),
		nativeRPMStrings(1039, "root"), nativeRPMStrings(1040, "root"),
		nativeRPMString(1124, "cpio"), nativeRPMString(1125, "gzip"), nativeRPMInt32s(5011, 8),
		nativeRPMInt32s(1116, 0), nativeRPMStrings(1117, filePath[separator+1:]),
		nativeRPMStrings(1118, filePath[:separator+1]),
	}
	cpio := nativeCPIOEntry("."+filePath, mode, content)
	cpio = append(cpio, nativeCPIOEntry("TRAILER!!!", 0, nil)...)
	lead := make([]byte, 96)
	copy(lead, []byte{0xed, 0xab, 0xee, 0xdb, 3, 0, 0, 0})
	out := append(lead, nativeRPMHeader()...)
	for len(out)%8 != 0 {
		out = append(out, 0)
	}
	out = append(out, nativeRPMHeader(tags...)...)
	return append(out, nativeTestGzip(t, cpio)...)
}

func nativeTestRPMVersion(t *testing.T, version, release string, withDirectory bool, extra []nativeRPMTag, cpio []byte) []byte {
	t.Helper()
	sha := sha256.Sum256([]byte("binary"))
	tags := []nativeRPMTag{
		nativeRPMString(1000, "leaguebridge"), nativeRPMString(1001, version), nativeRPMString(1002, release),
		nativeRPMString(1021, "linux"), nativeRPMString(1022, "x86_64"),
		nativeRPMString(1124, "cpio"), nativeRPMString(1125, "gzip"),
	}
	if withDirectory {
		tags = append(tags,
			nativeRPMInt32s(1028, 6, 0), nativeRPMInt16s(1030, 0o100755, 0o040755),
			nativeRPMStrings(1035, hex.EncodeToString(sha[:]), ""), nativeRPMStrings(1039, "root", "root"),
			nativeRPMStrings(1040, "root", "root"), nativeRPMInt32s(5011, 8),
			nativeRPMInt32s(1116, 0, 1), nativeRPMStrings(1117, "leaguebridge", "bin"),
			nativeRPMStrings(1118, "/usr/bin/", "/usr/"),
		)
	} else {
		tags = append(tags,
			nativeRPMInt32s(1028, 6), nativeRPMInt16s(1030, 0o100755),
			nativeRPMStrings(1035, hex.EncodeToString(sha[:])), nativeRPMStrings(1039, "root"),
			nativeRPMStrings(1040, "root"), nativeRPMInt32s(5011, 8),
			nativeRPMInt32s(1116, 0), nativeRPMStrings(1117, "leaguebridge"),
			nativeRPMStrings(1118, "/usr/bin/"),
		)
	}
	tags = append(tags, extra...)
	lead := make([]byte, 96)
	copy(lead, []byte{0xed, 0xab, 0xee, 0xdb, 3, 0, 0, 0})
	out := append(lead, nativeRPMHeader()...)
	for len(out)%8 != 0 {
		out = append(out, 0)
	}
	out = append(out, nativeRPMHeader(tags...)...)
	return append(out, nativeTestGzip(t, cpio)...)
}

func nativeTestCPIO() []byte {
	out := nativeCPIOEntry("./usr/bin/leaguebridge", 0o100755, []byte("binary"))
	return append(out, nativeCPIOEntry("TRAILER!!!", 0, nil)...)
}

func TestInspectRPMActualHeaderAndPayload(t *testing.T) {
	got, err := inspectRPM(context.Background(), nativeTestRPM(t, nil, nativeTestCPIO()))
	if err != nil {
		t.Fatal(err)
	}
	wantSHA := sha256.Sum256([]byte("binary"))
	if got.Name != "leaguebridge" || got.Version != "v1.2.3" || got.Architecture != "x86_64" ||
		len(got.Files) != 1 || got.Files[0] != (inspectedFile{"/usr/bin/leaguebridge", "0755", 6, hex.EncodeToString(wantSHA[:])}) {
		t.Fatalf("unexpected RPM package observation: %+v", got)
	}
}

func TestInspectRPMCIPrereleaseAndDirectory(t *testing.T) {
	directory := nativeCPIOEntry("./usr/bin", 0o040755, nil)
	copy(directory[6+4*8:6+5*8], []byte("00000002")) // ordinary directory link count
	cpio := append(directory, nativeTestCPIO()...)
	got, err := inspectRPM(context.Background(), nativeTestRPMVersion(t, "0.0.0", "1.ci", true, nil, cpio))
	if err != nil || got.Version != "v0.0.0-ci" || len(got.Files) != 1 {
		t.Fatalf("CI RPM version and safe directory: %+v, %v", got, err)
	}
}

func TestInspectRPMEmptyFileLanguages(t *testing.T) {
	got, err := inspectRPM(context.Background(), nativeTestRPM(t, []nativeRPMTag{nativeRPMStrings(1097, "")}, nativeTestCPIO()))
	if err != nil || len(got.Files) != 1 {
		t.Fatalf("empty RPM file languages: %+v, %v", got, err)
	}
}

func TestInspectRPMReviewedDocumentationFlags(t *testing.T) {
	for _, tc := range []struct {
		name    string
		path    string
		flags   uint32
		wantErr bool
	}{
		{"documentation without flags", "/usr/share/doc/leaguebridge/LICENSE", 0, false},
		{"documentation marker", "/usr/share/doc/leaguebridge/LICENSE", rpmFileFlagDoc, false},
		{"binary without flags", "/usr/bin/leaguebridge", 0, false},
		{"config flag on documentation", "/usr/share/doc/leaguebridge/LICENSE", 1, true},
		{"documentation flag on binary", "/usr/bin/leaguebridge", rpmFileFlagDoc, true},
		{"combined documentation and config flags", "/usr/share/doc/leaguebridge/LICENSE", rpmFileFlagDoc | 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := inspectRPM(context.Background(), nativeTestRPMWithFile(t, tc.path, tc.flags))
			if tc.wantErr && err == nil {
				t.Fatal("RPM file flags were accepted")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("reviewed RPM file flags were rejected: %v", err)
			}
		})
	}
}

func TestInspectRPMOrdinarySelfProvides(t *testing.T) {
	self := []nativeRPMTag{
		nativeRPMStrings(1049, "rpmlib(CompressedFileNames)", "rpmlib(FileDigests)", "rpmlib(PayloadFilesHavePrefix)"),
		nativeRPMStrings(1050, "3.0.4-1", "4.6.0-1", "4.0-1"),
		nativeRPMInt32s(1048, 0x100000a, 0x100000a, 0x100000a),
		nativeRPMStrings(1047, "leaguebridge", "leaguebridge(x86-64)"),
		nativeRPMStrings(1113, "1.2.3-1", "1.2.3-1"),
		nativeRPMInt32s(1112, 8, 8),
	}
	got, err := inspectRPM(context.Background(), nativeTestRPM(t, self, nativeTestCPIO()))
	if err != nil || len(got.Files) != 1 {
		t.Fatalf("ordinary RPM self-provides: %+v, %v", got, err)
	}
}

func TestInspectRPMRejectsUnreviewedContent(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra []nativeRPMTag
		cpio  []byte
	}{
		{"scriptlet", []nativeRPMTag{nativeRPMString(1024, "echo hi")}, nativeTestCPIO()},
		{"trigger", []nativeRPMTag{nativeRPMStrings(5066, "echo hi")}, nativeTestCPIO()},
		{"file capability", []nativeRPMTag{nativeRPMStrings(5010, "cap_setuid+ep")}, nativeTestCPIO()},
		{"language-filtered file", []nativeRPMTag{nativeRPMStrings(1097, "en")}, nativeTestCPIO()},
		{"sysusers virtual provide", []nativeRPMTag{nativeRPMStrings(1047, "user(attacker)"), nativeRPMStrings(1113, "dSBhdHRhY2tlciAtAA"), nativeRPMInt32s(1112, 8)}, nativeTestCPIO()},
		{"unrelated virtual provide", []nativeRPMTag{nativeRPMStrings(1047, "other-package"), nativeRPMStrings(1113, "1.2.3-1"), nativeRPMInt32s(1112, 8)}, nativeTestCPIO()},
		{"wrong self EVR", []nativeRPMTag{nativeRPMStrings(1047, "leaguebridge"), nativeRPMStrings(1113, "9.9.9-1"), nativeRPMInt32s(1112, 8)}, nativeTestCPIO()},
		{"extra Requires", []nativeRPMTag{nativeRPMStrings(1049, "other-package"), nativeRPMStrings(1050, "1"), nativeRPMInt32s(1048, 8)}, nativeTestCPIO()},
		{"wrong rpmlib version", []nativeRPMTag{nativeRPMStrings(1049, "rpmlib(FileDigests)"), nativeRPMStrings(1050, "9.9.9-1"), nativeRPMInt32s(1048, 0x100000a)}, nativeTestCPIO()},
		{"obsoletes package", []nativeRPMTag{nativeRPMStrings(1090, "other-package"), nativeRPMStrings(1115, "1"), nativeRPMInt32s(1114, 8)}, nativeTestCPIO()},
		{"header digest mismatch", nil, append(nativeCPIOEntry("./usr/bin/leaguebridge", 0o100755, []byte("other!")), nativeCPIOEntry("TRAILER!!!", 0, nil)...)},
		{"symlink", nil, append(nativeCPIOEntry("./usr/bin/leaguebridge", 0o120777, []byte("target")), nativeCPIOEntry("TRAILER!!!", 0, nil)...)},
		{"path traversal", nil, append(nativeCPIOEntry("../evil", 0o100755, []byte("binary")), nativeCPIOEntry("TRAILER!!!", 0, nil)...)},
		{"duplicate payload", nil, append(append(nativeCPIOEntry("./usr/bin/leaguebridge", 0o100755, []byte("binary")), nativeCPIOEntry("./usr/bin/leaguebridge", 0o100755, []byte("binary"))...), nativeCPIOEntry("TRAILER!!!", 0, nil)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := inspectRPM(context.Background(), nativeTestRPM(t, tc.extra, tc.cpio)); err == nil {
				t.Fatal("unsafe RPM package accepted")
			}
		})
	}
	for _, relation := range []struct {
		name, version, flags uint32
	}{
		{1054, 1055, 1053}, // Conflicts
		{5046, 5047, 5048}, // Recommends
		{5049, 5050, 5051}, // Suggests
		{5052, 5053, 5054}, // Supplements
		{5055, 5056, 5057}, // Enhances
		{5035, 5036, 5037}, // OrderWithRequires
	} {
		t.Run(fmt.Sprintf("dependency relation %d", relation.name), func(t *testing.T) {
			tags := []nativeRPMTag{
				nativeRPMStrings(relation.name, "other-package"),
				nativeRPMStrings(relation.version, "1"),
				nativeRPMInt32s(relation.flags, 8),
			}
			if _, err := inspectRPM(context.Background(), nativeTestRPM(t, tags, nativeTestCPIO())); err == nil {
				t.Fatal("unreviewed dependency relation accepted")
			}
		})
	}
}

func TestInspectLinuxPackageRejectsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := inspectDeb(ctx, nativeTestDeb(t, []byte(nativeDebControl), nativeTestPayloadTar(t))); err != context.Canceled {
		t.Fatalf("Debian canceled context: %v", err)
	}
	if _, err := inspectRPM(ctx, nativeTestRPM(t, nil, nativeTestCPIO())); err != context.Canceled {
		t.Fatalf("RPM canceled context: %v", err)
	}
}
