package productionpackage

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Yunushan/leaguebridge/internal/releaseversion"
)

// The Linux inspectors intentionally accept the ordinary, bounded package
// formats produced by scripts/native-package-linux-smoke.sh. Unrecognized
// compression, special filesystem objects, install hooks, and format variants
// require an explicit review before they can be accepted as production input.
const (
	maximumNativeEntries = 1024
	maximumRPMHeader     = 16 << 20
	maximumControlTar    = 4 << 20
	rpmFileFlagDoc       = 1 << 1
)

func inspectDeb(ctx context.Context, packageData []byte) (inspectedPackage, error) {
	if ctx == nil {
		return inspectedPackage{}, errors.New("Debian inspection context is required")
	}
	if err := ctx.Err(); err != nil {
		return inspectedPackage{}, err
	}
	members, err := debMembers(packageData)
	if err != nil {
		return inspectedPackage{}, err
	}
	controlData, err := decompressNative(ctx, members[1].name, members[1].data, maximumControlTar)
	if err != nil {
		return inspectedPackage{}, fmt.Errorf("decompress Debian control: %w", err)
	}
	metadata, err := inspectDebControl(ctx, controlData)
	if err != nil {
		return inspectedPackage{}, err
	}
	payload, err := decompressNative(ctx, members[2].name, members[2].data, maximumUncompressed)
	if err != nil {
		return inspectedPackage{}, fmt.Errorf("decompress Debian payload: %w", err)
	}
	metadata.Files, err = inspectTarFiles(ctx, payload)
	if err != nil {
		return inspectedPackage{}, fmt.Errorf("inspect Debian payload: %w", err)
	}
	return metadata, nil
}

type debMember struct {
	name string
	data []byte
}

func debMembers(data []byte) ([]debMember, error) {
	if !bytes.HasPrefix(data, []byte("!<arch>\n")) {
		return nil, errors.New("Debian package has no ar magic")
	}
	var members []debMember
	for pos := 8; pos < len(data); {
		if len(data)-pos < 60 || string(data[pos+58:pos+60]) != "`\n" {
			return nil, errors.New("invalid Debian ar member header")
		}
		header := data[pos : pos+60]
		name := strings.TrimSuffix(strings.TrimSpace(string(header[:16])), "/")
		if name == "" || strings.ContainsAny(name, "/\\\x00") {
			return nil, errors.New("unsupported Debian ar member name")
		}
		size, err := strconv.ParseInt(strings.TrimSpace(string(header[48:58])), 10, 64)
		if err != nil || size < 0 || size > maximumPackage || size > int64(len(data)-pos-60) {
			return nil, errors.New("invalid Debian ar member size")
		}
		start := pos + 60
		end := start + int(size)
		members = append(members, debMember{name: name, data: data[start:end]})
		if len(members) > 3 {
			return nil, errors.New("Debian package has extra ar members")
		}
		pos = end
		if size%2 != 0 {
			if pos >= len(data) || data[pos] != '\n' {
				return nil, errors.New("invalid Debian ar padding")
			}
			pos++
		}
	}
	if len(members) != 3 || members[0].name != "debian-binary" ||
		!bytes.Equal(members[0].data, []byte("2.0\n")) ||
		!strings.HasPrefix(members[1].name, "control.tar") ||
		!strings.HasPrefix(members[2].name, "data.tar") {
		return nil, errors.New("unsupported Debian binary package layout")
	}
	return members, nil
}

func inspectDebControl(ctx context.Context, data []byte) (inspectedPackage, error) {
	tr := tar.NewReader(bytes.NewReader(data))
	var control []byte
	seen := make(map[string]bool)
	for {
		if err := ctx.Err(); err != nil {
			return inspectedPackage{}, err
		}
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return inspectedPackage{}, fmt.Errorf("read Debian control tar: %w", err)
		}
		name := strings.TrimPrefix(h.Name, "./")
		if (h.Name == "." || h.Name == "./") && h.Typeflag == tar.TypeDir {
			continue
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			return inspectedPackage{}, errors.New("Debian control has a non-regular member")
		}
		if h.Uid != 0 || h.Gid != 0 || h.Size < 0 || h.Size > maximumControlTar ||
			len(h.PAXRecords) != 0 || len(h.Xattrs) != 0 || seen[name] {
			return inspectedPackage{}, errors.New("invalid Debian control member")
		}
		seen[name] = true
		switch name {
		case "control":
			control, err = io.ReadAll(io.LimitReader(tr, maximumControlTar+1))
			if err != nil || int64(len(control)) != h.Size {
				return inspectedPackage{}, errors.New("invalid Debian control bytes")
			}
		case "md5sums":
			// dpkg-deb may add a checksum inventory; it is inert metadata.
		default:
			return inspectedPackage{}, fmt.Errorf("unreviewed Debian control member %q", name)
		}
	}
	if len(control) == 0 {
		return inspectedPackage{}, errors.New("Debian control file is missing")
	}
	fields := make(map[string]string)
	if control[len(control)-1] != '\n' {
		return inspectedPackage{}, errors.New("Debian control file has no final newline")
	}
	lastKey := ""
	for _, line := range strings.Split(strings.TrimSuffix(string(control), "\n"), "\n") {
		if line == "" {
			return inspectedPackage{}, errors.New("Debian control contains an extra stanza or blank field")
		}
		if strings.ContainsAny(line, "\x00\r") {
			return inspectedPackage{}, errors.New("invalid Debian control field")
		}
		if line[0] == ' ' || line[0] == '\t' {
			if lastKey != "description" {
				return inspectedPackage{}, errors.New("unexpected Debian control continuation")
			}
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || value == "" {
			return inspectedPackage{}, errors.New("invalid Debian control field")
		}
		key = strings.ToLower(key)
		if _, exists := fields[key]; exists {
			return inspectedPackage{}, errors.New("duplicate Debian control field")
		}
		lastKey = key
		switch key {
		case "package", "version", "architecture", "maintainer", "section", "priority", "description", "installed-size", "homepage":
			fields[key] = strings.TrimSpace(value)
		default:
			return inspectedPackage{}, fmt.Errorf("unreviewed Debian control field %q", key)
		}
	}
	version := "v" + strings.ReplaceAll(fields["version"], "~", "-")
	if fields["package"] != "leaguebridge" || fields["maintainer"] == "" || fields["description"] == "" ||
		len(version) > 128 || !releaseversion.Valid(version) ||
		(fields["architecture"] != "amd64" && fields["architecture"] != "arm64") {
		return inspectedPackage{}, errors.New("Debian package identity is outside the production inventory")
	}
	return inspectedPackage{Name: fields["package"], Version: version, Architecture: fields["architecture"]}, nil
}

func inspectTarFiles(ctx context.Context, data []byte) ([]inspectedFile, error) {
	tr := tar.NewReader(bytes.NewReader(data))
	seen := make(map[string]bool)
	var files []inspectedFile
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar member: %w", err)
		}
		name, err := nativePath(h.Name, h.Typeflag == tar.TypeDir)
		if err != nil {
			return nil, err
		}
		if seen[name] {
			return nil, errors.New("duplicate native payload path")
		}
		seen[name] = true
		if h.Uid != 0 || h.Gid != 0 || len(h.PAXRecords) != 0 || len(h.Xattrs) != 0 || h.Mode&^int64(0o777) != 0 {
			return nil, errors.New("native tar member has unsupported ownership, mode, or metadata")
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if h.Size != 0 || h.Mode != 0o755 {
				return nil, errors.New("native tar directory has unsupported attributes")
			}
		case tar.TypeReg, tar.TypeRegA:
			if name == "/" || h.Size < 0 || h.Size > maximumUncompressed || total > maximumUncompressed-h.Size {
				return nil, errors.New("native tar file is oversized or invalid")
			}
			total += h.Size
			sha := sha256.New()
			if _, err := io.CopyN(sha, tr, h.Size); err != nil {
				return nil, fmt.Errorf("read native tar file: %w", err)
			}
			files = append(files, inspectedFile{Path: name, Mode: fmt.Sprintf("%04o", h.Mode), Size: h.Size, SHA256: hex.EncodeToString(sha.Sum(nil))})
		default:
			return nil, errors.New("native tar contains a link, device, or unsupported member")
		}
		if len(seen) > maximumNativeEntries {
			return nil, errors.New("too many native tar entries")
		}
	}
	if len(files) == 0 {
		return nil, errors.New("native tar contains no regular files")
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

func nativePath(raw string, directory bool) (string, error) {
	if directory && (raw == "." || raw == "./") {
		return "/", nil
	}
	name := strings.TrimPrefix(raw, "./")
	if directory {
		name = strings.TrimSuffix(name, "/")
	}
	if name == "" || strings.ContainsAny(name, "\\\x00\n\r") || strings.HasPrefix(name, "/") ||
		path.Clean(name) != name || strings.HasPrefix(name, "../") || name == ".." || strings.Contains(name, "//") {
		return "", errors.New("unsafe native payload path")
	}
	for _, component := range strings.Split(name, "/") {
		if component == "" || component == "." || component == ".." {
			return "", errors.New("unsafe native payload path component")
		}
	}
	if name != "usr" && !strings.HasPrefix(name, "usr/") {
		return "", errors.New("native payload path is outside /usr")
	}
	return "/" + name, nil
}

type boundedNativeOutput struct {
	data     bytes.Buffer
	maximum  int64
	exceeded bool
}

func (w *boundedNativeOutput) Write(p []byte) (int, error) {
	if int64(len(p)) > w.maximum-int64(w.data.Len()) {
		w.exceeded = true
		return 0, errors.New("native decompressed output exceeds limit")
	}
	return w.data.Write(p)
}

func decompressNative(ctx context.Context, name string, data []byte, maximum int64) ([]byte, error) {
	if int64(len(data)) > maximumPackage {
		return nil, errors.New("compressed native member exceeds limit")
	}
	if strings.HasSuffix(name, ".tar") {
		if int64(len(data)) > maximum {
			return nil, errors.New("native tar exceeds limit")
		}
		return data, nil
	}
	if strings.HasSuffix(name, ".tar.gz") {
		zipped, err := gzip.NewReader(contextReader{ctx: ctx, reader: bytes.NewReader(data)})
		if err != nil {
			return nil, err
		}
		defer zipped.Close()
		out, err := io.ReadAll(io.LimitReader(zipped, maximum+1))
		if err != nil || int64(len(out)) > maximum {
			return nil, errors.New("invalid or oversized native gzip tar")
		}
		return out, nil
	}
	var command string
	var args []string
	switch {
	case strings.HasSuffix(name, ".tar.xz"):
		command, args = "xz", []string{"--decompress", "--stdout"}
	case strings.HasSuffix(name, ".tar.zst"):
		command, args = "zstd", []string{"--decompress", "--stdout", "--no-progress"}
	default:
		return nil, fmt.Errorf("unsupported native tar compression %q", name)
	}
	toolCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(toolCtx, command, args...)
	cmd.Stdin = bytes.NewReader(data)
	out := &boundedNativeOutput{maximum: maximum}
	stderr := &boundedNativeOutput{maximum: 8 << 10}
	cmd.Stdout, cmd.Stderr = out, stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if out.exceeded {
			return nil, errors.New("native decompressed output exceeds limit")
		}
		return nil, fmt.Errorf("native decompression failed: %w: %s", err, strings.TrimSpace(stderr.data.String()))
	}
	return out.data.Bytes(), nil
}

func inspectRPM(ctx context.Context, packageData []byte) (inspectedPackage, error) {
	if ctx == nil {
		return inspectedPackage{}, errors.New("RPM inspection context is required")
	}
	if err := ctx.Err(); err != nil {
		return inspectedPackage{}, err
	}
	if len(packageData) < 96 || !bytes.Equal(packageData[:4], []byte{0xed, 0xab, 0xee, 0xdb}) ||
		binary.BigEndian.Uint16(packageData[6:8]) != 0 {
		return inspectedPackage{}, errors.New("unsupported RPM binary package lead")
	}
	_, signatureEnd, err := parseRPMHeader(packageData, 96)
	if err != nil {
		return inspectedPackage{}, fmt.Errorf("parse RPM signature header: %w", err)
	}
	mainOffset := (signatureEnd + 7) &^ 7
	main, payloadOffset, err := parseRPMHeader(packageData, mainOffset)
	if err != nil {
		return inspectedPackage{}, fmt.Errorf("parse RPM main header: %w", err)
	}
	for tag := range rpmScriptTags {
		if main.has(tag) {
			return inspectedPackage{}, fmt.Errorf("RPM has unreviewed script or trigger tag %d", tag)
		}
	}
	if main.has(5010) || main.has(1098) || main.has(1106) {
		return inspectedPackage{}, errors.New("RPM has file capabilities, relocation, or source-package metadata")
	}
	name, err := main.stringTag(1000)
	if err != nil {
		return inspectedPackage{}, err
	}
	version, err := main.stringTag(1001)
	if err != nil {
		return inspectedPackage{}, err
	}
	release, err := main.stringTag(1002)
	if err != nil {
		return inspectedPackage{}, err
	}
	architecture, err := main.stringTag(1022)
	if err != nil {
		return inspectedPackage{}, err
	}
	format, err := main.stringTag(1124)
	if err != nil {
		return inspectedPackage{}, err
	}
	compressor, err := main.stringTag(1125)
	if err != nil {
		return inspectedPackage{}, err
	}
	normalizedVersion := "v" + version
	if release != "1" {
		if !strings.HasPrefix(release, "1.") || len(release) <= 2 {
			return inspectedPackage{}, errors.New("RPM release is outside the production inventory")
		}
		normalizedVersion += "-" + strings.TrimPrefix(release, "1.")
	}
	if name != "leaguebridge" || len(normalizedVersion) > 128 || !releaseversion.Valid(normalizedVersion) ||
		(architecture != "x86_64" && architecture != "aarch64") || format != "cpio" || compressor != "gzip" {
		return inspectedPackage{}, errors.New("RPM identity or payload format is outside the production inventory")
	}
	if main.has(1003) {
		epoch, err := main.uintArrayTag(1003, 4)
		if err != nil || len(epoch) != 1 || epoch[0] != 0 {
			return inspectedPackage{}, errors.New("RPM has a nonzero or invalid epoch")
		}
	}
	if main.has(1021) {
		osName, err := main.stringTag(1021)
		if err != nil || osName != "linux" {
			return inspectedPackage{}, errors.New("RPM has unsupported target operating system")
		}
	}
	if err := verifyRPMDependencies(main, version, release, architecture); err != nil {
		return inspectedPackage{}, err
	}
	if payloadOffset >= len(packageData) {
		return inspectedPackage{}, errors.New("RPM payload is missing")
	}
	payload, err := decompressNative(ctx, "data.tar.gz", packageData[payloadOffset:], maximumUncompressed)
	if err != nil {
		return inspectedPackage{}, fmt.Errorf("decompress RPM payload: %w", err)
	}
	files, directories, err := inspectCPIO(ctx, payload)
	if err != nil {
		return inspectedPackage{}, fmt.Errorf("inspect RPM cpio payload: %w", err)
	}
	if err := compareRPMFileHeader(main, files, directories); err != nil {
		return inspectedPackage{}, err
	}
	return inspectedPackage{Name: name, Version: normalizedVersion, Architecture: architecture, Files: files}, nil
}

// RPM script and trigger tag numbers are from rpm.org's RPM Tags manual.
var rpmScriptTags = map[uint32]bool{
	1023: true, 1024: true, 1025: true, 1026: true, 1079: true,
	1085: true, 1086: true, 1087: true, 1088: true, 1091: true,
	1151: true, 1152: true, 1153: true, 1154: true,
	5020: true, 5021: true, 5022: true, 5023: true, 5024: true, 5025: true, 5026: true,
	5103: true, 5104: true, 5105: true, 5106: true, 5107: true, 5108: true,
	1065: true, 1066: true, 1067: true, 1068: true, 1069: true, 1092: true, 5027: true,
	5066: true, 5067: true, 5068: true, 5069: true, 5070: true, 5071: true, 5072: true,
	5076: true, 5077: true, 5078: true, 5079: true, 5080: true, 5081: true, 5082: true,
	5084: true, 5085: true,
}

// The smoke RPM uses AutoReqProv: no. RPM still adds its own format Requires
// and package/ISA self Provides. Other relationships may change install
// ordering, bring in unrelated packages, block an install, or remove packages.
func verifyRPMDependencies(h rpmHeader, version, release, architecture string) error {
	for _, relation := range []struct {
		name string
		tags [3]uint32
	}{
		{"Conflicts", [3]uint32{1054, 1055, 1053}},
		{"Obsoletes", [3]uint32{1090, 1115, 1114}},
		{"Recommends", [3]uint32{5046, 5047, 5048}},
		{"Suggests", [3]uint32{5049, 5050, 5051}},
		{"Supplements", [3]uint32{5052, 5053, 5054}},
		{"Enhances", [3]uint32{5055, 5056, 5057}},
		{"OrderWithRequires", [3]uint32{5035, 5036, 5037}},
	} {
		for _, tag := range relation.tags {
			if h.has(tag) {
				return fmt.Errorf("RPM has unreviewed %s metadata", relation.name)
			}
		}
	}
	if h.has(1049) || h.has(1050) || h.has(1048) {
		if !h.has(1049) || !h.has(1050) || !h.has(1048) {
			return errors.New("RPM Requires triplet is incomplete")
		}
		names, err := h.stringArrayTag(1049)
		if err != nil {
			return errors.New("RPM Requires names are invalid")
		}
		versions, err := h.stringArrayTag(1050)
		if err != nil || len(versions) != len(names) {
			return errors.New("RPM Requires versions are invalid")
		}
		flags, err := h.uintArrayTag(1048, 4)
		if err != nil || len(flags) != len(names) {
			return errors.New("RPM Requires flags are invalid")
		}
		allowed := map[string]string{
			"rpmlib(CompressedFileNames)":    "3.0.4-1",
			"rpmlib(FileDigests)":            "4.6.0-1",
			"rpmlib(PayloadFilesHavePrefix)": "4.0-1",
		}
		seen := make(map[string]bool, len(names))
		for i, name := range names {
			if seen[name] || allowed[name] == "" || versions[i] != allowed[name] || flags[i] != 0x100000a {
				return fmt.Errorf("RPM has unreviewed Requires capability %q", name)
			}
			seen[name] = true
		}
	}
	// RPM 4.19+ executes user(), group(), and groupmember() Provides as
	// sysusers operations before extracting the payload. Require exact self
	// capabilities and EVR so virtual metadata cannot create a side effect.
	if h.has(1047) || h.has(1113) || h.has(1112) {
		if !h.has(1047) || !h.has(1113) || !h.has(1112) {
			return errors.New("RPM Provides triplet is incomplete")
		}
		names, err := h.stringArrayTag(1047)
		if err != nil {
			return errors.New("RPM Provides names are invalid")
		}
		versions, err := h.stringArrayTag(1113)
		if err != nil || len(versions) != len(names) {
			return errors.New("RPM Provides versions are invalid")
		}
		flags, err := h.uintArrayTag(1112, 4)
		if err != nil || len(flags) != len(names) {
			return errors.New("RPM Provides flags are invalid")
		}
		archProvide := "leaguebridge(x86-64)"
		if architecture == "aarch64" {
			archProvide = "leaguebridge(aarch-64)"
		}
		seen := make(map[string]bool, len(names))
		for i, name := range names {
			self := name == "leaguebridge" || name == archProvide ||
				(architecture == "aarch64" && name == "leaguebridge(aarch64)")
			if seen[name] || !self || versions[i] != version+"-"+release || flags[i] != 8 {
				return fmt.Errorf("RPM has unreviewed Provides capability %q", name)
			}
			seen[name] = true
		}
	}
	return nil
}

type rpmIndex struct {
	typ   uint32
	off   uint32
	count uint32
}

type rpmHeader struct {
	entries map[uint32]rpmIndex
	data    []byte
}

func parseRPMHeader(raw []byte, offset int) (rpmHeader, int, error) {
	if offset < 0 || len(raw)-offset < 16 || !bytes.Equal(raw[offset:offset+8], []byte{0x8e, 0xad, 0xe8, 1, 0, 0, 0, 0}) {
		return rpmHeader{}, 0, errors.New("RPM header magic is invalid")
	}
	count := binary.BigEndian.Uint32(raw[offset+8 : offset+12])
	size := binary.BigEndian.Uint32(raw[offset+12 : offset+16])
	if count > 16384 || size > maximumRPMHeader || uint64(16)+uint64(count)*16+uint64(size) > uint64(len(raw)-offset) {
		return rpmHeader{}, 0, errors.New("RPM header exceeds bounds")
	}
	dataOffset := offset + 16 + int(count)*16
	data := raw[dataOffset : dataOffset+int(size)]
	entries := make(map[uint32]rpmIndex, count)
	for i := 0; i < int(count); i++ {
		entry := raw[offset+16+i*16 : offset+32+i*16]
		tag := binary.BigEndian.Uint32(entry[:4])
		typ := binary.BigEndian.Uint32(entry[4:8])
		off := binary.BigEndian.Uint32(entry[8:12])
		n := binary.BigEndian.Uint32(entry[12:16])
		if _, duplicate := entries[tag]; duplicate || typ < 1 || typ > 9 || off >= size || n > maximumNativeEntries*16 {
			return rpmHeader{}, 0, errors.New("RPM header index is invalid")
		}
		entries[tag] = rpmIndex{typ: typ, off: off, count: n}
	}
	return rpmHeader{entries: entries, data: data}, dataOffset + int(size), nil
}

func (h rpmHeader) has(tag uint32) bool { _, ok := h.entries[tag]; return ok }

func (h rpmHeader) stringTag(tag uint32) (string, error) {
	e, ok := h.entries[tag]
	if !ok || e.typ != 6 || e.count != 1 {
		return "", fmt.Errorf("RPM string tag %d is missing or invalid", tag)
	}
	bytes := h.data[e.off:]
	end := bytesIndexZero(bytes)
	if end <= 0 {
		return "", fmt.Errorf("RPM string tag %d is invalid", tag)
	}
	return string(bytes[:end]), nil
}

func bytesIndexZero(data []byte) int { return bytes.IndexByte(data, 0) }

func (h rpmHeader) stringArrayTag(tag uint32) ([]string, error) {
	e, ok := h.entries[tag]
	if !ok || e.typ != 8 || e.count == 0 || e.count > maximumNativeEntries {
		return nil, fmt.Errorf("RPM string-array tag %d is missing or invalid", tag)
	}
	data := h.data[e.off:]
	result := make([]string, 0, e.count)
	for i := uint32(0); i < e.count; i++ {
		end := bytesIndexZero(data)
		if end < 0 {
			return nil, fmt.Errorf("RPM string-array tag %d is truncated", tag)
		}
		result = append(result, string(data[:end]))
		data = data[end+1:]
	}
	return result, nil
}

func (h rpmHeader) uintArrayTag(tag, typ uint32) ([]uint64, error) {
	e, ok := h.entries[tag]
	if !ok || e.typ != typ || e.count == 0 || e.count > maximumNativeEntries {
		return nil, fmt.Errorf("RPM integer-array tag %d is missing or invalid", tag)
	}
	width := 4
	if typ == 3 {
		width = 2
	}
	if uint64(e.off)+uint64(e.count)*uint64(width) > uint64(len(h.data)) {
		return nil, fmt.Errorf("RPM integer-array tag %d is truncated", tag)
	}
	values := make([]uint64, e.count)
	for i := range values {
		if width == 2 {
			values[i] = uint64(binary.BigEndian.Uint16(h.data[int(e.off)+i*width:]))
		} else {
			values[i] = uint64(binary.BigEndian.Uint32(h.data[int(e.off)+i*width:]))
		}
	}
	return values, nil
}

func compareRPMFileHeader(h rpmHeader, payload []inspectedFile, directories map[string]string) error {
	bases, err := h.stringArrayTag(1117)
	if err != nil {
		return err
	}
	dirs, err := h.stringArrayTag(1118)
	if err != nil {
		return err
	}
	indexes, err := h.uintArrayTag(1116, 4)
	if err != nil {
		return err
	}
	modes, err := h.uintArrayTag(1030, 3)
	if err != nil {
		return err
	}
	sizes, err := h.uintArrayTag(1028, 4)
	if err != nil {
		return err
	}
	digests, err := h.stringArrayTag(1035)
	if err != nil {
		return err
	}
	algo, err := h.uintArrayTag(5011, 4)
	if err != nil || len(algo) != 1 || algo[0] != 8 {
		return errors.New("RPM file digests are not SHA-256")
	}
	if len(bases) < len(payload) || len(indexes) != len(bases) || len(modes) != len(bases) ||
		len(sizes) != len(bases) || len(digests) != len(bases) {
		return errors.New("RPM header file inventory differs from payload")
	}
	var flags []uint64
	if h.has(1037) {
		flags, err = h.uintArrayTag(1037, 4)
		if err != nil || len(flags) != len(bases) {
			return errors.New("RPM file flags are invalid")
		}
	}
	var links []string
	if h.has(1036) {
		links, err = h.stringArrayTag(1036)
		if err != nil || len(links) != len(bases) {
			return errors.New("RPM file link inventory is invalid")
		}
	}
	if h.has(1097) {
		langs, err := h.stringArrayTag(1097)
		if err != nil || len(langs) != len(bases) {
			return errors.New("RPM file language inventory is invalid")
		}
		for _, lang := range langs {
			if lang != "" {
				return errors.New("RPM language-filtered files are unsupported")
			}
		}
	}
	for _, tag := range []uint32{1039, 1040} {
		if h.has(tag) {
			owners, err := h.stringArrayTag(tag)
			if err != nil || len(owners) != len(bases) {
				return errors.New("RPM file ownership inventory is invalid")
			}
			for _, owner := range owners {
				if owner != "root" {
					return errors.New("RPM file owner or group is not root")
				}
			}
		}
	}
	actual := make(map[string]inspectedFile, len(payload))
	for _, file := range payload {
		actual[file.Path] = file
	}
	for i, base := range bases {
		if indexes[i] >= uint64(len(dirs)) || base == "" || strings.ContainsAny(base, "/\\\x00") ||
			!strings.HasPrefix(dirs[indexes[i]], "/") || !strings.HasSuffix(dirs[indexes[i]], "/") {
			return errors.New("RPM header file path is invalid")
		}
		full := dirs[indexes[i]] + base
		if modes[i]&0o170000 == 0o040000 {
			if directories[full] != "0755" || modes[i]&0o7777 != 0o755 || sizes[i] != 0 ||
				digests[i] != "" || (flags != nil && flags[i] != 0) || (links != nil && links[i] != "") {
				return errors.New("RPM header directory metadata differs from payload")
			}
			delete(directories, full)
			continue
		}
		file, ok := actual[full]
		if !ok {
			return fmt.Errorf("RPM header file %q is missing from payload", full)
		}
		if modes[i]&0o170000 != 0o100000 || modes[i]&0o7000 != 0 {
			return fmt.Errorf("RPM header file %q has unsafe mode bits %06o", full, modes[i])
		}
		if headerMode := fmt.Sprintf("%04o", modes[i]&0o777); headerMode != file.Mode {
			return fmt.Errorf("RPM header file %q mode %s differs from payload mode %s", full, headerMode, file.Mode)
		}
		if sizes[i] != uint64(file.Size) {
			return fmt.Errorf("RPM header file %q size %d differs from payload size %d", full, sizes[i], file.Size)
		}
		if digests[i] != file.SHA256 {
			return fmt.Errorf("RPM header file %q SHA-256 differs from payload", full)
		}
		if flags != nil && !reviewedRPMFileFlags(full, flags[i]) {
			return fmt.Errorf("RPM header file %q has unreviewed flags 0x%x", full, flags[i])
		}
		if links != nil && links[i] != "" {
			return fmt.Errorf("RPM header file %q has unreviewed link metadata", full)
		}
		delete(actual, full)
	}
	if len(actual) != 0 {
		return errors.New("RPM payload has files absent from its header")
	}
	return nil
}

func reviewedRPMFileFlags(filePath string, flags uint64) bool {
	if flags == 0 {
		return true
	}
	return strings.HasPrefix(filePath, "/usr/share/doc/leaguebridge/") && flags == rpmFileFlagDoc
}

func inspectCPIO(ctx context.Context, data []byte) ([]inspectedFile, map[string]string, error) {
	var files []inspectedFile
	directories := make(map[string]string)
	seen := make(map[string]bool)
	var total int64
	pos := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if len(data)-pos < 110 || (string(data[pos:pos+6]) != "070701" && string(data[pos:pos+6]) != "070702") {
			return nil, nil, errors.New("unsupported or truncated RPM cpio member")
		}
		magic := string(data[pos : pos+6])
		field := func(index int) (uint64, error) {
			start := pos + 6 + index*8
			return strconv.ParseUint(string(data[start:start+8]), 16, 32)
		}
		mode, err1 := field(1)
		uid, err2 := field(2)
		gid, err3 := field(3)
		nlink, err4 := field(4)
		size, err5 := field(6)
		nameSize, err6 := field(11)
		checksum, err7 := field(12)
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil || err6 != nil || err7 != nil ||
			nameSize == 0 || nameSize > 4096 || size > uint64(maximumUncompressed) ||
			uint64(len(data)-pos-110) < nameSize {
			return nil, nil, errors.New("invalid RPM cpio member header")
		}
		nameStart := pos + 110
		nameEnd := nameStart + int(nameSize)
		if data[nameEnd-1] != 0 {
			return nil, nil, errors.New("RPM cpio name is not terminated")
		}
		rawName := string(data[nameStart : nameEnd-1])
		pos = (nameEnd + 3) &^ 3
		if pos > len(data) || size > uint64(len(data)-pos) {
			return nil, nil, errors.New("RPM cpio payload is truncated")
		}
		content := data[pos : pos+int(size)]
		pos = (pos + int(size) + 3) &^ 3
		if pos > len(data) {
			return nil, nil, errors.New("RPM cpio padding is truncated")
		}
		if magic == "070702" {
			var sum uint32
			for _, b := range content {
				sum += uint32(b)
			}
			if uint64(sum) != checksum {
				return nil, nil, errors.New("RPM cpio checksum mismatch")
			}
		} else if checksum != 0 {
			return nil, nil, errors.New("unexpected RPM cpio checksum")
		}
		if rawName == "TRAILER!!!" {
			if size != 0 || len(files) == 0 {
				return nil, nil, errors.New("invalid RPM cpio trailer")
			}
			for _, b := range data[pos:] {
				if b != 0 {
					return nil, nil, errors.New("RPM cpio has bytes after trailer")
				}
			}
			break
		}
		isDir := mode&0o170000 == 0o040000
		name, err := nativePath(rawName, isDir)
		if err != nil || seen[name] || uid != 0 || gid != 0 || nlink == 0 ||
			(!isDir && nlink != 1) || mode&0o7000 != 0 {
			return nil, nil, errors.New("RPM cpio has unsafe path, ownership, or link count")
		}
		seen[name] = true
		switch mode & 0o170000 {
		case 0o040000:
			if size != 0 || mode&0o777 != 0o755 {
				return nil, nil, errors.New("RPM cpio directory has unsupported attributes")
			}
			directories[name] = "0755"
		case 0o100000:
			if name == "/" || total > maximumUncompressed-int64(size) {
				return nil, nil, errors.New("RPM cpio regular file is invalid or oversized")
			}
			total += int64(size)
			sha := sha256.Sum256(content)
			files = append(files, inspectedFile{Path: name, Mode: fmt.Sprintf("%04o", mode&0o777), Size: int64(size), SHA256: hex.EncodeToString(sha[:])})
		default:
			return nil, nil, errors.New("RPM cpio has a link, device, or unsupported member")
		}
		if len(seen) > maximumNativeEntries {
			return nil, nil, errors.New("RPM cpio has too many entries")
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, directories, nil
}
