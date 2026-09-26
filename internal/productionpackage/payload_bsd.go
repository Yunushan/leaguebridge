package productionpackage

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Yunushan/leaguebridge/internal/releaseversion"
)

// The BSD inspectors parse the package bytes supplied by the private snapshot
// in VerifyPayloadSet. They accept the package layouts built by
// scripts/native-package-bsd-smoke.sh and fail closed on install directives or
// package features that this verifier cannot account for.
const bsdMaximumControl = int64(1 << 20)

var bsdChecksumPattern = regexp.MustCompile(`^[A-Za-z0-9$+/=_-]{16,256}$`)

type bsdEntry struct {
	name     string
	mode     int64
	typeflag byte
	data     []byte
}

func inspectFreeBSDPkg(ctx context.Context, packageData []byte, goos string) (inspectedPackage, error) {
	if goos != "freebsd" && goos != "dragonfly" {
		return inspectedPackage{}, fmt.Errorf("unsupported pkg platform %q", goos)
	}
	entries, err := bsdArchive(ctx, packageData, goos)
	if err != nil {
		return inspectedPackage{}, err
	}
	if len(entries) < 2 || entries[0].name != "+COMPACT_MANIFEST" || entries[1].name != "+MANIFEST" ||
		entries[0].typeflag != tar.TypeReg || entries[1].typeflag != tar.TypeReg {
		return inspectedPackage{}, errors.New("pkg archive must start with compact and full manifests")
	}
	manifest, err := bsdFreeBSDManifest(entries[1].data, goos)
	if err != nil {
		return inspectedPackage{}, err
	}
	if err := bsdMatchCompactManifest(entries[0].data, manifest); err != nil {
		return inspectedPackage{}, err
	}
	files := make(map[string]inspectedFile)
	seenDirs := make(map[string]bool)
	for _, entry := range entries[2:] {
		if strings.HasPrefix(entry.name, "+") {
			return inspectedPackage{}, fmt.Errorf("unexpected pkg control entry %q", entry.name)
		}
		installed, err := bsdInstalledPath(entry.name, true)
		if err != nil {
			return inspectedPackage{}, err
		}
		if entry.typeflag == tar.TypeDir {
			expectedMode, listed := manifest.dirs[installed]
			actualMode := fmt.Sprintf("%04o", entry.mode)
			modeMatches := expectedMode == actualMode
			if goos == "dragonfly" && expectedMode == "" {
				// DragonFly pkg manifests use "y" as a directory-presence
				// marker. The archive still has to bind the reviewed mode.
				modeMatches = actualMode == "0755"
			}
			if !listed || !modeMatches || seenDirs[installed] {
				return inspectedPackage{}, fmt.Errorf("unlisted pkg directory %q", installed)
			}
			seenDirs[installed] = true
			continue
		}
		file, err := bsdInspectedRegular(entry, installed)
		if err != nil {
			return inspectedPackage{}, err
		}
		if _, exists := files[installed]; exists {
			return inspectedPackage{}, fmt.Errorf("duplicate pkg payload %q", installed)
		}
		// Modern pkg manifests use BLAKE2/base32 sums. Their syntax is
		// checked below, but this inspector does not recompute BLAKE2.
		// matchInspectedPayload separately compares SHA-256 of these tar
		// bytes with the authenticated staging manifest.
		if metadata, listed := manifest.files[installed]; !listed ||
			(metadata.mode != file.Mode && !(goos == "dragonfly" && metadata.mode == "")) ||
			(digestPattern.MatchString(metadata.sum) && metadata.sum != file.SHA256) {
			return inspectedPackage{}, fmt.Errorf("pkg manifest does not bind payload %q", installed)
		}
		files[installed] = file
	}
	if len(files) != len(manifest.files) || len(seenDirs) != len(manifest.dirs) {
		return inspectedPackage{}, errors.New("pkg manifest and tar payload inventories differ")
	}
	return inspectedPackage{Name: manifest.name, Version: manifest.version, Architecture: manifest.arch, Files: bsdSortedFiles(files)}, nil
}

func inspectOpenBSDPkg(ctx context.Context, packageData []byte) (inspectedPackage, error) {
	entries, err := bsdArchive(ctx, packageData, "openbsd")
	if err != nil {
		return inspectedPackage{}, err
	}
	controls, payload, err := bsdSplitPackingArchive(entries, map[string]bool{"+CONTENTS": true, "+DESC": true})
	if err != nil {
		return inspectedPackage{}, err
	}
	packing, err := bsdPackingList(controls["+CONTENTS"], "openbsd")
	if err != nil {
		return inspectedPackage{}, err
	}
	if !strings.HasPrefix(packing.name, "leaguebridge-") || !strings.HasSuffix(packing.name, "-openbsd-"+packing.arch) {
		return inspectedPackage{}, errors.New("OpenBSD package name does not bind architecture")
	}
	bare := strings.TrimSuffix(strings.TrimPrefix(packing.name, "leaguebridge-"), "-openbsd-"+packing.arch)
	version, err := bsdVersion(bare)
	if err != nil {
		return inspectedPackage{}, err
	}
	files, err := bsdMatchPackingPayload(payload, packing)
	if err != nil {
		return inspectedPackage{}, err
	}
	return inspectedPackage{Name: "leaguebridge", Version: version, Architecture: packing.arch, Files: files}, nil
}

func inspectNetBSDPkg(ctx context.Context, packageData []byte) (inspectedPackage, error) {
	entries, err := bsdArchive(ctx, packageData, "netbsd")
	if err != nil {
		return inspectedPackage{}, err
	}
	controls, payload, err := bsdSplitPackingArchive(entries, map[string]bool{
		"+CONTENTS": true, "+COMMENT": true, "+DESC": true, "+BUILD_INFO": true,
	})
	if err != nil {
		return inspectedPackage{}, err
	}
	packing, err := bsdPackingList(controls["+CONTENTS"], "netbsd")
	if err != nil {
		return inspectedPackage{}, err
	}
	if !strings.HasPrefix(packing.name, "leaguebridge-") {
		return inspectedPackage{}, errors.New("NetBSD package name is invalid")
	}
	version, err := bsdVersion(strings.TrimPrefix(packing.name, "leaguebridge-"))
	if err != nil {
		return inspectedPackage{}, err
	}
	arch, err := bsdNetBSDArchitecture(controls["+BUILD_INFO"])
	if err != nil {
		return inspectedPackage{}, err
	}
	files, err := bsdMatchPackingPayload(payload, packing)
	if err != nil {
		return inspectedPackage{}, err
	}
	return inspectedPackage{Name: "leaguebridge", Version: version, Architecture: arch, Files: files}, nil
}

type bsdLimitWriter struct {
	buf bytes.Buffer
	max int64
}

func (writer *bsdLimitWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > writer.max-int64(writer.buf.Len()) {
		return 0, errors.New("BSD package expands beyond the maximum size")
	}
	return writer.buf.Write(data)
}

func bsdArchive(ctx context.Context, packageData []byte, goos string) ([]bsdEntry, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("active inspection context is required")
	}
	if len(packageData) == 0 || int64(len(packageData)) > maximumPackage {
		return nil, errors.New("BSD package size is invalid")
	}
	var decoded []byte
	switch goos {
	case "openbsd", "netbsd":
		reader, err := gzip.NewReader(bytes.NewReader(packageData))
		if err != nil {
			return nil, fmt.Errorf("open BSD gzip package: %w", err)
		}
		decoded, err = io.ReadAll(io.LimitReader(reader, maximumUncompressed+1))
		closeErr := reader.Close()
		if err != nil || closeErr != nil || int64(len(decoded)) > maximumUncompressed {
			return nil, errors.New("BSD gzip package is corrupt or too large")
		}
	case "freebsd", "dragonfly":
		// Go's standard library has no XZ reader. The path is fixed, receives
		// private bytes on stdin, and has no shell or caller-supplied arguments.
		output := &bsdLimitWriter{max: maximumUncompressed}
		var stderr bsdLimitWriter
		stderr.max = 16 << 10
		command := exec.CommandContext(ctx, "/usr/bin/xz", "-dc")
		command.Stdin = bytes.NewReader(packageData)
		command.Stdout = output
		command.Stderr = &stderr
		if err := command.Run(); err != nil {
			return nil, fmt.Errorf("decompress BSD xz package: %w", err)
		}
		decoded = output.buf.Bytes()
	default:
		return nil, errors.New("unsupported BSD package compression")
	}
	source := bytes.NewReader(decoded)
	archive := tar.NewReader(source)
	entries := make([]bsdEntry, 0, 16)
	seen := make(map[string]bool)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode BSD tar header: %w", err)
		}
		if len(entries) >= 64 {
			return nil, errors.New("BSD package has too many entries")
		}
		name, err := bsdArchiveName(header.Name)
		if err != nil {
			return nil, err
		}
		if seen[strings.TrimPrefix(name, "/")] {
			return nil, fmt.Errorf("duplicate BSD archive path %q", name)
		}
		seen[strings.TrimPrefix(name, "/")] = true
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA && header.Typeflag != tar.TypeDir {
			return nil, fmt.Errorf("BSD archive entry %q is not a regular file or directory", name)
		}
		if !strings.HasPrefix(name, "+") {
			if header.Uname != "root" || header.Gname != "wheel" {
				return nil, fmt.Errorf("BSD archive entry %q has unreviewed owner or group", name)
			}
			if goos == "freebsd" || goos == "dragonfly" {
				if (header.Uid != 0 && header.Uid != 65534) || (header.Gid != 0 && header.Gid != 65534) {
					return nil, fmt.Errorf("pkg archive entry %q has unreviewed numeric ownership", name)
				}
			} else if header.Uid != 0 || header.Gid != 0 {
				return nil, fmt.Errorf("BSD archive entry %q has non-root numeric ownership", name)
			}
		}
		if len(header.Xattrs) != 0 {
			return nil, fmt.Errorf("BSD archive entry %q has extended attributes", name)
		}
		for key, value := range header.PAXRecords {
			if goos == "netbsd" && key == "hdrcharset" && (value == "BINARY" || value == "ISO-IR 10646 2000 UTF-8") {
				// NetBSD's pax fallback records the header character set. All
				// installed paths and owner names are checked independently.
				continue
			}
			if key != "atime" && key != "ctime" && key != "mtime" && key != "path" {
				return nil, fmt.Errorf("BSD archive entry %q has unreviewed PAX record %q", name, key)
			}
		}
		mode := header.Mode
		if goos == "openbsd" && !strings.HasPrefix(name, "+") &&
			(header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA) &&
			mode&^0o777 == 0o100000 {
			// OpenBSD pkg_create writes the regular-file type bit into
			// the tar mode field in addition to the regular typeflag.
			mode &= 0o777
		}
		if header.Size < 0 || header.Size > nativeBSDMaximumEntry(name) || mode&^0o777 != 0 {
			return nil, fmt.Errorf("BSD archive entry %q has unsafe size or mode", name)
		}
		if header.Typeflag == tar.TypeDir && header.Size != 0 {
			return nil, fmt.Errorf("BSD directory %q carries data", name)
		}
		data, err := io.ReadAll(archive)
		if err != nil || int64(len(data)) != header.Size {
			return nil, fmt.Errorf("read BSD archive entry %q: %w", name, err)
		}
		entries = append(entries, bsdEntry{name: name, mode: mode, typeflag: header.Typeflag, data: data})
	}
	for _, value := range decoded[len(decoded)-source.Len():] {
		if value != 0 {
			return nil, errors.New("BSD tar package has nonzero trailing data")
		}
	}
	return entries, nil
}

func nativeBSDMaximumEntry(name string) int64 {
	if strings.HasPrefix(name, "+") {
		return bsdMaximumControl
	}
	return 128 << 20
}

func bsdArchiveName(raw string) (string, error) {
	name := strings.TrimPrefix(raw, "./")
	name = strings.TrimSuffix(name, "/")
	if name == "" || name == "." || strings.ContainsAny(name, "\\\x00") ||
		path.Clean(name) != name || strings.HasPrefix(name, "../") || name == ".." {
		return "", fmt.Errorf("unsafe BSD archive path %q", raw)
	}
	return name, nil
}

func bsdInstalledPath(name string, freebsd bool) (string, error) {
	if strings.HasPrefix(name, "+") {
		return "", errors.New("metadata is not an installed path")
	}
	if freebsd {
		if !strings.HasPrefix(name, "usr/local/") && !strings.HasPrefix(name, "/usr/local/") {
			return "", fmt.Errorf("pkg payload escapes /usr/local: %q", name)
		}
		return "/" + strings.TrimPrefix(name, "/"), nil
	}
	if strings.HasPrefix(name, "/") || strings.HasPrefix(name, "usr/local/") {
		return "", fmt.Errorf("packing-list payload has unexpected root: %q", name)
	}
	return "/usr/local/" + name, nil
}

func bsdInspectedRegular(entry bsdEntry, installed string) (inspectedFile, error) {
	if entry.typeflag != tar.TypeReg && entry.typeflag != tar.TypeRegA {
		return inspectedFile{}, fmt.Errorf("installed entry %q is not a regular file", installed)
	}
	if entry.mode != 0o644 && entry.mode != 0o755 {
		return inspectedFile{}, fmt.Errorf("installed entry %q has unexpected mode %04o", installed, entry.mode)
	}
	hash := sha256.Sum256(entry.data)
	return inspectedFile{Path: installed, Mode: fmt.Sprintf("%04o", entry.mode), Size: int64(len(entry.data)), SHA256: hex.EncodeToString(hash[:])}, nil
}

func bsdSortedFiles(files map[string]inspectedFile) []inspectedFile {
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	ordered := make([]inspectedFile, 0, len(paths))
	for _, path := range paths {
		ordered = append(ordered, files[path])
	}
	return ordered
}

type bsdPkgManifest struct {
	name, version, arch, rawArch string
	files                        map[string]bsdPkgFile
	dirs                         map[string]string
}

type bsdPkgFile struct {
	sum  string
	mode string
}

func bsdFreeBSDManifest(data []byte, goos string) (bsdPkgManifest, error) {
	if err := bsdRejectDuplicateJSON(data); err != nil {
		return bsdPkgManifest{}, fmt.Errorf("pkg manifest JSON: %w", err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return bsdPkgManifest{}, err
	}
	allowed := map[string]bool{
		"name": true, "version": true, "arch": true, "abi": true, "origin": true,
		"comment": true, "maintainer": true, "prefix": true, "desc": true,
		"flatsize": true, "files": true, "dirs": true, "directories": true,
		"licenselogic": true, "licenses": true, "options": true,
		"annotations": true, "www": true, "categories": true, "pkgsize": true,
		"sum": true,
	}
	for key := range object {
		if !allowed[key] {
			return bsdPkgManifest{}, fmt.Errorf("pkg manifest contains unreviewed field %q", key)
		}
	}
	stringField := func(key string) (string, error) {
		var value string
		if len(object[key]) == 0 || json.Unmarshal(object[key], &value) != nil {
			return "", fmt.Errorf("pkg manifest has invalid %s", key)
		}
		return value, nil
	}
	name, err := stringField("name")
	if err != nil || name != "leaguebridge" {
		return bsdPkgManifest{}, errors.New("pkg manifest name is not leaguebridge")
	}
	origin, err := stringField("origin")
	if err != nil || origin != "sysutils/leaguebridge" {
		return bsdPkgManifest{}, errors.New("pkg manifest origin is not sysutils/leaguebridge")
	}
	bare, err := stringField("version")
	if err != nil {
		return bsdPkgManifest{}, err
	}
	version, err := bsdVersion(bare)
	if err != nil {
		return bsdPkgManifest{}, err
	}
	archField, err := stringField("arch")
	if err != nil {
		return bsdPkgManifest{}, err
	}
	arch, err := bsdFreeBSDArchitecture(archField, goos)
	if err != nil {
		return bsdPkgManifest{}, err
	}
	prefix, err := stringField("prefix")
	if err != nil || prefix != "/usr/local" {
		return bsdPkgManifest{}, errors.New("pkg manifest prefix is not /usr/local")
	}
	if abi := object["abi"]; len(abi) > 0 {
		var value string
		if json.Unmarshal(abi, &value) != nil {
			return bsdPkgManifest{}, errors.New("pkg manifest ABI is invalid")
		}
		abiArch, err := bsdFreeBSDArchitecture(value, goos)
		if err != nil || abiArch != arch {
			return bsdPkgManifest{}, errors.New("pkg manifest ABI conflicts with architecture")
		}
	}
	var fileEntries map[string]json.RawMessage
	if err := json.Unmarshal(object["files"], &fileEntries); err != nil || len(fileEntries) == 0 {
		return bsdPkgManifest{}, errors.New("pkg manifest has no file inventory")
	}
	files := make(map[string]bsdPkgFile, len(fileEntries))
	for installed, raw := range fileEntries {
		if !bsdSafeInstallPath(installed) {
			return bsdPkgManifest{}, fmt.Errorf("unsafe pkg manifest path %q", installed)
		}
		attrs, err := bsdPkgAttributes(raw, true, goos)
		if err != nil {
			return bsdPkgManifest{}, fmt.Errorf("pkg manifest file %q: %w", installed, err)
		}
		files[installed] = attrs
	}
	dirs := make(map[string]string)
	for _, key := range []string{"dirs", "directories"} {
		if len(object[key]) == 0 {
			continue
		}
		var listed map[string]json.RawMessage
		if json.Unmarshal(object[key], &listed) != nil {
			return bsdPkgManifest{}, fmt.Errorf("pkg manifest %s is invalid", key)
		}
		for dir, raw := range listed {
			if dir != "/usr/local/libexec/leaguebridge" && dir != "/usr/local/share/doc/leaguebridge" {
				return bsdPkgManifest{}, fmt.Errorf("pkg manifest owns unexpected directory %q", dir)
			}
			attrs, err := bsdPkgAttributes(raw, false, goos)
			if err != nil {
				return bsdPkgManifest{}, fmt.Errorf("pkg manifest directory %q has unreviewed attributes: %w", dir, err)
			}
			if attrs.mode != "0755" && !(goos == "dragonfly" && attrs.mode == "") {
				return bsdPkgManifest{}, fmt.Errorf("pkg manifest directory %q has unreviewed attributes", dir)
			}
			if _, duplicate := dirs[dir]; duplicate {
				return bsdPkgManifest{}, fmt.Errorf("duplicate pkg directory %q", dir)
			}
			dirs[dir] = attrs.mode
		}
	}
	if len(dirs) != 2 {
		return bsdPkgManifest{}, errors.New("pkg manifest omits one of the two owned directories")
	}
	return bsdPkgManifest{name: name, version: version, arch: arch, rawArch: archField, files: files, dirs: dirs}, nil
}

func bsdPkgAttributes(raw json.RawMessage, file bool, goos string) (bsdPkgFile, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		var value any
		if valueErr := json.Unmarshal(raw, &value); valueErr != nil {
			return bsdPkgFile{}, errors.New("attributes are invalid JSON")
		}
		if text, ok := value.(string); ok {
			if file && goos == "dragonfly" && bsdChecksumPattern.MatchString(text) {
				// DragonFly's pkg emits the legacy checksum-only files map.
				// Archive modes and the staged SHA-256 are verified separately.
				return bsdPkgFile{sum: text}, nil
			}
			if !file && goos == "dragonfly" && text == "y" {
				// DragonFly pkg uses a presence marker for directories; their
				// mode and ownership are checked from the package archive.
				return bsdPkgFile{}, nil
			}
			if len(text) > 128 {
				text = text[:128]
			}
			return bsdPkgFile{}, fmt.Errorf("attributes are a string (%q)", text)
		}
		return bsdPkgFile{}, fmt.Errorf("attributes are not an object (%T)", value)
	}
	if len(object) == 0 {
		return bsdPkgFile{}, errors.New("attributes are an empty object")
	}
	allowed := map[string]bool{"sum": file, "uname": true, "gname": true, "perm": true, "mtime": file}
	for key := range object {
		if !allowed[key] {
			return bsdPkgFile{}, fmt.Errorf("unreviewed attribute %q", key)
		}
	}
	var uname, gname, perm string
	if json.Unmarshal(object["uname"], &uname) != nil || uname != "root" ||
		json.Unmarshal(object["gname"], &gname) != nil || gname != "wheel" ||
		json.Unmarshal(object["perm"], &perm) != nil || (perm != "0644" && perm != "0755") {
		return bsdPkgFile{}, errors.New("unsafe package owner, group, or mode")
	}
	value := bsdPkgFile{mode: perm}
	if file {
		if json.Unmarshal(object["sum"], &value.sum) != nil || !bsdChecksumPattern.MatchString(value.sum) {
			return bsdPkgFile{}, errors.New("file checksum is missing or malformed")
		}
		if len(object["mtime"]) > 0 {
			var timestamp int64
			if json.Unmarshal(object["mtime"], &timestamp) != nil || timestamp < 0 {
				return bsdPkgFile{}, errors.New("file modification time is invalid")
			}
		}
	}
	return value, nil
}

func bsdMatchCompactManifest(data []byte, full bsdPkgManifest) error {
	if err := bsdRejectDuplicateJSON(data); err != nil {
		return err
	}
	var value map[string]json.RawMessage
	if json.Unmarshal(data, &value) != nil {
		return errors.New("pkg compact manifest is invalid")
	}
	for key, expected := range map[string]string{"name": full.name, "version": strings.TrimPrefix(full.version, "v"), "arch": full.rawArch} {
		var observed string
		if json.Unmarshal(value[key], &observed) != nil || observed != expected {
			return fmt.Errorf("pkg compact manifest %s conflicts with full manifest", key)
		}
	}
	return nil
}

func bsdFreeBSDArchitecture(value, goos string) (string, error) {
	if value == "" {
		return "", errors.New("pkg architecture is absent")
	}
	parts := strings.Split(value, ":")
	platform := "FreeBSD"
	if goos == "dragonfly" {
		platform = "DragonFly"
	}
	if len(parts) < 3 || !strings.EqualFold(parts[0], platform) || parts[1] == "" {
		return "", fmt.Errorf("pkg architecture %q does not identify %s", value, platform)
	}
	arch := strings.ToLower(strings.Join(parts[2:], ":"))
	switch arch {
	case "amd64", "x86:64":
		return "amd64", nil
	case "aarch64", "aarch64:64", "arm64":
		if goos == "freebsd" {
			return "aarch64", nil
		}
	}
	return "", fmt.Errorf("unsupported pkg architecture %q", value)
}

func bsdVersion(bare string) (string, error) {
	if len(bare) > 128 || strings.Contains(bare, "+") || !releaseversion.Valid("v"+bare) {
		return "", fmt.Errorf("BSD package version %q is invalid", bare)
	}
	return "v" + bare, nil
}

func bsdSafeInstallPath(value string) bool {
	return strings.HasPrefix(value, "/usr/local/") && path.Clean(value) == value &&
		!strings.ContainsAny(value, "\\\x00")
}

type bsdPacking struct {
	name  string
	arch  string
	files map[string]bsdPackingFile
}

type bsdPackingFile struct {
	mode    string
	sha     string
	size    int64
	hasSize bool
}

func bsdPackingList(data []byte, goos string) (bsdPacking, error) {
	result := bsdPacking{files: make(map[string]bsdPackingFile)}
	if len(data) == 0 || len(data) > int(bsdMaximumControl) || data[len(data)-1] != '\n' {
		return bsdPacking{}, errors.New("BSD packing list is invalid")
	}
	cwd := ""
	mode := ""
	last := ""
	ownerSeen := false
	groupSeen := false
	for lineNumber, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if line == "" || strings.ContainsRune(line, '\r') {
			return bsdPacking{}, fmt.Errorf("BSD packing list line %d is empty or malformed", lineNumber+1)
		}
		if !strings.HasPrefix(line, "@") {
			if cwd != "/usr/local" || (mode == "" && goos != "openbsd") {
				return bsdPacking{}, fmt.Errorf("BSD packing file line %d %q has no fixed install root or mode (cwd=%q mode=%q)", lineNumber+1, line, cwd, mode)
			}
			installed, err := bsdInstalledPath(line, false)
			if err != nil {
				return bsdPacking{}, err
			}
			if path.Clean(line) != line || strings.ContainsAny(line, "\\\x00") || result.files[installed].mode != "" {
				return bsdPacking{}, fmt.Errorf("unsafe or duplicate BSD packing path %q", line)
			}
			result.files[installed] = bsdPackingFile{mode: mode}
			last = installed
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		arg := ""
		if len(parts) == 2 {
			arg = parts[1]
		}
		switch parts[0] {
		case "@name":
			if result.name != "" || arg == "" {
				return bsdPacking{}, errors.New("duplicate or empty BSD package name")
			}
			result.name = arg
		case "@arch":
			if goos != "openbsd" || result.arch != "" || (arg != "amd64" && arg != "arm64") {
				return bsdPacking{}, errors.New("BSD package architecture is invalid")
			}
			result.arch = arg
		case "@cwd":
			if arg != "/usr/local" || (cwd != "" && cwd != arg) {
				return bsdPacking{}, fmt.Errorf("BSD package changes install root on line %d: current=%q requested=%q", lineNumber+1, cwd, arg)
			}
			cwd = arg
		case "@mode":
			if arg != "0755" && arg != "0644" {
				return bsdPacking{}, fmt.Errorf("unsafe BSD packing mode %q", arg)
			}
			mode = arg
		case "@owner":
			if ownerSeen || arg != "root" {
				return bsdPacking{}, errors.New("BSD package owner is not root")
			}
			ownerSeen = true
		case "@group":
			if groupSeen || arg != "wheel" {
				return bsdPacking{}, errors.New("BSD package group is not wheel")
			}
			groupSeen = true
		case "@sha":
			if goos != "openbsd" || last == "" {
				return bsdPacking{}, errors.New("OpenBSD checksum is misplaced")
			}
			hash, err := base64.StdEncoding.DecodeString(arg)
			file := result.files[last]
			if err != nil || len(hash) != sha256.Size || file.sha != "" {
				return bsdPacking{}, errors.New("OpenBSD checksum is invalid")
			}
			file.sha = hex.EncodeToString(hash)
			result.files[last] = file
		case "@size":
			if goos != "openbsd" || last == "" {
				return bsdPacking{}, errors.New("OpenBSD size is misplaced")
			}
			size, err := strconv.ParseInt(arg, 10, 64)
			file := result.files[last]
			if err != nil || size < 0 || file.hasSize {
				return bsdPacking{}, errors.New("OpenBSD size is invalid")
			}
			file.size, file.hasSize = size, true
			result.files[last] = file
		case "@ts":
			if goos != "openbsd" || last == "" || arg == "" {
				return bsdPacking{}, errors.New("OpenBSD timestamp is misplaced")
			}
		case "@comment":
			if goos == "openbsd" {
				if !strings.HasPrefix(arg, "pkgpath=sysutils/leaguebridge") {
					return bsdPacking{}, errors.New("unreviewed OpenBSD package comment")
				}
			} else if !strings.HasPrefix(arg, "MD5:") && !strings.HasPrefix(arg, "SHA1:") && !strings.HasPrefix(arg, "SHA256:") {
				return bsdPacking{}, errors.New("unreviewed NetBSD package comment")
			}
		default:
			return bsdPacking{}, fmt.Errorf("unreviewed BSD packing directive %q", parts[0])
		}
	}
	if result.name == "" || cwd != "/usr/local" || len(result.files) != 7 || !ownerSeen || !groupSeen ||
		(goos == "openbsd" && result.arch == "") {
		return bsdPacking{}, errors.New("BSD packing list has incomplete identity or payload inventory")
	}
	if goos == "openbsd" {
		for installed, file := range result.files {
			if file.sha == "" || !file.hasSize {
				return bsdPacking{}, fmt.Errorf("OpenBSD packing list omits digest or size for %q", installed)
			}
		}
	}
	return result, nil
}

func bsdSplitPackingArchive(entries []bsdEntry, allowed map[string]bool) (map[string][]byte, []bsdEntry, error) {
	if len(entries) == 0 || entries[0].name != "+CONTENTS" {
		return nil, nil, errors.New("BSD package must start with +CONTENTS")
	}
	controls := make(map[string][]byte)
	var payload []bsdEntry
	for _, entry := range entries {
		if strings.HasPrefix(entry.name, "+") {
			if !allowed[entry.name] || controls[entry.name] != nil || entry.typeflag != tar.TypeReg {
				return nil, nil, fmt.Errorf("unexpected BSD package control file %q", entry.name)
			}
			controls[entry.name] = entry.data
			continue
		}
		payload = append(payload, entry)
	}
	for name := range allowed {
		if controls[name] == nil {
			return nil, nil, fmt.Errorf("BSD package lacks %s", name)
		}
	}
	return controls, payload, nil
}

func bsdMatchPackingPayload(entries []bsdEntry, packing bsdPacking) ([]inspectedFile, error) {
	files := make(map[string]inspectedFile)
	for _, entry := range entries {
		installed, err := bsdInstalledPath(entry.name, false)
		if err != nil {
			return nil, err
		}
		if entry.typeflag == tar.TypeDir {
			return nil, fmt.Errorf("unreviewed BSD package directory %q", installed)
		}
		file, err := bsdInspectedRegular(entry, installed)
		if err != nil {
			return nil, err
		}
		listed, ok := packing.files[installed]
		if !ok || (listed.mode != "" && listed.mode != file.Mode) || (listed.sha != "" && listed.sha != file.SHA256) ||
			(listed.hasSize && listed.size != file.Size) {
			return nil, fmt.Errorf("BSD packing list does not bind payload %q", installed)
		}
		files[installed] = file
	}
	if len(files) != len(packing.files) {
		return nil, errors.New("BSD packing list and tar payload inventories differ")
	}
	return bsdSortedFiles(files), nil
}

func bsdNetBSDArchitecture(data []byte) (string, error) {
	fields := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" || fields[parts[0]] != "" {
			return "", errors.New("NetBSD +BUILD_INFO is invalid")
		}
		fields[parts[0]] = parts[1]
	}
	if len(fields) != 4 || fields["OPSYS"] != "NetBSD" || fields["OS_VERSION"] == "" || fields["PKGTOOLS_VERSION"] == "" {
		return "", errors.New("NetBSD build identity is incomplete")
	}
	switch fields["MACHINE_ARCH"] {
	case "x86_64":
		return "amd64", nil
	case "aarch64":
		return "aarch64", nil
	default:
		return "", fmt.Errorf("unsupported NetBSD machine architecture %q", fields["MACHINE_ARCH"])
	}
}

func bsdRejectDuplicateJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var visit func(int) error
	visit = func(depth int) error {
		if depth > 64 {
			return errors.New("JSON nesting exceeds the limit")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]bool)
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return fmt.Errorf("duplicate or invalid JSON key %q", name)
				}
				seen[name] = true
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		_, err = decoder.Token()
		return err
	}
	if err := visit(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON in package manifest")
	}
	return nil
}
