// Command ciartifact transports the fixed CI evidence inventory without losing
// executable modes in GitHub's ZIP artifact transport. This is an integrity
// container, not an attestation: consumers must still verify the signed files.
package main

import (
	"archive/tar"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Yunushan/leaguebridge/internal/fileinput"
)

const maxArchiveSize = 256 << 20

type member struct {
	name  string
	mode  int64
	limit int64
}

func main() {
	unpack := flag.Bool("unpack", false, "restore into a new root directory")
	root := flag.String("root", ".", "input root, or new output directory with -unpack")
	archive := flag.String("archive", "", "exclusive output tar, or input tar with -unpack")
	kind := flag.String("kind", "", "runtime or package")
	goos := flag.String("goos", "", "target operating system")
	goarch := flag.String("goarch", "", "target architecture")
	family := flag.String("family", "", "native package family (package only)")
	flag.Parse()
	members, err := inventory(*kind, *goos, *goarch, *family)
	if err == nil && (flag.NArg() != 0 || *archive == "" || *root == "") {
		err = errors.New("root, archive, and inventory flags are required; positional arguments are not accepted")
	}
	if err == nil {
		if *unpack {
			err = restore(*archive, *root, members)
		} else {
			err = pack(*root, *archive, members)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ciartifact:", err)
		os.Exit(2)
	}
}

func inventory(kind, goos, goarch, family string) ([]member, error) {
	if (goarch != "amd64" && goarch != "arm64") ||
		(goos != "linux" && goos != "freebsd" && goos != "openbsd" && goos != "netbsd" && goos != "dragonfly") ||
		(goos == "dragonfly" && goarch != "amd64") {
		return nil, errors.New("unsupported CI target")
	}
	var result []member
	add := func(name string, mode int64, limit int64) { result = append(result, member{name, mode, limit}) }
	switch kind {
	case "runtime":
		if family != "" {
			return nil, errors.New("runtime inventory does not accept a package family")
		}
		evidence, binary := "bsd-evidence/"+goos+"/"+goarch, "bsd-ci/leaguebridge-"+goos+"-"+goarch
		if goos == "linux" {
			evidence, binary = "linux-evidence/"+goarch, "ci-bin/leaguebridge-linux-"+goarch
		}
		add(binary, 0755, 128<<20)
		for _, name := range []string{"native-runtime.json", "kernel.txt", "version.json", "status.json", "readiness.json", "manifest-verify.json", "doctor.json", "result.txt", "install-lifecycle.txt"} {
			add(evidence+"/"+name, 0644, 8<<20)
		}
	case "package":
		base, prefix, filename := family, "usr/local", ""
		if goos != "linux" {
			base += "/" + goarch
		}
		switch {
		case goos == "linux" && goarch == "amd64" && family == "debian":
			prefix, filename = "usr", "leaguebridge_0.0.0~ci_amd64.deb"
		case goos == "linux" && goarch == "amd64" && family == "rpm":
			prefix, filename = "usr", "leaguebridge-0.0.0-1.ci.x86_64.rpm"
		case goos == "freebsd" && family == "freebsd-pkg", goos == "dragonfly" && family == "dports":
			filename = "leaguebridge-0.0.0-ci-" + goos + "-" + goarch + ".pkg"
		case goos == "openbsd" && family == "openbsd-pkg", goos == "netbsd" && family == "pkgsrc":
			filename = "leaguebridge-0.0.0-ci-" + goos + "-" + goarch + ".tgz"
		default:
			return nil, errors.New("package family does not match a CI package target")
		}
		add("native-package-output/"+base+"/"+filename, 0644, 128<<20)
		add("native-package-evidence/"+base+"/native-package.json", 0644, 1<<20)
		add("native-package-evidence/"+base+"/install.txt", 0644, 1<<20)
		staging := "native-package-staging/" + base
		add(staging+"/NATIVE-PACKAGE-MANIFEST.json", 0644, 1<<20)
		add(staging+"/root/"+prefix+"/bin/leaguebridge", 0755, 128<<20)
		for _, name := range []string{"linux-bsd-client-smoke.sh", "linux-bsd-remote-session.sh"} {
			add(staging+"/root/"+prefix+"/libexec/leaguebridge/"+name, 0755, 8<<20)
		}
		for _, name := range []string{"LICENSE", "README.md", "SBOM.spdx.json", "PACKAGE-MANIFEST.json"} {
			add(staging+"/root/"+prefix+"/share/doc/leaguebridge/"+name, 0644, 8<<20)
		}
	default:
		return nil, errors.New("kind must be runtime or package")
	}
	sort.Slice(result, func(i, j int) bool { return result[i].name < result[j].name })
	return result, nil
}

func encode(members []member, bodies map[string][]byte) ([]byte, error) {
	var output bytes.Buffer
	w := tar.NewWriter(&output)
	for _, item := range members {
		body := bodies[item.name]
		if int64(len(body)) > item.limit || output.Len()+len(body)+2048 > maxArchiveSize {
			return nil, errors.New("CI archive exceeds its size limit")
		}
		h := &tar.Header{Name: item.name, Mode: item.mode, Size: int64(len(body)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR, ModTime: time.Unix(0, 0).UTC()}
		if err := w.WriteHeader(h); err != nil {
			return nil, err
		}
		if _, err := w.Write(body); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func pack(root, archive string, members []member) error {
	bodies := make(map[string][]byte, len(members))
	var total int64
	for _, item := range members {
		input, err := fileinput.OpenDirectoryRoot(filepath.Join(root, filepath.FromSlash(path.Dir(item.name))))
		if err != nil {
			return err
		}
		body, err := fileinput.ReadRegularBoundedFromRoot(input, path.Base(item.name), item.limit)
		info, statErr := input.Lstat(path.Base(item.name))
		_ = input.Close()
		if err != nil {
			return fmt.Errorf("read %s: %w", item.name, err)
		}
		if statErr != nil {
			return statErr
		}
		if item.mode == 0755 && runtime.GOOS != "windows" && info.Mode().Perm()&0111 == 0 {
			return fmt.Errorf("input %s is not executable", item.name)
		}
		total += int64(len(body))
		if total > maxArchiveSize {
			return errors.New("CI archive exceeds its size limit")
		}
		bodies[item.name] = body
	}
	data, err := encode(members, bodies)
	if err != nil {
		return err
	}
	parent, err := fileinput.OpenDirectoryRoot(filepath.Dir(archive))
	if err != nil {
		return err
	}
	defer parent.Close()
	name := filepath.Base(archive)
	f, err := parent.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		_ = parent.Remove(name)
		return errors.Join(writeErr, closeErr)
	}
	return nil
}

func decode(data []byte, members []member) (map[string][]byte, error) {
	if len(data) > maxArchiveSize {
		return nil, errors.New("CI archive exceeds its size limit")
	}
	r := tar.NewReader(bytes.NewReader(data))
	bodies := make(map[string][]byte, len(members))
	for _, item := range members {
		h, err := r.Next()
		if err != nil {
			return nil, fmt.Errorf("read expected %s: %w", item.name, err)
		}
		if h.Name != item.name || h.Typeflag != tar.TypeReg || h.Mode != item.mode || h.Size < 0 || h.Size > item.limit || h.Linkname != "" {
			return nil, fmt.Errorf("invalid CI archive member %q; expected regular %s with mode %04o", h.Name, item.name, item.mode)
		}
		body, err := io.ReadAll(io.LimitReader(r, item.limit+1))
		if err != nil {
			return nil, err
		}
		if int64(len(body)) != h.Size {
			return nil, errors.New("truncated CI archive member")
		}
		bodies[item.name] = body
	}
	if _, err := r.Next(); err != io.EOF {
		return nil, errors.New("CI archive contains extra or malformed members")
	}
	canonical, err := encode(members, bodies)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(data, canonical) {
		return nil, errors.New("CI archive has noncanonical metadata, padding, or trailing data")
	}
	return bodies, nil
}

func restore(archive, destination string, members []member) error {
	input, err := fileinput.OpenDirectoryRoot(filepath.Dir(archive))
	if err != nil {
		return err
	}
	data, err := fileinput.ReadRegularBoundedFromRoot(input, filepath.Base(archive), maxArchiveSize)
	_ = input.Close()
	if err != nil {
		return err
	}
	bodies, err := decode(data, members)
	if err != nil {
		return err
	}
	absolute, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	parent, err := fileinput.OpenDirectoryRoot(filepath.Dir(absolute))
	if err != nil {
		return err
	}
	defer parent.Close()
	name := filepath.Base(absolute)
	if _, err := parent.Lstat(name); err == nil {
		return errors.New("restore destination already exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	output, temporary, err := fileinput.CreateTempDirectory(parent, ".ciartifact-", 0700)
	if err != nil {
		return err
	}
	defer func() { _ = output.Close(); _ = fileinput.RemoveAllInRoot(parent, temporary) }()
	for _, item := range members {
		current := ""
		for _, part := range strings.Split(path.Dir(item.name), "/") {
			current = path.Join(current, part)
			if err := output.Mkdir(filepath.FromSlash(current), 0755); err != nil && !os.IsExist(err) {
				return err
			}
		}
		f, err := output.OpenFile(filepath.FromSlash(item.name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(item.mode))
		if err != nil {
			return err
		}
		_, writeErr := f.Write(bodies[item.name])
		modeErr := f.Chmod(os.FileMode(item.mode))
		closeErr := f.Close()
		if err := errors.Join(writeErr, modeErr, closeErr); err != nil {
			return err
		}
	}
	if err := output.Close(); err != nil {
		return err
	}
	return fileinput.RenameInRoot(parent, temporary, name)
}
