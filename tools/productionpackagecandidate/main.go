// Command productionpackagecandidate builds or verifies score-free native
// package candidate metadata against a named, live-verified published release.
// Run it from the downloaded CI evidence directory.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Yunushan/leaguebridge/internal/fileinput"
	"github.com/Yunushan/leaguebridge/internal/productionpackage"
	"github.com/Yunushan/leaguebridge/internal/releaseassessment"
	"github.com/Yunushan/leaguebridge/internal/releaseversion"
	"github.com/Yunushan/leaguebridge/internal/target"
)

type options struct {
	command, version, releaseDir, archive, staging, packagePath, output, candidate, gh string
}

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "productionpackagecandidate: %v\n", err)
		os.Exit(2)
	}
}

func run(ctx context.Context, args []string, stdout io.Writer) error {
	opts, err := parse(args)
	if err != nil {
		return err
	}
	release, err := releaseassessment.VerifyForProduction(ctx, releaseRequest(opts))
	if err != nil {
		return fmt.Errorf("live release verification: %w", err)
	}
	switch opts.command {
	case "build":
		data, err := productionpackage.Build(ctx, release, opts.archive, opts.staging, opts.packagePath)
		if err != nil {
			return fmt.Errorf("build package candidate: %w", err)
		}
		if err := publishNewCandidate(opts.output, data, func(temporaryPath string) error {
			if _, err := productionpackage.Verify(ctx, release, temporaryPath, opts.archive, opts.staging, opts.packagePath); err != nil {
				return fmt.Errorf("rederive freshly built candidate: %w", err)
			}
			return release.Recheck(ctx)
		}); err != nil {
			return fmt.Errorf("publish package candidate: %w", err)
		}
		hash := sha256.Sum256(data)
		_, err = fmt.Fprintf(stdout, "created score-free production package candidate %s\nsha256: %s\n", opts.output, hex.EncodeToString(hash[:]))
		return err
	case "verify":
		matched, err := productionpackage.Verify(ctx, release, opts.candidate, opts.archive, opts.staging, opts.packagePath)
		if err != nil {
			return fmt.Errorf("verify package candidate: %w", err)
		}
		if err := release.Recheck(ctx); err != nil {
			return fmt.Errorf("recheck live release: %w", err)
		}
		summary, err := matched.Summary()
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "verified score-free production package candidate %s\nrelease: %s (%s)\npackage: %s/%s %s %s\npackage sha256: %s\ncandidate sha256: %s\n", opts.candidate, summary.Version, summary.Commit, summary.GOOS, summary.GOARCH, summary.Family, summary.PackageFilename, summary.PackageSHA256, summary.CandidateSHA256)
		return err
	default:
		return errors.New("expected build or verify command")
	}
}

func parse(args []string) (options, error) {
	if len(args) == 0 || (args[0] != "build" && args[0] != "verify") {
		return options{}, errors.New("usage: productionpackagecandidate build|verify --version TAG --release-dir DIR --archive FILE --staging DIR --package FILE [--output NEW_FILE | --candidate FILE] [--gh TRUSTED_GH]; run from the downloaded CI evidence directory")
	}
	opts := options{command: args[0]}
	set := flag.NewFlagSet("productionpackagecandidate "+opts.command, flag.ContinueOnError)
	set.SetOutput(io.Discard)
	set.StringVar(&opts.version, "version", "", "published stable release tag")
	set.StringVar(&opts.releaseDir, "release-dir", "", "directory containing ten downloaded release files")
	set.StringVar(&opts.archive, "archive", "", "published source archive for the package target")
	set.StringVar(&opts.staging, "staging", "", "complete native package staging tree")
	set.StringVar(&opts.packagePath, "package", "", "native package candidate bytes")
	set.StringVar(&opts.output, "output", "", "new candidate metadata path (build only)")
	set.StringVar(&opts.candidate, "candidate", "", "existing candidate metadata path (verify only)")
	set.StringVar(&opts.gh, "gh", "gh", "trusted GitHub CLI executable")
	if err := set.Parse(args[1:]); err != nil {
		return options{}, err
	}
	if set.NArg() != 0 {
		return options{}, errors.New("positional arguments are not accepted")
	}
	if !releaseversion.Valid(opts.version) || strings.ContainsAny(opts.version, "+-") ||
		blank(opts.releaseDir) || blank(opts.archive) || blank(opts.staging) || blank(opts.packagePath) || blank(opts.gh) {
		return options{}, errors.New("stable --version TAG, --release-dir DIR, --archive FILE, --staging DIR, --package FILE, and trusted --gh are required")
	}
	if opts.command == "build" && (blank(opts.output) || opts.candidate != "") {
		return options{}, errors.New("build requires --output NEW_FILE and rejects --candidate")
	}
	if opts.command == "verify" && (blank(opts.candidate) || opts.output != "") {
		return options{}, errors.New("verify requires --candidate FILE and rejects --output")
	}
	return opts, nil
}

func blank(value string) bool { return strings.TrimSpace(value) == "" }

// Keep the exact CI subject selection used by readiness verify-production.
// Subject paths are interpreted relative to the process working directory.
func releaseRequest(opts options) releaseassessment.Request {
	request := releaseassessment.Request{
		GHPath: opts.gh, Version: opts.version, ReleaseDir: opts.releaseDir,
		RaceVetSubject: "ci-attestation/race-vet-linux.json",
	}
	for _, candidate := range target.Ordered() {
		request.CrossBuildSubjects = append(request.CrossBuildSubjects,
			"ci-attestation/cross-build-"+candidate.GOOS+"-"+candidate.GOARCH+".json")
	}
	return request
}

// publishNewCandidate writes a complete private temporary file, checks its
// current package inputs and mutable release, then links it into place
// exclusively and atomically. A
// preexisting output is never replaced, including a preexisting symlink.
func publishNewCandidate(output string, data []byte, beforePublish func(string) error) (returnErr error) {
	if blank(output) || len(data) == 0 || beforePublish == nil {
		return errors.New("output path, candidate bytes, and prepublication check are required")
	}
	absolute, err := filepath.Abs(output)
	if err != nil {
		return fmt.Errorf("resolve output: %w", err)
	}
	if err := fileinput.RejectSymlinkedParents(absolute); err != nil {
		return fmt.Errorf("output path: %w", err)
	}
	name := filepath.Base(absolute)
	if name == "" || name == "." || name == ".." || name == string(filepath.Separator) {
		return errors.New("output must name a regular child file")
	}
	parent, err := fileinput.OpenDirectoryRoot(filepath.Dir(absolute))
	if err != nil {
		return fmt.Errorf("open output parent: %w", err)
	}
	defer parent.Close()
	file, temporary, err := fileinput.CreateTempFile(parent, ".leaguebridge-package-candidate-", 0o600)
	if err != nil {
		return fmt.Errorf("create temporary candidate: %w", err)
	}
	defer parent.Remove(temporary)
	if written, err := file.Write(data); err != nil || written != len(data) {
		_ = file.Close()
		if err != nil {
			return fmt.Errorf("write temporary candidate: %w", err)
		}
		return fmt.Errorf("write temporary candidate: %w", io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync temporary candidate: %w", err)
	}
	created, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("inspect temporary candidate: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary candidate: %w", err)
	}
	if err := beforePublish(filepath.Join(filepath.Dir(absolute), temporary)); err != nil {
		return fmt.Errorf("check package and live release before candidate publication: %w", err)
	}
	// A second process with directory write access can replace a path while
	// the live release check runs. Match the original file identity and bytes
	// immediately before linking, then inspect the linked output as well.
	if err := checkCandidateBytes(parent, temporary, created, data); err != nil {
		return fmt.Errorf("temporary candidate changed before publication: %w", err)
	}
	if err := fileinput.LinkInRoot(parent, temporary, name); err != nil {
		return fmt.Errorf("link new candidate exclusively: %w", err)
	}
	if err := checkCandidateBytes(parent, name, created, data); err != nil {
		// Remove only the link to the file we created. A concurrently replaced
		// output may belong to another writer and must not be removed here.
		if current, statErr := parent.Lstat(name); statErr == nil && os.SameFile(created, current) {
			_ = parent.Remove(name)
		}
		return fmt.Errorf("published candidate changed: %w", err)
	}
	return nil
}

func checkCandidateBytes(parent *os.Root, name string, created os.FileInfo, want []byte) error {
	current, err := parent.Lstat(name)
	if err != nil {
		return err
	}
	if !current.Mode().IsRegular() || current.Size() != int64(len(want)) || !os.SameFile(created, current) {
		return errors.New("candidate file identity or size changed")
	}
	data, err := fileinput.ReadRegularBoundedFromRoot(parent, name, int64(len(want)))
	if err != nil {
		return err
	}
	if !bytes.Equal(data, want) {
		return errors.New("candidate file content changed")
	}
	return nil
}
