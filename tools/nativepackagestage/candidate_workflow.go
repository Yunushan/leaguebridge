package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Yunushan/leaguebridge/internal/exactjson"
	"github.com/Yunushan/leaguebridge/internal/fileinput"
	"github.com/Yunushan/leaguebridge/internal/productionpackage"
	"github.com/Yunushan/leaguebridge/internal/releaseassessment"
)

// These commands prepare score-free package candidates. They do not define a
// publisher, package signing policy, repository index, or readiness evidence.
type candidateWorkflowOptions struct {
	command, version, releaseDir, inputs, packages, output, repo, checker, gh string
	disposableGuest                                                           bool
}

type candidateSetRecord struct {
	SchemaVersion   int                      `json:"schema_version"`
	RecordType      string                   `json:"record_type"`
	ValidationScope string                   `json:"validation_scope"`
	Release         releaseSetIdentity       `json:"release"`
	Cells           []candidateSetRecordCell `json:"cells"`
}

type candidateSetRecordCell struct {
	Family                string `json:"family"`
	GOOS                  string `json:"goos"`
	GOARCH                string `json:"goarch"`
	PackageFilename       string `json:"package_filename"`
	PackageSHA256         string `json:"package_sha256"`
	ArchiveSHA256         string `json:"archive_sha256"`
	ExecutableSHA256      string `json:"executable_sha256"`
	StagingManifestSHA256 string `json:"staging_manifest_sha256"`
}

func runCandidateWorkflow(ctx context.Context, args []string, stdout io.Writer) error {
	opts, err := parseCandidateWorkflow(args)
	if err != nil {
		return err
	}
	if opts.command == "candidate-host" {
		return buildHostCandidates(ctx, opts, stdout)
	}
	release, err := releaseassessment.VerifyForProduction(ctx, releaseSetRequest(releaseSetOptions{
		version: opts.version, releaseDir: opts.releaseDir, gh: opts.gh,
	}))
	if err != nil {
		return fmt.Errorf("authenticate live stable release: %w", err)
	}
	facts, err := factsFromVerifiedRelease(release)
	if err != nil {
		return err
	}
	if err := verifyReleaseSetInputs(ctx, facts, opts.releaseDir, opts.inputs); err != nil {
		return fmt.Errorf("verify release-set inputs: %w", err)
	}
	if err := release.Recheck(ctx); err != nil {
		return fmt.Errorf("recheck live release: %w", err)
	}
	switch opts.command {
	case "candidate-set":
		return verifyCandidateWorkflowSet(ctx, opts, release, facts, stdout)
	default:
		return errors.New("unknown candidate workflow command")
	}
}

func parseCandidateWorkflow(args []string) (candidateWorkflowOptions, error) {
	if len(args) == 0 || (args[0] != "candidate-host" && args[0] != "candidate-set") {
		return candidateWorkflowOptions{}, errors.New("expected candidate-host or candidate-set")
	}
	opts := candidateWorkflowOptions{command: args[0]}
	set := flag.NewFlagSet("nativepackagestage "+opts.command, flag.ContinueOnError)
	set.SetOutput(io.Discard)
	set.StringVar(&opts.version, "version", "", "published stable release tag")
	set.StringVar(&opts.releaseDir, "release-dir", "", "ten downloaded release files")
	set.StringVar(&opts.inputs, "inputs", "", "release-set staging directory")
	set.StringVar(&opts.packages, "packages", "", "merged package candidate directory")
	set.StringVar(&opts.output, "output", "", "new host directory or candidate-set record file")
	set.StringVar(&opts.repo, "repo", "", "trusted source checkout containing package smoke scripts")
	set.StringVar(&opts.checker, "version-checker", "", "BSD semantic-version checker executable")
	set.StringVar(&opts.gh, "gh", "gh", "trusted GitHub CLI executable")
	set.BoolVar(&opts.disposableGuest, "disposable-guest", false, "confirm BSD package install runs in a disposable guest")
	if err := set.Parse(args[1:]); err != nil {
		return candidateWorkflowOptions{}, err
	}
	if set.NArg() != 0 || !stableReleaseSetVersion(opts.version) ||
		blankReleaseSet(opts.releaseDir) || blankReleaseSet(opts.inputs) {
		return candidateWorkflowOptions{}, errors.New("stable --version, --release-dir, and --inputs are required")
	}
	if opts.command == "candidate-host" {
		if blankReleaseSet(opts.output) || blankReleaseSet(opts.repo) || opts.packages != "" {
			return candidateWorkflowOptions{}, errors.New("candidate-host requires --output NEW_DIR and --repo CHECKOUT and rejects --packages")
		}
	} else if blankReleaseSet(opts.packages) || blankReleaseSet(opts.gh) || blankReleaseSet(opts.output) || opts.repo != "" || opts.checker != "" || opts.disposableGuest {
		return candidateWorkflowOptions{}, errors.New("candidate-set requires --packages MERGED_DIR and --output NEW_RECORD and rejects host build options")
	}
	return opts, nil
}

// A release-set plan is an untrusted locator. Every field and staging tree is
// checked anew against the opaque live release before a builder consumes it.
func verifyReleaseSetInputs(ctx context.Context, facts releaseSetFacts, releaseDir, inputs string) error {
	assets, err := validateReleaseSetFacts(facts)
	if err != nil {
		return err
	}
	root, err := fileinput.OpenDirectoryRoot(inputs)
	if err != nil {
		return fmt.Errorf("open release-set root: %w", err)
	}
	defer root.Close()
	data, err := fileinput.ReadRegularBoundedFromRoot(root, releaseSetManifestName, 128<<10)
	if err != nil {
		return fmt.Errorf("read release-set plan: %w", err)
	}
	if err := exactjson.ValidateKeys(data, releaseSetManifest{}); err != nil {
		return fmt.Errorf("release-set plan keys: %w", err)
	}
	var plan releaseSetManifest
	if err := json.Unmarshal(data, &plan); err != nil {
		return fmt.Errorf("decode release-set plan: %w", err)
	}
	canonical, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(data, canonical) {
		return errors.New("release-set plan is not canonical")
	}
	if plan.SchemaVersion != 1 || plan.PlanType != "leaguebridge-release-bound-native-package-inputs" ||
		plan.ValidationScope != "release-bound-staging-only" ||
		plan.Release != (releaseSetIdentity{facts.version, facts.commit, facts.tree, facts.releaseID, facts.scorecardSHA256}) {
		return errors.New("release-set plan does not match the authenticated stable release")
	}
	cells := productionpackage.ExpectedCells()
	if len(cells) != 11 || len(plan.Cells) != len(cells) {
		return errors.New("release-set plan must contain exactly the fixed eleven cells")
	}
	releaseRoot, err := fileinput.OpenDirectoryRoot(releaseDir)
	if err != nil {
		return fmt.Errorf("open release asset directory: %w", err)
	}
	defer releaseRoot.Close()
	seenArchives := make(map[string]bool, 9)
	for i, cell := range cells {
		if err := ctx.Err(); err != nil {
			return err
		}
		got := plan.Cells[i]
		name := fmt.Sprintf("leaguebridge_%s_%s_%s.tar.gz", strings.TrimPrefix(facts.version, "v"), cell.GOOS, cell.GOARCH)
		asset, ok := assets[name]
		if !ok || got.Family != cell.Family || got.GOOS != cell.GOOS || got.GOARCH != cell.GOARCH ||
			got.ArchiveFilename != name || got.ArchiveSHA256 != asset.SHA256 || got.ArchiveSizeBytes != asset.SizeBytes ||
			got.StagingPath != path.Join(string(cell.Family), cell.GOARCH) || !releaseSetDigestPattern.MatchString(got.StagingManifestSHA256) ||
			got.PackageState != "unbuilt" || got.SigningState != "not_performed" ||
			got.PublicationState != "not_performed" || got.LifecycleState != "not_verified" {
			return fmt.Errorf("release-set cell %d differs from the authenticated release inventory", i)
		}
		if !seenArchives[name] {
			if err := checkReleaseSetArchive(releaseRoot, asset); err != nil {
				return fmt.Errorf("check %s: %w", name, err)
			}
			seenArchives[name] = true
		}
		digest := got.StagingManifestSHA256
		if err := verifyReleaseSetCell(ctx, root, facts.version, got, &digest); err != nil {
			return fmt.Errorf("verify staged %s: %w", got.StagingPath, err)
		}
	}
	if len(seenArchives) != 9 {
		return errors.New("release-set source archive inventory is incomplete")
	}
	return nil
}

// Local guest validation checks that the shipped archive and staging bytes
// agree with the supplied plan. The plan is untrusted here: only candidate-set
// later authenticates the published release and may use VerifiedRelease.
func localReleaseSetFacts(ctx context.Context, version, releaseDir, inputs string) (releaseSetFacts, error) {
	root, err := fileinput.OpenDirectoryRoot(inputs)
	if err != nil {
		return releaseSetFacts{}, err
	}
	defer root.Close()
	data, err := fileinput.ReadRegularBoundedFromRoot(root, releaseSetManifestName, 128<<10)
	if err != nil {
		return releaseSetFacts{}, err
	}
	if err := exactjson.ValidateKeys(data, releaseSetManifest{}); err != nil {
		return releaseSetFacts{}, err
	}
	var plan releaseSetManifest
	if err := json.Unmarshal(data, &plan); err != nil {
		return releaseSetFacts{}, err
	}
	if plan.Release.Version != version {
		return releaseSetFacts{}, errors.New("local release-set version differs from requested version")
	}
	facts := releaseSetFacts{
		version: version, commit: plan.Release.Commit, tree: plan.Release.Tree,
		scorecardSHA256: plan.Release.ScorecardSHA256, releaseID: plan.Release.ReleaseID,
	}
	seen := make(map[string]bool, 9)
	for _, cell := range plan.Cells {
		if !seen[cell.ArchiveFilename] {
			facts.assets = append(facts.assets, releaseassessment.PublishedAsset{
				Name: cell.ArchiveFilename, SHA256: cell.ArchiveSHA256, SizeBytes: cell.ArchiveSizeBytes,
			})
			seen[cell.ArchiveFilename] = true
		}
	}
	releaseRoot, err := fileinput.OpenDirectoryRoot(releaseDir)
	if err != nil {
		return releaseSetFacts{}, err
	}
	defer releaseRoot.Close()
	checksums, err := fileinput.ReadRegularBoundedFromRoot(releaseRoot, "checksums.txt", 1<<20)
	if err != nil {
		return releaseSetFacts{}, err
	}
	sum := sha256.Sum256(checksums)
	facts.assets = append(facts.assets, releaseassessment.PublishedAsset{
		Name: "checksums.txt", SHA256: hex.EncodeToString(sum[:]), SizeBytes: int64(len(checksums)),
	})
	if err := verifyReleaseSetInputs(ctx, facts, releaseDir, inputs); err != nil {
		return releaseSetFacts{}, err
	}
	return facts, nil
}

func nativeHostCells() ([]productionpackage.Cell, error) {
	var cells []productionpackage.Cell
	for _, cell := range productionpackage.ExpectedCells() {
		if cell.GOOS == runtime.GOOS && cell.GOARCH == runtime.GOARCH {
			cells = append(cells, cell)
		}
	}
	if len(cells) == 0 || (runtime.GOOS == "linux" && len(cells) != 2) || (runtime.GOOS != "linux" && len(cells) != 1) {
		return nil, fmt.Errorf("host %s/%s has no complete native package build cell", runtime.GOOS, runtime.GOARCH)
	}
	return cells, nil
}

func buildHostCandidates(ctx context.Context, opts candidateWorkflowOptions, stdout io.Writer) error {
	cells, err := nativeHostCells()
	if err != nil {
		return err
	}
	if runtime.GOOS != "linux" && !opts.disposableGuest {
		return errors.New("BSD package smoke installs under /usr/local; --disposable-guest is required")
	}
	repo, err := filepath.Abs(opts.repo)
	if err != nil {
		return err
	}
	scriptName := "native-package-bsd-smoke.sh"
	if runtime.GOOS == "linux" {
		scriptName = "native-package-linux-smoke.sh"
	}
	script := filepath.Join(repo, "scripts", scriptName)
	if err := fileinput.RejectSymlinkedParents(script); err != nil {
		return fmt.Errorf("trusted script path: %w", err)
	}
	info, err := os.Lstat(script)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("trusted native package builder script is not a regular file")
	}
	inputAbs, err := filepath.Abs(opts.inputs)
	if err != nil {
		return err
	}
	releaseAbs, err := filepath.Abs(opts.releaseDir)
	if err != nil {
		return err
	}
	outputAbs, err := filepath.Abs(opts.output)
	if err != nil {
		return err
	}
	if pathWithin(inputAbs, outputAbs) || pathWithin(releaseAbs, outputAbs) || pathWithin(repo, outputAbs) {
		return errors.New("host output must be outside release assets, release-set staging, and source checkout")
	}
	if err := fileinput.RejectSymlinkedParents(outputAbs); err != nil {
		return fmt.Errorf("output path: %w", err)
	}
	if _, err := localReleaseSetFacts(ctx, opts.version, releaseAbs, inputAbs); err != nil {
		return fmt.Errorf("check local release-set bytes (not live authentication): %w", err)
	}
	parent, err := fileinput.OpenDirectoryRoot(filepath.Dir(outputAbs))
	if err != nil {
		return fmt.Errorf("open host output parent: %w", err)
	}
	defer parent.Close()
	outputName := filepath.Base(outputAbs)
	if outputName == "" || outputName == "." || outputName == ".." || outputName == string(filepath.Separator) {
		return errors.New("host output must name a new child directory")
	}
	if _, err := parent.Lstat(outputName); err == nil {
		return errors.New("host output already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporaryRoot, temporaryName, err := fileinput.CreateTempDirectory(parent, ".leaguebridge-release-package-host-", 0o700)
	if err != nil {
		return fmt.Errorf("create private host output: %w", err)
	}
	defer temporaryRoot.Close()
	defer fileinput.RemoveAllInRoot(parent, temporaryName)
	temporaryInfo, err := parent.Lstat(temporaryName)
	if err != nil {
		return err
	}
	temporaryPath := filepath.Join(filepath.Dir(outputAbs), temporaryName)
	archive := filepath.Join(releaseAbs, fmt.Sprintf("leaguebridge_%s_%s_%s.tar.gz", strings.TrimPrefix(opts.version, "v"), runtime.GOOS, runtime.GOARCH))
	var command *exec.Cmd
	if runtime.GOOS == "linux" {
		command = exec.CommandContext(ctx, "bash", script, opts.version, archive, temporaryPath, inputAbs)
	} else {
		command = exec.CommandContext(ctx, "sh", script, opts.version, runtime.GOOS, string(cells[0].Family), opts.checker, inputAbs, temporaryPath)
	}
	command.Dir = repo
	command.Stdout = stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("native package builder and install smoke: %w", err)
	}
	if current, err := parent.Lstat(temporaryName); err != nil || !os.SameFile(temporaryInfo, current) {
		return errors.New("private host output directory changed while building")
	}
	if visible, err := os.Lstat(temporaryPath); err != nil || !os.SameFile(temporaryInfo, visible) {
		return errors.New("private host output path changed while building")
	}
	packagePaths, err := scanPackageTree(opts.version, temporaryPath, cells, true)
	if err != nil {
		return err
	}
	digests := make([]string, len(packagePaths))
	for i, packagePath := range packagePaths {
		digests[i], err = digestCandidatePackage(ctx, packagePath)
		if err != nil {
			return err
		}
	}
	if _, err := localReleaseSetFacts(ctx, opts.version, releaseAbs, inputAbs); err != nil {
		return fmt.Errorf("recheck local release-set bytes: %w", err)
	}
	if err := parent.Mkdir(outputName, 0o700); err != nil {
		return fmt.Errorf("reserve new host output: %w", err)
	}
	created, err := parent.Lstat(outputName)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			if current, err := parent.Lstat(outputName); err == nil && os.SameFile(created, current) {
				_ = fileinput.RemoveAllInRoot(parent, outputName)
			}
		}
	}()
	for _, name := range []string{"native-package-output", "native-package-evidence"} {
		if err := fileinput.RenameInRoot(parent, filepath.Join(temporaryName, name), filepath.Join(outputName, name)); err != nil {
			return fmt.Errorf("publish host %s: %w", name, err)
		}
	}
	if err := checkPublishedHostDirectory(parent, outputAbs, outputName, created); err != nil {
		return err
	}
	movedPaths, err := scanPackageTree(opts.version, outputAbs, cells, true)
	if err != nil {
		return err
	}
	for i, packagePath := range movedPaths {
		got, err := digestCandidatePackage(ctx, packagePath)
		if err != nil {
			return err
		}
		if got != digests[i] {
			return fmt.Errorf("moved package %s changed bytes", packagePath)
		}
	}
	if _, err := localReleaseSetFacts(ctx, opts.version, releaseAbs, inputAbs); err != nil {
		return err
	}
	if err := checkPublishedHostDirectory(parent, outputAbs, outputName, created); err != nil {
		return err
	}
	finalRoot, err := parent.OpenRoot(outputName)
	if err != nil {
		return err
	}
	marker, err := finalRoot.OpenFile("CANDIDATE-HOST-COMPLETE.txt", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		_, err = marker.Write([]byte("local score-free package bytes; live release, publisher signatures, and publication unverified\n"))
		if closeErr := marker.Close(); err == nil {
			err = closeErr
		}
	}
	_ = finalRoot.Close()
	if err != nil {
		return err
	}
	if err := checkPublishedHostDirectory(parent, outputAbs, outputName, created); err != nil {
		return err
	}
	complete = true
	_, err = fmt.Fprintf(stdout, "created locally checked score-free host package bytes in %s (%s/%s); live release unverified\n", outputAbs, runtime.GOOS, runtime.GOARCH)
	return err
}

func checkPublishedHostDirectory(parent *os.Root, absolute, name string, created os.FileInfo) error {
	current, err := parent.Lstat(name)
	if err != nil || !current.IsDir() || !os.SameFile(created, current) {
		return errors.New("reserved host output directory changed")
	}
	visible, err := os.Lstat(absolute)
	if err != nil || !os.SameFile(created, visible) {
		return errors.New("host output path no longer names the reserved directory")
	}
	return nil
}

func verifyCandidateWorkflowSet(ctx context.Context, opts candidateWorkflowOptions, release releaseassessment.VerifiedRelease, facts releaseSetFacts, stdout io.Writer) error {
	root, err := filepath.Abs(opts.packages)
	if err != nil {
		return err
	}
	releaseDir, err := filepath.Abs(opts.releaseDir)
	if err != nil {
		return err
	}
	inputRoot, err := filepath.Abs(opts.inputs)
	if err != nil {
		return err
	}
	output, err := filepath.Abs(opts.output)
	if err != nil {
		return err
	}
	if pathWithin(root, releaseDir) || pathWithin(root, inputRoot) || pathWithin(releaseDir, root) || pathWithin(inputRoot, root) {
		return errors.New("package bytes, release assets, and release-set inputs must be separate trees")
	}
	if pathWithin(root, output) || pathWithin(releaseDir, output) || pathWithin(inputRoot, output) {
		return errors.New("candidate-set record must be outside package, release, and staging trees")
	}
	cells := productionpackage.ExpectedCells()
	if len(cells) != 11 {
		return errors.New("production package inventory no longer has exactly eleven cells")
	}
	if _, err := scanPackageTree(opts.version, root, cells, false); err != nil {
		return err
	}
	candidateRoot, err := os.MkdirTemp("", "leaguebridge-candidate-set-")
	if err != nil {
		return fmt.Errorf("create private candidate metadata root: %w", err)
	}
	defer os.RemoveAll(candidateRoot)
	inputs, err := candidatePaths(opts.version, releaseDir, inputRoot, root, candidateRoot, cells)
	if err != nil {
		return err
	}
	for _, input := range inputs {
		if err := writeAggregateCandidate(ctx, release, input); err != nil {
			return fmt.Errorf("derive native package candidate %s: %w", input.PackagePath, err)
		}
	}
	set, err := productionpackage.VerifyPayloadSet(ctx, release, inputs)
	if err != nil {
		return fmt.Errorf("verify eleven native package payloads: %w", err)
	}
	summaries, err := set.Summaries()
	if err != nil {
		return err
	}
	record, err := marshalCandidateSetRecord(facts, summaries)
	if err != nil {
		return err
	}
	checkLocal := func() error {
		if err := verifyReleaseSetInputs(ctx, facts, releaseDir, inputRoot); err != nil {
			return fmt.Errorf("release-set recheck: %w", err)
		}
		if err := recheckCandidateDigests(ctx, release, inputs); err != nil {
			return fmt.Errorf("eleven package digests: %w", err)
		}
		if _, err := scanPackageTree(opts.version, root, cells, false); err != nil {
			return fmt.Errorf("exact package tree: %w", err)
		}
		return nil
	}
	recheck := func() error {
		if err := checkLocal(); err != nil {
			return err
		}
		if err := release.Recheck(ctx); err != nil {
			return fmt.Errorf("live release recheck: %w", err)
		}
		// The release request can take minutes; reject package or staging
		// changes that occur while it runs before accepting the record.
		return checkLocal()
	}
	if err := publishCandidateSetRecord(output, record, recheck); err != nil {
		return err
	}
	for _, summary := range summaries {
		if _, err := fmt.Fprintf(stdout, "%s/%s %s %s sha256:%s\n", summary.GOOS, summary.GOARCH, summary.Family, summary.PackageFilename, summary.PackageSHA256); err != nil {
			return err
		}
	}
	hash := sha256.Sum256(record)
	_, err = fmt.Fprintf(stdout, "verified eleven release-bound native package payloads; score-free, unsigned and unpublished\nrecord: %s\nrecord sha256: %s\n", output, hex.EncodeToString(hash[:]))
	return err
}

func marshalCandidateSetRecord(facts releaseSetFacts, summaries []productionpackage.Summary) ([]byte, error) {
	cells := productionpackage.ExpectedCells()
	if len(cells) != 11 || len(summaries) != len(cells) {
		return nil, errors.New("complete eleven-cell summary is required")
	}
	record := candidateSetRecord{
		SchemaVersion: 1, RecordType: "leaguebridge.native-package-candidate-set.v1",
		ValidationScope: "candidate-payload-integrity-only",
		Release:         releaseSetIdentity{facts.version, facts.commit, facts.tree, facts.releaseID, facts.scorecardSHA256},
		Cells:           make([]candidateSetRecordCell, 0, len(cells)),
	}
	for i, summary := range summaries {
		cell := cells[i]
		if summary.Version != facts.version || summary.Commit != facts.commit || summary.Tree != facts.tree ||
			summary.ReleaseID != facts.releaseID || summary.Family != cell.Family || summary.GOOS != cell.GOOS || summary.GOARCH != cell.GOARCH ||
			!releaseSetDigestPattern.MatchString(summary.PackageSHA256) || !releaseSetDigestPattern.MatchString(summary.ArchiveSHA256) ||
			!releaseSetDigestPattern.MatchString(summary.ExecutableSHA256) || !releaseSetDigestPattern.MatchString(summary.StagingManifestSHA256) {
			return nil, fmt.Errorf("candidate set summary %d differs from authenticated fixed inventory", i)
		}
		record.Cells = append(record.Cells, candidateSetRecordCell{
			Family: string(summary.Family), GOOS: summary.GOOS, GOARCH: summary.GOARCH,
			PackageFilename: summary.PackageFilename, PackageSHA256: summary.PackageSHA256,
			ArchiveSHA256: summary.ArchiveSHA256, ExecutableSHA256: summary.ExecutableSHA256,
			StagingManifestSHA256: summary.StagingManifestSHA256,
		})
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func publishCandidateSetRecord(output string, data []byte, recheck func() error) error {
	if len(data) == 0 || recheck == nil {
		return errors.New("candidate-set record and live recheck are required")
	}
	if err := fileinput.RejectSymlinkedParents(output); err != nil {
		return fmt.Errorf("record output path: %w", err)
	}
	parent, err := fileinput.OpenDirectoryRoot(filepath.Dir(output))
	if err != nil {
		return fmt.Errorf("open candidate-set record parent: %w", err)
	}
	defer parent.Close()
	name := filepath.Base(output)
	if name == "" || name == "." || name == ".." || name == string(filepath.Separator) {
		return errors.New("record output must name a new regular file")
	}
	if _, err := parent.Lstat(name); err == nil {
		return errors.New("candidate-set record already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, temporary, err := fileinput.CreateTempFile(parent, ".leaguebridge-candidate-set-", 0o600)
	if err != nil {
		return fmt.Errorf("create private candidate-set record: %w", err)
	}
	defer parent.Remove(temporary)
	if n, err := file.Write(data); err != nil || n != len(data) {
		_ = file.Close()
		return errors.New("write complete candidate-set record")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	created, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := recheck(); err != nil {
		return fmt.Errorf("prepublication candidate-set recheck: %w", err)
	}
	if err := checkCandidateSetRecordBytes(parent, temporary, created, data); err != nil {
		return err
	}
	if err := fileinput.LinkInRoot(parent, temporary, name); err != nil {
		return fmt.Errorf("publish candidate-set record exclusively: %w", err)
	}
	complete := false
	defer func() {
		if !complete {
			if current, err := parent.Lstat(name); err == nil && os.SameFile(created, current) {
				_ = parent.Remove(name)
			}
		}
	}()
	if err := checkCandidateSetRecordBytes(parent, name, created, data); err != nil {
		return err
	}
	if err := recheck(); err != nil {
		return fmt.Errorf("postpublication candidate-set recheck: %w", err)
	}
	if err := checkCandidateSetRecordBytes(parent, name, created, data); err != nil {
		return err
	}
	visible, err := os.Lstat(output)
	if err != nil || !os.SameFile(created, visible) {
		return errors.New("candidate-set record path changed after publication")
	}
	complete = true
	return nil
}

func checkCandidateSetRecordBytes(parent *os.Root, name string, created os.FileInfo, want []byte) error {
	current, err := parent.Lstat(name)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(created, current) || current.Size() != int64(len(want)) {
		return errors.New("candidate-set record identity or size changed")
	}
	data, err := fileinput.ReadRegularBoundedFromRoot(parent, name, int64(len(want)))
	if err != nil || !bytes.Equal(data, want) {
		return errors.New("candidate-set record bytes changed")
	}
	return nil
}

func candidatePaths(version, releaseDir, inputRoot, packageRoot, candidateRoot string, cells []productionpackage.Cell) ([]productionpackage.CandidatePaths, error) {
	paths := make([]productionpackage.CandidatePaths, 0, len(cells))
	for _, cell := range cells {
		name, err := productionpackage.ExpectedPackageFilename(version, cell.Family, cell.GOOS, cell.GOARCH)
		if err != nil {
			return nil, err
		}
		archive := fmt.Sprintf("leaguebridge_%s_%s_%s.tar.gz", strings.TrimPrefix(version, "v"), cell.GOOS, cell.GOARCH)
		paths = append(paths, productionpackage.CandidatePaths{
			CandidatePath: filepath.Join(candidateRoot, "native-package-candidate", string(cell.Family), cell.GOARCH, "candidate.json"),
			ArchivePath:   filepath.Join(releaseDir, archive),
			StagingDir:    filepath.Join(inputRoot, string(cell.Family), cell.GOARCH),
			PackagePath:   filepath.Join(packageRoot, "native-package-output", string(cell.Family), cell.GOARCH, name),
		})
	}
	return paths, nil
}

// scanPackageTree enforces that the package subtree holds one regular native
// archive for each requested cell, with no aliases, symlinks, or extra files.
// The aggregate caller supplies all eleven fixed cells.
func scanPackageTree(version, packageRoot string, cells []productionpackage.Cell, hostOutput bool) ([]string, error) {
	root, err := fileinput.OpenDirectoryRoot(packageRoot)
	if err != nil {
		return nil, fmt.Errorf("open package root: %w", err)
	}
	defer root.Close()
	entries, err := os.ReadDir(packageRoot)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.Name() == "native-package-output" && entry.IsDir() {
			continue
		}
		if hostOutput && entry.Name() == "native-package-evidence" && entry.IsDir() {
			continue
		}
		if hostOutput && entry.Name() == "CANDIDATE-HOST-COMPLETE.txt" && entry.Type().IsRegular() {
			continue
		}
		return nil, fmt.Errorf("unexpected package root entry %q", entry.Name())
	}
	paths := make([]string, 0, len(cells))
	allowed := make(map[string]bool, len(cells)*4)
	allowed["native-package-output"] = true
	for _, cell := range cells {
		name, err := productionpackage.ExpectedPackageFilename(version, cell.Family, cell.GOOS, cell.GOARCH)
		if err != nil {
			return nil, err
		}
		relative := filepath.Join("native-package-output", string(cell.Family), cell.GOARCH, name)
		for part := relative; part != "."; part = filepath.Dir(part) {
			allowed[part] = true
		}
		paths = append(paths, filepath.Join(packageRoot, relative))
	}
	if err := filepath.WalkDir(filepath.Join(packageRoot, "native-package-output"), func(full string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(packageRoot, full)
		if err != nil || !allowed[relative] {
			return fmt.Errorf("unexpected package tree path %q", relative)
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("package tree contains symlink %q", relative)
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("package tree contains non-regular file %q", relative)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	for _, packagePath := range paths {
		parent, err := fileinput.OpenDirectoryRoot(filepath.Dir(packagePath))
		if err != nil {
			return nil, err
		}
		info, statErr := parent.Lstat(filepath.Base(packagePath))
		_ = parent.Close()
		if statErr != nil || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("required native package %s is missing or not regular", packagePath)
		}
	}
	if hostOutput {
		allowedEvidence := map[string]bool{"native-package-evidence": true}
		for _, cell := range cells {
			relative := filepath.Join("native-package-evidence", string(cell.Family), cell.GOARCH, "install.txt")
			for part := relative; part != "."; part = filepath.Dir(part) {
				allowedEvidence[part] = true
			}
		}
		if err := filepath.WalkDir(filepath.Join(packageRoot, "native-package-evidence"), func(full string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			relative, err := filepath.Rel(packageRoot, full)
			if err != nil || !allowedEvidence[relative] {
				return fmt.Errorf("unexpected host evidence path %q", relative)
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("host evidence contains symlink %q", relative)
			}
			if entry.IsDir() {
				return nil
			}
			if !entry.Type().IsRegular() {
				return fmt.Errorf("host evidence contains non-regular file %q", relative)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		for _, cell := range cells {
			name := filepath.Join(packageRoot, "native-package-evidence", string(cell.Family), cell.GOARCH, "install.txt")
			parent, err := fileinput.OpenDirectoryRoot(filepath.Dir(name))
			if err != nil {
				return nil, err
			}
			info, statErr := parent.Lstat(filepath.Base(name))
			_ = parent.Close()
			if statErr != nil || !info.Mode().IsRegular() {
				return nil, fmt.Errorf("required host install log %s is missing or not regular", name)
			}
		}
	}
	return paths, nil
}

func writeAggregateCandidate(ctx context.Context, release releaseassessment.VerifiedRelease, input productionpackage.CandidatePaths) error {
	data, err := productionpackage.Build(ctx, release, input.ArchivePath, input.StagingDir, input.PackagePath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(input.CandidatePath), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(input.CandidatePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if n, err := file.Write(data); err != nil || n != len(data) {
		_ = file.Close()
		return errors.New("write complete candidate metadata")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	_, err = productionpackage.Verify(ctx, release, input.CandidatePath, input.ArchivePath, input.StagingDir, input.PackagePath)
	return err
}

func digestCandidatePackage(ctx context.Context, path string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	parent, err := fileinput.OpenDirectoryRoot(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	defer parent.Close()
	data, err := fileinput.ReadRegularBoundedFromRoot(parent, filepath.Base(path), 256<<20)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func recheckCandidateDigests(ctx context.Context, release releaseassessment.VerifiedRelease, inputs []productionpackage.CandidatePaths) error {
	for _, input := range inputs {
		verified, err := productionpackage.Verify(ctx, release, input.CandidatePath, input.ArchivePath, input.StagingDir, input.PackagePath)
		if err != nil {
			return err
		}
		summary, err := verified.Summary()
		if err != nil {
			return err
		}
		got, err := digestCandidatePackage(ctx, input.PackagePath)
		if err != nil {
			return err
		}
		if got != summary.PackageSHA256 {
			return fmt.Errorf("package %s changed after candidate verification", input.PackagePath)
		}
	}
	return nil
}
