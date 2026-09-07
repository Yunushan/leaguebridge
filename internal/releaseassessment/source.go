package releaseassessment

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Yunushan/leaguebridge/internal/readiness"
)

const (
	supportedCIWorkflow      = "deb4351ce333350397d1bc0a08732dcab869325e6c94c53d87d321a76b1ed0e9"
	supportedReleaseWorkflow = "c3865515e0e015f3a2cc835c66101a4883ee2e484533af0086091ececfe082d1"
	// This exact released v3 policy predates the current verifier's source-file
	// inventory. The pin approves policy bytes only, never execution evidence.
	// Its repository baseline is earned only after checking every source blob.
	reviewedHistoricalPolicy = "bc8294b9ee974e76305916ceb72d5655eb6b148e828dd9c7f8c42a2711069945"
	scorecardPath            = "internal/readiness/data/scorecard.json"
	maximumTreeEntries       = 2000
	maximumEvidenceFiles     = 512
)

var objectIDPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type sourceIdentity struct {
	Commit, Tree string
	Epoch        int64
}
type gitObject struct {
	SHA  string `json:"sha"`
	Type string `json:"type"`
}
type gitReference struct {
	Ref    string    `json:"ref"`
	Object gitObject `json:"object"`
}
type gitTag struct {
	SHA    string    `json:"sha"`
	Tag    string    `json:"tag"`
	Object gitObject `json:"object"`
}
type gitCommit struct {
	SHA       string    `json:"sha"`
	Tree      gitObject `json:"tree"`
	Committer struct {
		Date time.Time `json:"date"`
	} `json:"committer"`
}
type gitEntry struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
}
type gitTree struct {
	SHA       string     `json:"sha"`
	Truncated *bool      `json:"truncated"`
	Entries   []gitEntry `json:"tree"`
}
type gitBlob struct {
	SHA      string `json:"sha"`
	Encoding string `json:"encoding"`
	Size     int64  `json:"size"`
	Content  string `json:"content"`
}

func resolveCommit(ctx context.Context, api apiClient, commit string) (sourceIdentity, error) {
	if !objectIDPattern.MatchString(commit) {
		return sourceIdentity{}, errors.New("release tag does not identify an exact Git commit")
	}
	var object gitCommit
	if err := api(ctx, "repos/"+repository+"/git/commits/"+commit, &object); err != nil {
		return sourceIdentity{}, stageFailure(ctx, "read release source commit", err)
	}
	if object.SHA != commit || !objectIDPattern.MatchString(object.Tree.SHA) || len(object.Tree.SHA) != len(commit) || object.Committer.Date.IsZero() || object.Committer.Date.Unix() <= 0 {
		return sourceIdentity{}, errors.New("release commit source tree or timestamp is inconsistent")
	}
	return sourceIdentity{commit, object.Tree.SHA, object.Committer.Date.Unix()}, nil
}

func resolveSource(ctx context.Context, api apiClient, commit string, now time.Time) (sourceIdentity, []byte, readiness.Scorecard, error) {
	source, err := resolveCommit(ctx, api, commit)
	if err != nil {
		return sourceIdentity{}, nil, readiness.Scorecard{}, err
	}
	reader := sourceReader{api: api, tree: source.Tree, trees: make(map[string]map[string]gitEntry)}
	for _, definition := range []struct{ path, digest string }{{ciWorkflow, supportedCIWorkflow}, {releaseWorkflow, supportedReleaseWorkflow}} {
		data, err := reader.readFile(ctx, definition.path, 256<<10)
		if err != nil {
			return sourceIdentity{}, nil, readiness.Scorecard{}, err
		}
		if digestBytes(data) != definition.digest {
			return sourceIdentity{}, nil, readiness.Scorecard{}, errors.New("release source workflow is unsupported; review its exact definition before assessment")
		}
	}
	data, err := reader.readFile(ctx, scorecardPath, readiness.MaximumScorecardSize)
	if err != nil {
		return sourceIdentity{}, nil, readiness.Scorecard{}, err
	}
	card, err := parseReleasedPolicy(data, now)
	if err != nil {
		return sourceIdentity{}, nil, readiness.Scorecard{}, stageFailure(ctx, "released scorecard policy", err)
	}
	if err := reader.verifyEvidence(ctx, card); err != nil {
		return sourceIdentity{}, nil, readiness.Scorecard{}, err
	}
	return source, data, card, nil
}

// The immutable historical policy pin authorizes only that exact already
// reviewed contract. Different bytes must satisfy today's full ParseAt contract;
// malformed or adjusted historical dates/weights never inherit the exception.
func parseReleasedPolicy(data []byte, now time.Time) (readiness.Scorecard, error) {
	if digestBytes(data) != reviewedHistoricalPolicy {
		return readiness.ParseAt(data, now)
	}
	var card readiness.Scorecard
	if err := json.Unmarshal(data, &card); err != nil {
		return readiness.Scorecard{}, errors.New("reviewed historical policy decoding failed")
	}
	if err := validatePolicyTime(card, now); err != nil {
		return readiness.Scorecard{}, err
	}
	return card, nil
}

func validatePolicyTime(card readiness.Scorecard, now time.Time) error {
	if now.IsZero() || card.AssessedAt.IsZero() || card.ExpiresAt.IsZero() || card.AssessedAt.After(now.Add(readiness.MaximumFutureSkew)) ||
		!card.ExpiresAt.After(card.AssessedAt) || card.ExpiresAt.Sub(card.AssessedAt) > readiness.MaximumValidity || now.After(card.ExpiresAt) {
		return errors.New("released scorecard is future-dated, expired, or outside its existing validity bounds")
	}
	return nil
}

func repositoryBaseline(card readiness.Scorecard) int {
	result := 0
	for _, category := range card.Engineering {
		for _, item := range category.Subcriteria {
			if item.EvidenceType == readiness.RepositoryContentV1 {
				result += item.Weight
			}
		}
	}
	return result
}

type sourceReader struct {
	api   apiClient
	tree  string
	trees map[string]map[string]gitEntry
}

func (reader *sourceReader) readFile(ctx context.Context, name string, maximum int64) ([]byte, error) {
	identity, err := reader.fileIdentity(ctx, name)
	if err != nil {
		return nil, err
	}
	return readBlob(ctx, reader.api, identity, maximum)
}

func (reader *sourceReader) fileIdentity(ctx context.Context, name string) (string, error) {
	if name == "" || len(name) > 512 || path.Clean(name) != name || path.IsAbs(name) || strings.ContainsAny(name, "\\\x00") || strings.HasPrefix(name, "../") {
		return "", errors.New("source evidence path is invalid")
	}
	components := strings.Split(name, "/")
	current := reader.tree
	for index, component := range components {
		entries, ok := reader.trees[current]
		if !ok {
			var tree gitTree
			if err := reader.api(ctx, "repos/"+repository+"/git/trees/"+current, &tree); err != nil {
				return "", stageFailure(ctx, "read release evidence Git tree", err)
			}
			var err error
			entries, err = authenticateTree(tree, current)
			if err != nil {
				return "", err
			}
			reader.trees[current] = entries
		}
		entry, ok := entries[component]
		if !ok {
			return "", errors.New("required evidence is absent from the release Git tree")
		}
		if index < len(components)-1 {
			if entry.Type != "tree" || entry.Mode != "040000" {
				return "", errors.New("release evidence path traverses a non-directory Git object")
			}
		} else if entry.Type != "blob" || (entry.Mode != "100644" && entry.Mode != "100755") {
			return "", errors.New("release evidence is not a regular Git file")
		}
		current = entry.SHA
	}
	return current, nil
}

func authenticateTree(tree gitTree, expected string) (map[string]gitEntry, error) {
	if tree.SHA != expected || tree.Truncated == nil || *tree.Truncated || len(tree.Entries) == 0 || len(tree.Entries) > maximumTreeEntries {
		return nil, errors.New("source Git tree is missing, inconsistent, truncated, or exceeds its bound")
	}
	entries := make(map[string]gitEntry, len(tree.Entries))
	ordered := append([]gitEntry(nil), tree.Entries...)
	for _, item := range ordered {
		if item.Path == "" || item.Path == "." || item.Path == ".." || strings.ContainsAny(item.Path, "/\x00") || entries[item.Path].Path != "" || !objectIDPattern.MatchString(item.SHA) || len(item.SHA) != len(expected) {
			return nil, errors.New("source Git tree has an invalid or duplicate entry")
		}
		if !((item.Type == "tree" && item.Mode == "040000") || (item.Type == "commit" && item.Mode == "160000") ||
			(item.Type == "blob" && (item.Mode == "100644" || item.Mode == "100755" || item.Mode == "120000"))) {
			return nil, errors.New("source Git tree contains an unsupported entry mode")
		}
		entries[item.Path] = item
	}
	sort.Slice(ordered, func(i, j int) bool {
		left, right := ordered[i].Path, ordered[j].Path
		if ordered[i].Type == "tree" {
			left += "/"
		}
		if ordered[j].Type == "tree" {
			right += "/"
		}
		return left < right
	})
	var raw bytes.Buffer
	for _, item := range ordered {
		mode := item.Mode
		if mode == "040000" {
			mode = "40000"
		}
		fmt.Fprintf(&raw, "%s %s\x00", mode, item.Path)
		id, _ := hex.DecodeString(item.SHA)
		raw.Write(id)
	}
	if gitDigest("tree", raw.Bytes(), len(expected)) != expected {
		return nil, errors.New("source Git tree contents do not match their object identity")
	}
	return entries, nil
}

func readBlob(ctx context.Context, api apiClient, identity string, maximum int64) ([]byte, error) {
	var blob gitBlob
	if err := api(ctx, "repos/"+repository+"/git/blobs/"+identity, &blob); err != nil {
		return nil, stageFailure(ctx, "read release evidence Git blob", err)
	}
	if blob.SHA != identity || blob.Encoding != "base64" || blob.Size < 0 || blob.Size > maximum || int64(len(blob.Content)) > 2*maximum {
		return nil, errors.New("source Git blob metadata is invalid or exceeds its bound")
	}
	data, err := base64.StdEncoding.Strict().DecodeString(blob.Content)
	if err != nil || int64(len(data)) != blob.Size || gitDigest("blob", data, len(identity)) != identity {
		return nil, errors.New("source Git blob bytes do not match their object identity")
	}
	return data, nil
}

func gitDigest(kind string, data []byte, identityLength int) string {
	var digest hash.Hash = sha1.New() // Git object identity; policy pins use SHA-256.
	if identityLength == 64 {
		digest = sha256.New()
	}
	fmt.Fprintf(digest, "%s %d\x00", kind, len(data))
	digest.Write(data)
	return hex.EncodeToString(digest.Sum(nil))
}

func digestBytes(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func (reader *sourceReader) verifyEvidence(ctx context.Context, card readiness.Scorecard) error {
	references := make(map[string]string)
	for _, category := range card.Engineering {
		for _, item := range category.Subcriteria {
			if item.EvidenceType != readiness.RepositoryContentV1 {
				continue
			}
			for _, ref := range item.Evidence {
				if old, seen := references[ref.Path]; !sha256Pattern.MatchString(ref.SHA256) || (seen && old != ref.SHA256) {
					return errors.New("released repository evidence references are inconsistent")
				}
				references[ref.Path] = ref.SHA256
			}
		}
	}
	if len(references) == 0 || len(references) > maximumEvidenceFiles {
		return errors.New("released repository evidence inventory is empty or exceeds its bound")
	}
	// Resolve the finite tree paths first, sharing verified tree objects. Then
	// bound concurrent blob downloads; no live evidence is cached across calls.
	objects := make(map[string]string)
	names := make([]string, 0, len(references))
	for name := range references {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		id, err := reader.fileIdentity(ctx, name)
		if err != nil {
			return err
		}
		if old, exists := objects[id]; exists && old != references[name] {
			return errors.New("released source blob has conflicting evidence digests")
		}
		objects[id] = references[name]
	}
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	tasks := make(chan string)
	failures := make(chan error, 1)
	var workers sync.WaitGroup
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for id := range tasks {
				data, err := readBlob(workCtx, reader.api, id, readiness.MaximumEvidenceSize)
				if err == nil && digestBytes(data) != objects[id] {
					err = errors.New("released repository evidence SHA-256 does not match its authenticated source blob")
				}
				if err != nil {
					select {
					case failures <- err:
					default:
					}
					cancel()
					return
				}
			}
		}()
	}
feed:
	for id := range objects {
		select {
		case tasks <- id:
		case <-workCtx.Done():
			break feed
		}
	}
	close(tasks)
	workers.Wait()
	select {
	case err := <-failures:
		return err
	default:
	}
	return ctx.Err()
}
