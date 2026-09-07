package releaseassessment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/Yunushan/leaguebridge/internal/target"
)

type release struct {
	ID          int64     `json:"id"`
	Tag         string    `json:"tag_name"`
	Draft       *bool     `json:"draft"`
	Prerelease  *bool     `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	URL         string    `json:"html_url"`
	Assets      []asset   `json:"assets"`
}
type asset struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	State     string    `json:"state"`
	Size      int64     `json:"size"`
	Digest    string    `json:"digest"`
	URL       string    `json:"browser_download_url"`
	UpdatedAt time.Time `json:"updated_at"`
}
type ruleset struct {
	ID           int64             `json:"id"`
	Target       string            `json:"target"`
	SourceType   string            `json:"source_type"`
	Source       string            `json:"source"`
	Enforcement  string            `json:"enforcement"`
	BypassActors []json.RawMessage `json:"bypass_actors"`
	Conditions   struct {
		RefName struct {
			Include []string `json:"include"`
			Exclude []string `json:"exclude"`
		} `json:"ref_name"`
	} `json:"conditions"`
	Rules []struct {
		Type       string          `json:"type"`
		Parameters json.RawMessage `json:"parameters"`
	} `json:"rules"`
}
type publication struct {
	Release           release
	Assets            []asset
	Commit, TagObject string
	Protection        []ruleset
}

func resolvePublication(ctx context.Context, api apiClient, version string) (publication, error) {
	var result publication
	if err := api(ctx, "repos/"+repository+"/releases/tags/"+version, &result.Release); err != nil {
		return publication{}, stageFailure(ctx, "read named published release", err)
	}
	r := result.Release
	if r.ID <= 0 || r.Tag != version || r.Draft == nil || *r.Draft || r.Prerelease == nil || *r.Prerelease || r.PublishedAt.IsZero() || r.UpdatedAt.IsZero() || r.URL != "https://github.com/"+repository+"/releases/tag/"+version {
		return publication{}, errors.New("named release is absent, draft, prerelease, or has an inconsistent identity")
	}
	if err := api(ctx, fmt.Sprintf("repos/%s/releases/%d/assets?per_page=100&page=1", repository, r.ID), &result.Assets); err != nil {
		return publication{}, stageFailure(ctx, "read published release assets", err)
	}
	if err := validateAssets(result.Assets, version); err != nil {
		return publication{}, err
	}
	if err := validateAssets(r.Assets, version); err != nil {
		return publication{}, err
	}
	sort.Slice(result.Assets, func(i, j int) bool { return result.Assets[i].Name < result.Assets[j].Name })
	sort.Slice(result.Release.Assets, func(i, j int) bool { return result.Release.Assets[i].Name < result.Release.Assets[j].Name })
	if !reflect.DeepEqual(result.Assets, result.Release.Assets) {
		return publication{}, errors.New("release and published asset inventories disagree")
	}
	var err error
	result.Commit, result.TagObject, err = resolveTag(ctx, api, version)
	if err != nil {
		return publication{}, err
	}
	result.Protection, err = resolveProtection(ctx, api)
	if err != nil {
		return publication{}, err
	}
	return result, nil
}

func releaseNames(version string) []string {
	names := []string{"checksums.txt"}
	for _, item := range target.Ordered() {
		names = append(names, "leaguebridge_"+strings.TrimPrefix(version, "v")+"_"+item.GOOS+"_"+item.GOARCH+".tar.gz")
	}
	sort.Strings(names)
	return names
}

func validateAssets(assets []asset, version string) error {
	names := releaseNames(version)
	if len(assets) != len(names) {
		return errors.New("published release must contain exactly nine archives and checksums.txt")
	}
	wanted := make(map[string]bool, len(names))
	for _, name := range names {
		wanted[name] = true
	}
	ids := make(map[int64]bool)
	for _, item := range assets {
		if !wanted[item.Name] || item.ID <= 0 || ids[item.ID] || item.State != "uploaded" || item.Size <= 0 || item.Size > maximumFileSize(item.Name) || item.UpdatedAt.IsZero() ||
			!strings.HasPrefix(item.Digest, "sha256:") || !sha256Pattern.MatchString(strings.TrimPrefix(item.Digest, "sha256:")) || item.URL != "https://github.com/"+repository+"/releases/download/"+version+"/"+item.Name {
			return errors.New("published asset identity, state, size, digest, or download location is invalid")
		}
		delete(wanted, item.Name)
		ids[item.ID] = true
	}
	return nil
}

func resolveTag(ctx context.Context, api apiClient, version string) (string, string, error) {
	var ref gitReference
	if err := api(ctx, "repos/"+repository+"/git/ref/tags/"+version, &ref); err != nil {
		return "", "", stageFailure(ctx, "read release tag", err)
	}
	if ref.Ref != "refs/tags/"+version || !objectIDPattern.MatchString(ref.Object.SHA) {
		return "", "", errors.New("release tag has an inconsistent Git identity")
	}
	initial := ref.Object.SHA
	object := ref.Object
	seen := make(map[string]bool)
	for depth := 0; depth <= 5; depth++ {
		if object.Type == "commit" {
			return object.SHA, initial, nil
		}
		if object.Type != "tag" || depth == 5 || seen[object.SHA] {
			return "", "", errors.New("release tag cannot be peeled to a bounded unique commit")
		}
		seen[object.SHA] = true
		var tag gitTag
		if err := api(ctx, "repos/"+repository+"/git/tags/"+object.SHA, &tag); err != nil {
			return "", "", stageFailure(ctx, "read annotated release tag", err)
		}
		if tag.SHA != object.SHA || (depth == 0 && tag.Tag != version) || !objectIDPattern.MatchString(tag.Object.SHA) || len(tag.Object.SHA) != len(initial) {
			return "", "", errors.New("annotated release tag object is inconsistent")
		}
		object = tag.Object
	}
	return "", "", errors.New("release tag peeling exceeded its bound")
}

func resolveProtection(ctx context.Context, api apiClient) ([]ruleset, error) {
	var result []ruleset
	seen := make(map[int64]bool)
	complete := false
	for page := 1; page <= 10; page++ {
		var list []ruleset
		if err := api(ctx, fmt.Sprintf("repos/%s/rulesets?includes_parents=true&per_page=100&page=%d", repository, page), &list); err != nil {
			return nil, stageFailure(ctx, "read release tag protections", err)
		}
		if len(list) > 100 {
			return nil, errors.New("release protection inventory exceeds its page bound")
		}
		for _, summary := range list {
			if summary.ID <= 0 || seen[summary.ID] {
				return nil, errors.New("release protection inventory has invalid or duplicate identities")
			}
			seen[summary.ID] = true
			if summary.Target != "tag" || summary.Enforcement != "active" || summary.SourceType != "Repository" || summary.Source != repository {
				continue
			}
			var full ruleset
			if err := api(ctx, fmt.Sprintf("repos/%s/rulesets/%d", repository, summary.ID), &full); err != nil {
				return nil, stageFailure(ctx, "read active release tag rules", err)
			}
			if full.ID != summary.ID {
				return nil, errors.New("release protection detail identity changed")
			}
			if validProtection(full) {
				result = append(result, full)
			}
		}
		if len(list) < 100 {
			complete = true
			break
		}
	}
	if !complete || len(result) == 0 {
		return nil, errors.New("release requires active repository protection of v* tags against updates and deletion without bypass actors")
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func validProtection(rule ruleset) bool {
	if rule.Target != "tag" || rule.Enforcement != "active" || rule.SourceType != "Repository" || rule.Source != repository || rule.BypassActors == nil || len(rule.BypassActors) != 0 ||
		len(rule.Conditions.RefName.Include) != 1 || rule.Conditions.RefName.Include[0] != "refs/tags/v*" || rule.Conditions.RefName.Exclude == nil || len(rule.Conditions.RefName.Exclude) != 0 || len(rule.Rules) != 2 {
		return false
	}
	seen := make(map[string]bool)
	for _, item := range rule.Rules {
		if seen[item.Type] || (item.Type != "update" && item.Type != "deletion") {
			return false
		}
		seen[item.Type] = true
		if len(item.Parameters) != 0 && string(item.Parameters) != "null" && string(item.Parameters) != "{}" {
			var parameters struct {
				UpdateAllowsFetchAndMerge *bool `json:"update_allows_fetch_and_merge"`
			}
			decoder := json.NewDecoder(strings.NewReader(string(item.Parameters)))
			decoder.DisallowUnknownFields()
			if item.Type != "update" || decoder.Decode(&parameters) != nil || parameters.UpdateAllowsFetchAndMerge == nil || *parameters.UpdateAllowsFetchAndMerge {
				return false
			}
		}
	}
	return seen["update"] && seen["deletion"]
}

type workflow struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Path  string `json:"path"`
	State string `json:"state"`
}
type repositoryIdentity struct {
	FullName string `json:"full_name"`
}
type workflowRun struct {
	ID             int64              `json:"id"`
	Attempt        int                `json:"run_attempt"`
	WorkflowID     int64              `json:"workflow_id"`
	Path           string             `json:"path"`
	Event          string             `json:"event"`
	Branch         string             `json:"head_branch"`
	Commit         string             `json:"head_sha"`
	Status         string             `json:"status"`
	Conclusion     string             `json:"conclusion"`
	Repository     repositoryIdentity `json:"repository"`
	HeadRepository repositoryIdentity `json:"head_repository"`
}
type runPage struct {
	Total int           `json:"total_count"`
	Runs  []workflowRun `json:"workflow_runs"`
}
type job struct {
	ID         int64  `json:"id"`
	RunID      int64  `json:"run_id"`
	Attempt    *int   `json:"run_attempt"`
	Commit     string `json:"head_sha"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
}
type jobPage struct {
	Total int   `json:"total_count"`
	Jobs  []job `json:"jobs"`
}

func verifyReleaseRun(ctx context.Context, api apiClient, version, commit string) (workflowRun, error) {
	var definition workflow
	if err := api(ctx, "repos/"+repository+"/actions/workflows/release.yml", &definition); err != nil {
		return workflowRun{}, stageFailure(ctx, "read Release workflow identity", err)
	}
	if definition.ID <= 0 || definition.Name != "Release" || definition.Path != releaseWorkflow || definition.State != "active" {
		return workflowRun{}, errors.New("expected active Release workflow is unavailable")
	}
	run, err := latestReleaseRun(ctx, api, definition.ID, version, commit)
	if err != nil {
		return workflowRun{}, err
	}
	if run.Status != "completed" || run.Conclusion != "success" {
		return workflowRun{}, errors.New("latest exact-tag Release attempt has not completed successfully")
	}
	var jobs jobPage
	if err := api(ctx, fmt.Sprintf("repos/%s/actions/runs/%d/attempts/%d/jobs?per_page=100&page=1", repository, run.ID, run.Attempt), &jobs); err != nil {
		return workflowRun{}, stageFailure(ctx, "read Release attempt jobs", err)
	}
	required := map[string]bool{"Reject reachable known vulnerabilities": true, "Test and build unprivileged artifacts": true, "Attest and publish artifacts": true}
	if jobs.Total != len(required) || len(jobs.Jobs) != jobs.Total {
		return workflowRun{}, errors.New("Release attempt must include all three reviewed jobs")
	}
	ids := make(map[int64]bool)
	for _, item := range jobs.Jobs {
		if !required[item.Name] || item.ID <= 0 || ids[item.ID] || item.RunID != run.ID || (item.Attempt != nil && *item.Attempt != run.Attempt) || item.Commit != commit || item.Status != "completed" || item.Conclusion != "success" {
			return workflowRun{}, errors.New("Release job source, attempt, identity, or successful completion is invalid")
		}
		delete(required, item.Name)
		ids[item.ID] = true
	}
	current, err := latestReleaseRun(ctx, api, definition.ID, version, commit)
	if err != nil {
		return workflowRun{}, err
	}
	if current != run {
		return workflowRun{}, errors.New("Release run changed while checking its jobs")
	}
	return run, nil
}

func latestReleaseRun(ctx context.Context, api apiClient, workflowID int64, version, commit string) (workflowRun, error) {
	var latest workflowRun
	seen := make(map[int64]bool)
	total, count := -1, 0
	for page := 1; page <= 10; page++ {
		var response runPage
		endpoint := fmt.Sprintf("repos/%s/actions/workflows/%d/runs?head_sha=%s&branch=%s&per_page=100&page=%d", repository, workflowID, commit, version, page)
		if err := api(ctx, endpoint, &response); err != nil {
			return workflowRun{}, stageFailure(ctx, "read exact-tag Release runs", err)
		}
		if response.Total < 0 || response.Total > 1000 || len(response.Runs) > 100 || (total >= 0 && total != response.Total) {
			return workflowRun{}, errors.New("Release run pagination is inconsistent or exceeds its bound")
		}
		total = response.Total
		count += len(response.Runs)
		if count > total || (len(response.Runs) == 0 && count != total) {
			return workflowRun{}, errors.New("Release run page does not match its declared total")
		}
		for _, item := range response.Runs {
			if item.ID <= 0 || item.Attempt <= 0 || seen[item.ID] || item.WorkflowID != workflowID || item.Path != releaseWorkflow || item.Commit != commit || item.Branch != version || item.Repository.FullName != repository || item.HeadRepository.FullName != repository {
				return workflowRun{}, errors.New("Release run source, workflow, or tag identity is inconsistent")
			}
			seen[item.ID] = true
			if item.Event != "push" {
				continue
			}
			if item.ID > latest.ID {
				latest = item
			}
		}
		if count == total {
			break
		}
	}
	if count != total || latest.ID == 0 {
		return workflowRun{}, errors.New("no complete exact-tag Release push run inventory")
	}
	return latest, nil
}
