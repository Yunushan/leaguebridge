package compat

import (
	"testing"
	"time"
)

func TestFreshnessAtBoundaries(t *testing.T) {
	t.Parallel()

	manifest := mustEmbedded(t)
	tests := []struct {
		name    string
		at      string
		want    FreshnessState
		ageDays int
	}{
		{name: "future", at: "2026-08-31", want: FreshnessFuture, ageDays: 5},
		{name: "as of", at: "2026-09-01", want: FreshnessFresh, ageDays: 6},
		{name: "last fresh day", at: "2026-09-25", want: FreshnessFresh, ageDays: 30},
		{name: "first stale day", at: "2026-09-26", want: FreshnessStale, ageDays: 31},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			at, err := time.Parse("2006-01-02", test.at)
			if err != nil {
				t.Fatal(err)
			}
			got, err := manifest.FreshnessAt(at)
			if err != nil {
				t.Fatalf("FreshnessAt() error = %v", err)
			}
			if got.State != test.want || got.AgeDays != test.ageDays {
				t.Fatalf("FreshnessAt() = state %q age %d, want state %q age %d", got.State, got.AgeDays, test.want, test.ageDays)
			}
			if got.EvaluatedAt != test.at {
				t.Fatalf("EvaluatedAt = %q, want %q", got.EvaluatedAt, test.at)
			}
			if got.ExpiresAt != "2026-09-25" {
				t.Fatalf("ExpiresAt = %q, want 2026-09-25", got.ExpiresAt)
			}
		})
	}
}

func TestFreshnessUsesOldestSourceCheck(t *testing.T) {
	t.Parallel()

	manifest := mustEmbedded(t)
	manifest.Sources[0].CheckedAt = "2026-08-20"
	report, err := manifest.FreshnessAt(time.Date(2026, 8, 26, 23, 59, 0, 0, time.FixedZone("west", -7*60*60)))
	if err != nil {
		t.Fatalf("FreshnessAt() error = %v", err)
	}
	// The instant is 2026-08-27 UTC. Freshness is intentionally audited on
	// UTC calendar dates, independently of the caller's local time zone.
	if report.EvaluatedAt != "2026-08-27" || report.OldestSourceCheckedAt != "2026-08-20" || report.AgeDays != 7 {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestFreshnessRejectsZeroTimeAndInvalidManifest(t *testing.T) {
	t.Parallel()

	manifest := mustEmbedded(t)
	if _, err := manifest.FreshnessAt(time.Time{}); err == nil {
		t.Fatal("zero evaluation time accepted")
	}
	manifest.Policy.MaxAgeDays = 0
	if _, err := manifest.FreshnessAt(time.Now()); err == nil {
		t.Fatal("invalid manifest accepted")
	}
}
