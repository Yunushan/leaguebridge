package compat

import (
	"fmt"
	"time"
)

// FreshnessState reports whether all dated evidence is within the manifest's
// declared maximum age at a particular UTC calendar date.
type FreshnessState string

const (
	FreshnessFresh  FreshnessState = "fresh"
	FreshnessStale  FreshnessState = "stale"
	FreshnessFuture FreshnessState = "future"
)

// Freshness is a deterministic, date-based report. AgeDays is the age of the
// oldest relevant date (the manifest asOf date or a source checkedAt date).
type Freshness struct {
	State                 FreshnessState `json:"state"`
	AsOf                  string         `json:"asOf"`
	OldestSourceCheckedAt string         `json:"oldestSourceCheckedAt"`
	EvaluatedAt           string         `json:"evaluatedAt"`
	ExpiresAt             string         `json:"expiresAt"`
	AgeDays               int            `json:"ageDays"`
	MaxAgeDays            int            `json:"maxAgeDays"`
}

// FreshnessAt validates the manifest and calculates freshness using UTC
// calendar dates. A future manifest or future source check is never fresh.
func (m Manifest) FreshnessAt(at time.Time) (Freshness, error) {
	if at.IsZero() {
		return Freshness{}, fmt.Errorf("freshness: evaluation time is required")
	}
	if err := Validate(m); err != nil {
		return Freshness{}, fmt.Errorf("freshness: %w", err)
	}
	asOf, _ := parseDate("asOf", m.AsOf)
	oldest := asOf
	for _, source := range m.Sources {
		checked, _ := parseDate("checkedAt", source.CheckedAt)
		if checked.Before(oldest) {
			oldest = checked
		}
	}

	evaluated := dateOnlyUTC(at)
	report := Freshness{
		AsOf:                  m.AsOf,
		OldestSourceCheckedAt: oldest.Format("2006-01-02"),
		EvaluatedAt:           evaluated.Format("2006-01-02"),
		ExpiresAt:             oldest.AddDate(0, 0, m.Policy.MaxAgeDays).Format("2006-01-02"),
		AgeDays:               int((evaluated.Unix() - oldest.Unix()) / (24 * 60 * 60)),
		MaxAgeDays:            m.Policy.MaxAgeDays,
	}
	if evaluated.Before(asOf) || evaluated.Before(oldest) {
		report.State = FreshnessFuture
		return report, nil
	}
	for _, source := range m.Sources {
		checked, _ := parseDate("checkedAt", source.CheckedAt)
		if checked.After(evaluated) {
			report.State = FreshnessFuture
			return report, nil
		}
	}
	if report.AgeDays > report.MaxAgeDays {
		report.State = FreshnessStale
		return report, nil
	}
	report.State = FreshnessFresh
	return report, nil
}

func dateOnlyUTC(value time.Time) time.Time {
	value = value.UTC()
	return time.Date(value.Year(), value.Month(), value.Day(), 0, 0, 0, 0, time.UTC)
}
