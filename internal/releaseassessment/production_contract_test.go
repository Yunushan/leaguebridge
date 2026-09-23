package releaseassessment

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Yunushan/leaguebridge/internal/readiness"
)

func TestProductionContractUsesAuthenticatedReleasedRows(t *testing.T) {
	data, err := os.ReadFile("testdata/reviewed-v0.1.0-scorecard.json")
	if err != nil {
		t.Fatal(err)
	}
	var card readiness.Scorecard
	if err := json.Unmarshal(data, &card); err != nil {
		t.Fatal(err)
	}
	if err := checkProductionContract(card); err != nil {
		t.Fatalf("reviewed released contract: %v", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*readiness.Scorecard)
	}{
		{"missing row", func(c *readiness.Scorecard) {
			c.Engineering[2].Subcriteria = c.Engineering[2].Subcriteria[:len(c.Engineering[2].Subcriteria)-1]
		}},
		{"wrong weight", func(c *readiness.Scorecard) { c.Engineering[2].Subcriteria[3].Weight++ }},
		{"unreviewed evidence", func(c *readiness.Scorecard) {
			c.Engineering[2].Subcriteria[3].Evidence = []readiness.EvidenceReference{{Path: "forged", SHA256: strings.Repeat("0", 64)}}
		}},
		{"wrong category", func(c *readiness.Scorecard) {
			item := c.Engineering[2].Subcriteria[3]
			c.Engineering[2].Subcriteria = c.Engineering[2].Subcriteria[:3]
			c.Engineering[3].Subcriteria = append(c.Engineering[3].Subcriteria, item)
		}},
		{"duplicate row", func(c *readiness.Scorecard) {
			c.Engineering[2].Subcriteria = append(c.Engineering[2].Subcriteria, c.Engineering[2].Subcriteria[3])
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var copy readiness.Scorecard
			if err := json.Unmarshal(data, &copy); err != nil {
				t.Fatal(err)
			}
			test.mutate(&copy)
			if err := checkProductionContract(copy); err == nil {
				t.Fatal("changed released production contract was accepted")
			}
		})
	}
}
