package releaseassessment

import (
	"reflect"
	"strings"
	"testing"
)

func TestAPIEnvironmentScopesRulesetToken(t *testing.T) {
	inherited := []string{"PATH=/bin", "GH_TOKEN=workflow-token", "OTHER=value", "GH_TOKEN=duplicate"}
	cases := []struct {
		name      string
		endpoint  string
		want      string
		unchanged bool
	}{
		{
			name:     "ruleset collection",
			endpoint: "repos/" + repository + "/rulesets?includes_parents=true&page=1",
			want:     "owner-read-token",
		},
		{
			name:     "ruleset detail",
			endpoint: "repos/" + repository + "/rulesets/22471782",
			want:     "owner-read-token",
		},
		{
			name:      "release endpoint",
			endpoint:  "repos/" + repository + "/releases/tags/v0.1.0",
			want:      "workflow-token",
			unchanged: true,
		},
		{
			name:      "other repository ruleset",
			endpoint:  "repos/another/repository/rulesets/1",
			want:      "workflow-token",
			unchanged: true,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := apiEnvironment(test.endpoint, inherited, " owner-read-token ")
			if test.unchanged {
				if !reflect.DeepEqual(got, inherited) {
					t.Fatalf("environment = %#v; want the inherited environment unchanged", got)
				}
				return
			}
			var tokens []string
			for _, entry := range got {
				if strings.HasPrefix(entry, "GH_TOKEN=") {
					tokens = append(tokens, strings.TrimPrefix(entry, "GH_TOKEN="))
				}
			}
			if len(tokens) != 1 || tokens[0] != test.want {
				t.Fatalf("GH_TOKEN values = %#v; want [%q]", tokens, test.want)
			}
		})
	}
}
