package remote

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Yunushan/leaguebridge/internal/config"
)

func TestStreamOptionsMouseModesForQt(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		mode string
		want string
	}{
		{name: "absolute", mode: "absolute", want: "-absolute-mouse"},
		{name: "relative", mode: "relative", want: "-no-absolute-mouse"},
		{name: "case-insensitive", mode: "ABSOLUTE", want: "-absolute-mouse"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := (StreamOptions{MouseMode: tt.mode}).arguments(FlavorQt)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, []string{tt.want}) {
				t.Fatalf("arguments = %#v, want %#v", got, []string{tt.want})
			}
		})
	}
}

func TestStreamOptionsMouseModeSupportsFlatpakQt(t *testing.T) {
	t.Parallel()
	got, err := (StreamOptions{MouseMode: "absolute"}).arguments(FlavorFlatpak)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"-absolute-mouse"}) {
		t.Fatalf("Flatpak arguments = %#v", got)
	}
}

func TestStreamOptionsMouseModeRejectsEmbedded(t *testing.T) {
	t.Parallel()
	if _, err := (StreamOptions{MouseMode: "absolute"}).arguments(FlavorEmbedded); err == nil || !strings.Contains(err.Error(), "only by Moonlight Qt") {
		t.Fatalf("Embedded mouse mode error = %v; want Qt-only rejection", err)
	}
	_, err := BuildPlan(Client{Flavor: FlavorEmbedded, Binary: "/usr/bin/moonlight"}, Request{
		Route:                   config.RouteWindows,
		Operation:               Stream,
		Host:                    "pc.local",
		App:                     "League",
		PhysicalHostConfirmed:   true,
		AcceptUnverifiedHandoff: true,
		Stream:                  StreamOptions{MouseMode: "relative"},
	})
	if err == nil || !strings.Contains(err.Error(), "only by Moonlight Qt") {
		t.Fatalf("BuildPlan Embedded mouse mode error = %v; want Qt-only rejection", err)
	}
}

func TestValidatePlanArgumentsRejectsUnsafeMouseModes(t *testing.T) {
	t.Parallel()
	qt := Client{Flavor: FlavorQt, Binary: "/usr/bin/moonlight-qt"}
	if err := validatePlanArguments(qt, []string{"stream", "-absolute-mouse", "-no-absolute-mouse", "pc.local", "League"}); err == nil || !strings.Contains(err.Error(), "repeats the mouse mode") {
		t.Fatalf("repeated Qt mouse mode error = %v", err)
	}
	embedded := Client{Flavor: FlavorEmbedded, Binary: "/usr/bin/moonlight"}
	if err := validatePlanArguments(embedded, []string{"stream", "-absolute-mouse", "-app", "League", "pc.local"}); err == nil || !strings.Contains(err.Error(), "Qt-only mouse mode") {
		t.Fatalf("Embedded mouse mode argument error = %v", err)
	}
}
