package app

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestRemoteMouseFlagsForwardToMoonlightQt(t *testing.T) {
	for _, tt := range []struct {
		name string
		flag string
		want string
	}{
		{name: "absolute", flag: "--absolute-mouse", want: "-absolute-mouse"},
		{name: "relative", flag: "--no-absolute-mouse", want: "-no-absolute-mouse"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a, out, errOut, _, runner := newTestApp(t)
			args := []string{
				"remote", "stream", "--host", "gaming-pc.local", tt.flag,
				"--confirm-physical-host", "--acknowledge-unverified-handoff", "--dry-run", "--json",
			}
			if code := a.Run(context.Background(), args); code != ExitOK {
				t.Fatalf("code = %d; stdout=%q stderr=%q", code, out.String(), errOut.String())
			}
			envelope := decodeEnvelope(t, out.Bytes())
			plan := envelope.Data.(map[string]any)
			arguments := plan["arguments"].([]any)
			want := []any{"stream", tt.want, "gaming-pc.local", "League of Legends"}
			if !reflect.DeepEqual(arguments, want) || runner.called != 0 {
				t.Fatalf("arguments=%#v runner.called=%d; want %#v and no process", arguments, runner.called, want)
			}
		})
	}
}

func TestRemoteMouseFlagsRejectConflictsAndNonStreamUse(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "conflict",
			args: []string{"remote", "stream", "--absolute-mouse", "--no-absolute-mouse", "--dry-run"},
			want: "cannot combine",
		},
		{
			name: "pair",
			args: []string{"remote", "pair", "--absolute-mouse", "--dry-run"},
			want: "require the stream operation",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a, _, errOut, _, _ := newTestApp(t)
			if code := a.Run(context.Background(), tt.args); code != ExitUsage {
				t.Fatalf("code = %d; stderr=%q", code, errOut.String())
			}
			if !strings.Contains(errOut.String(), tt.want) {
				t.Fatalf("stderr=%q; want %q", errOut.String(), tt.want)
			}
		})
	}
}
