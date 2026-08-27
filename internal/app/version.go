package app

import (
	"fmt"

	"github.com/Yunushan/leaguebridge/internal/version"
)

func (a *App) runVersion(args []string) int {
	set := a.flagSet("version")
	asJSON := set.Bool("json", false, "emit JSON")
	if err := parseFlags(set, args); err != nil {
		return a.commandError("version", *asJSON, ExitUsage, "%v", err)
	}
	info := version.Current()
	if *asJSON {
		return a.writeJSON("version", info)
	}
	fmt.Fprintf(a.Stdout, "LeagueBridge %s\ncommit: %s\nbuilt: %s\nGo: %s\n", info.Version, info.Commit, info.BuildDate, info.GoVersion)
	return ExitOK
}
