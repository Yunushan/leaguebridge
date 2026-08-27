// Command versioncheck validates release version input before it reaches build
// metadata, archive names, or supply-chain documents.
package main

import (
	"fmt"
	"os"

	"github.com/Yunushan/leaguebridge/internal/releaseversion"
)

func main() {
	if len(os.Args) != 2 || !releaseversion.Valid(os.Args[1]) {
		fmt.Fprintln(os.Stderr, "invalid v-prefixed Semantic Version")
		os.Exit(1)
	}
}
