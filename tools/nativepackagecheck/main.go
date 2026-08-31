// Command nativepackagecheck verifies a native-package staging tree.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Yunushan/leaguebridge/internal/fileinput"
	"github.com/Yunushan/leaguebridge/internal/nativepackage"
)

func main() {
	staging := flag.String("staging", "", "native package staging directory")
	flag.Parse()
	if flag.NArg() != 0 {
		fatalf("positional arguments are not accepted")
	}
	if *staging == "" {
		fatalf("staging is required")
	}
	manifest, err := verify(*staging)
	if err != nil {
		fatalf("%v", err)
	}
	fmt.Printf("verified native package staging: family=%s target=%s/%s source=%s\n", manifest.Package.Family, manifest.Target.GOOS, manifest.Target.GOARCH, manifest.SourceArtifact.Filename)
}

func verify(stagingPath string) (nativepackage.Manifest, error) {
	root, err := fileinput.OpenDirectoryRoot(stagingPath)
	if err != nil {
		return nativepackage.Manifest{}, fmt.Errorf("open staging directory: %w", err)
	}
	defer root.Close()
	manifest, err := nativepackage.VerifyStagingRoot(root)
	if err != nil {
		return nativepackage.Manifest{}, err
	}
	return manifest, nil
}

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, "nativepackagecheck: "+format+"\n", arguments...)
	os.Exit(1)
}
