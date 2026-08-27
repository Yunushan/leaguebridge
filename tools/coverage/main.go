// Command coverage enforces the repository's core-package statement coverage.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func main() {
	minimum := flag.Float64("minimum", 80, "minimum statement coverage percentage")
	flag.Parse()
	if *minimum < 0 || *minimum > 100 {
		fatalf("minimum must be between 0 and 100")
	}

	profile, err := os.CreateTemp("", "leaguebridge-coverage-*.out")
	if err != nil {
		fatalf("create temporary profile: %v", err)
	}
	path := profile.Name()
	if err := profile.Close(); err != nil {
		fatalf("close temporary profile: %v", err)
	}
	defer os.Remove(path)

	cmd := exec.Command("go", "test", "-covermode=atomic", "-coverprofile="+path, "./internal/...")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fatalf("coverage tests failed: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		fatalf("open coverage profile: %v", err)
	}
	covered, total, err := parseProfile(f)
	f.Close()
	if err != nil {
		fatalf("parse coverage profile: %v", err)
	}
	if total == 0 {
		fatalf("coverage profile contains no statements")
	}
	percentage := float64(covered) * 100 / float64(total)
	fmt.Printf("core statement coverage: %.1f%% (minimum %.1f%%)\n", percentage, *minimum)
	if percentage+1e-9 < *minimum {
		os.Exit(1)
	}
}

func parseProfile(f *os.File) (covered, total int64, err error) {
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if first {
			first = false
			if !strings.HasPrefix(line, "mode: ") {
				return 0, 0, fmt.Errorf("missing mode header")
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return 0, 0, fmt.Errorf("malformed profile line %q", line)
		}
		statements, parseErr := strconv.ParseInt(fields[1], 10, 64)
		if parseErr != nil || statements < 0 {
			return 0, 0, fmt.Errorf("invalid statement count in %q", line)
		}
		count, parseErr := strconv.ParseInt(fields[2], 10, 64)
		if parseErr != nil || count < 0 {
			return 0, 0, fmt.Errorf("invalid execution count in %q", line)
		}
		total += statements
		if count > 0 {
			covered += statements
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}
	if first {
		return 0, 0, fmt.Errorf("empty profile")
	}
	return covered, total, nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "coverage: "+format+"\n", args...)
	os.Exit(2)
}
