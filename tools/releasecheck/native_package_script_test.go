package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativePackageSmokeScriptsDelegateSemanticVersionValidation(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"native-package-linux-smoke.sh",
		"native-package-bsd-smoke.sh",
	} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(filepath.Join("..", "..", "scripts", name))
			if err != nil {
				t.Fatal(err)
			}
			script := string(data)
			prefixGuard := "case \"$version\" in\n  v*) ;;"
			if !strings.Contains(script, prefixGuard) {
				t.Fatalf("%s must keep the shell version guard limited to the v prefix", name)
			}
			if strings.Contains(script, "v[0-9]*.[0-9]*.[0-9]*)") {
				t.Fatalf("%s must not duplicate SemVer grammar in a shell glob", name)
			}
			checker := "versioncheck \"$version\""
			if !strings.Contains(script, checker) {
				t.Fatalf("%s must invoke the repository semantic-version checker", name)
			}
			if strings.Index(script, checker) < strings.Index(script, prefixGuard) {
				t.Fatalf("%s invokes the semantic-version checker before its prefix guard", name)
			}
		})
	}
}

func TestVerifyInstallDelegatesSemanticVersionValidation(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", "scripts", "verify-install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	prefixGuard := "case \"$expected_version\" in\n\tv*) ;;"
	if !strings.Contains(script, prefixGuard) {
		t.Fatal("verify-install.sh must keep the shell version guard limited to the v prefix")
	}
	if strings.Contains(script, "v[0-9]*.[0-9]*.[0-9]*)") {
		t.Fatal("verify-install.sh must not duplicate SemVer grammar in a shell glob")
	}
}

func TestVerifyInstallResolvesNetBSDMachineArchitecture(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", "scripts", "verify-install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, required := range []string{
		"runtime_machine=$(uname -m)",
		"sysctl -n hw.machine_arch",
		"uname -p 2>/dev/null",
		"x86_64|amd64) runtime_goarch=amd64",
		"aarch64|arm64) runtime_goarch=arm64",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("verify-install.sh is missing machine-architecture fallback fragment %q", required)
		}
	}
}

func TestLinuxBSDRemoteSmokeResolvesNetBSDMachineArchitecture(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", "scripts", "linux-bsd-remote-smoke.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, required := range []string{
		"runtime_machine=$(uname -m)",
		"sysctl -n hw.machine_arch",
		"uname -p 2>/dev/null",
		"x86_64|amd64) expected_goarch=amd64",
		"aarch64|arm64) expected_goarch=arm64",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("linux-bsd-remote-smoke.sh is missing machine-architecture fallback fragment %q", required)
		}
	}
}

func TestBSDRuntimeSmokeResolvesNetBSDMachineArchitecture(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", "scripts", "bsd-runtime-smoke.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, required := range []string{
		"runtime_machine=$(uname -m)",
		"sysctl -n hw.machine_arch",
		"uname -p 2>/dev/null",
		"if [ \"$actual_goarch\" != \"$expected_goarch\" ]; then",
		"printf 'machine_arch=%s\\n' \"$actual_goarch\"",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("bsd-runtime-smoke.sh is missing machine-architecture validation fragment %q", required)
		}
	}
}

func TestBSDRuntimeSmokeProtectsEvidenceOutputs(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", "scripts", "bsd-runtime-smoke.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, required := range []string{
		`if [ -L "$evidence_dir" ] || { [ -e "$evidence_dir" ] && [ ! -d "$evidence_dir" ]; }; then`,
		`if [ -L "$evidence_dir" ] || [ ! -d "$evidence_dir" ]; then`,
		"for output in \\",
		"kernel.txt",
		"version.json",
		"status.json",
		"readiness.json",
		"manifest-verify.json",
		"doctor.json",
		"result.txt; do",
		`if [ -e "$evidence_dir/$output" ] || [ -L "$evidence_dir/$output" ]; then`,
		"refusing to overwrite existing evidence output",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("bsd-runtime-smoke.sh is missing evidence-integrity fragment %q", required)
		}
	}
	guardIndex := strings.Index(script, `if [ -L "$evidence_dir" ]`)
	mkdirIndex := strings.Index(script, `mkdir -p "$evidence_dir"`)
	writeIndex := strings.Index(script, `> "$evidence_dir/kernel.txt"`)
	if guardIndex < 0 || mkdirIndex < 0 || writeIndex < 0 || guardIndex > mkdirIndex || mkdirIndex > writeIndex {
		t.Fatal("bsd-runtime-smoke.sh must validate evidence paths before creating or writing evidence")
	}
}

func TestRuntimeSmokeRequiresVerifiedRepositoryEvidence(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"linux-runtime-smoke.sh", "bsd-runtime-smoke.sh", "linux-bsd-remote-smoke.sh"} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(filepath.Join("..", "..", "scripts", name))
			if err != nil {
				t.Fatal(err)
			}
			required := `require_fixed "$evidence_dir/readiness.json" '"repository_evidence_verified": true' "verified repository evidence"`
			if !strings.Contains(string(data), required) {
				t.Fatalf("%s must reject runtime evidence from an unstamped or mismatched repository build", name)
			}
		})
	}
}

func TestRuntimeSmokeAcceptsHeadlessAndDesktopDoctorStates(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"linux-runtime-smoke.sh", "bsd-runtime-smoke.sh"} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(filepath.Join("..", "..", "scripts", name))
			if err != nil {
				t.Fatal(err)
			}
			script := string(data)
			for _, required := range []string{
				`case "$doctor_exit" in`,
				`0) client_preflight=pass ;;`,
				`3) client_preflight=blocked ;;`,
				`expected 0 or 3`,
				`printf 'client_preflight=%s\n' "$client_preflight"`,
			} {
				if !strings.Contains(script, required) {
					t.Errorf("%s must record both desktop and headless doctor outcomes; missing %q", name, required)
				}
			}
		})
	}
}

func TestLinuxRuntimeSmokeResolvesBothPublishedArchitectures(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", "scripts", "linux-runtime-smoke.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, required := range []string{
		"runtime_machine=$(uname -m)",
		"x86_64|amd64) actual_arch=amd64",
		"aarch64|arm64) actual_arch=arm64",
		"sysctl -n hw.machine_arch",
		"uname -p 2>/dev/null",
		"printf 'machine=%s\\n' \"$runtime_machine\"",
		`require_fixed "$evidence_dir/doctor.json" "\"architecture\": \"$actual_arch\"" "runtime architecture $actual_arch"`,
	} {
		if !strings.Contains(script, required) {
			t.Errorf("linux-runtime-smoke.sh is missing architecture fragment %q", required)
		}
	}
}

func TestBSDPackageSmokeHandlesGuestToolingVariants(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", "scripts", "native-package-bsd-smoke.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, required := range []string{
		"/usr/local/libexec/leaguebridge/linux-bsd-client-smoke.sh",
		"/usr/local/libexec/leaguebridge/linux-bsd-remote-session.sh",
		"hash_package() {",
		"sha256sum \"$package_path\" | awk '{print $1}'",
		"sha256 -q \"$package_path\"",
		"openssl dgst -sha256 -r \"$package_path\"",
		"package_hash=$(sha256 \"$package_path\" | awk '{print $NF}')",
		"package_hash=$(openssl dgst -sha256 \"$package_path\" | awk '{print $NF}')",
		"*[!0-9A-Fa-f]*) fail \"SHA-256 utility returned an invalid package digest\"",
		"printf '%s  %s\\n' \"$(printf '%s' \"$package_hash\" | tr 'A-F' 'a-f')\" \"$package_path\"",
		"pkg_command=",
		"elif command -v pkg-static >/dev/null 2>&1; then",
		"pkg_command=$(command -v pkg)",
		"pkg_command=$(command -v pkg-static)",
		"BSD package tool did not resolve to an absolute path",
		"as_root \"$pkg_command\" delete -y \"$package_name\"",
		"native-package-bsd-smoke: command output before failure:",
		"if command -v pkg_create >/dev/null 2>&1; then",
		"package_root=\"$temporary_root/netbsd-package-root\"",
		"tar -czf \"$package_path_absolute\" \\",
		"+CONTENTS +COMMENT +DESC \\",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("BSD package smoke script is missing portability fragment %q", required)
		}
	}
	openBSDStart := strings.Index(script, "  openbsd)\n")
	netBSDStart := strings.Index(script, "  netbsd)\n")
	if openBSDStart < 0 || netBSDStart <= openBSDStart {
		t.Fatal("BSD package smoke script does not have ordered OpenBSD and NetBSD branches")
	}
	if strings.Contains(script[openBSDStart:netBSDStart], "@name $package_name") {
		t.Fatal("OpenBSD packing list must not duplicate the package name supplied to pkg_create")
	}
	for _, required := range []string{
		"installed_package_name=$package_name",
		"installed_package_name=\"$package_name-$expected_goos\"",
		"pkg_info -e \"$installed_package_name\"",
		"as_root pkg_delete -I \"$installed_package_name\"",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("BSD package smoke script is missing package-identity fragment %q", required)
		}
	}
}

func TestLinuxPackageSmokeInstallsRemoteSessionHelper(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", "scripts", "native-package-linux-smoke.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, required := range []string{
		"/usr/libexec/leaguebridge/linux-bsd-client-smoke.sh",
		"test -x \"$debian_scratch/usr/libexec/leaguebridge/linux-bsd-client-smoke.sh\"",
		"test -x \"$rpm_scratch/usr/libexec/leaguebridge/linux-bsd-client-smoke.sh\"",
		"/usr/libexec/leaguebridge/linux-bsd-remote-session.sh",
		"test -x \"$debian_scratch/usr/libexec/leaguebridge/linux-bsd-remote-session.sh\"",
		"test -x \"$rpm_scratch/usr/libexec/leaguebridge/linux-bsd-remote-session.sh\"",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("native-package-linux-smoke.sh is missing remote-session helper fragment %q", required)
		}
	}
}
