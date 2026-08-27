package probe

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const maximumCommandOutput = 64 * 1024

type systemFileSystem struct{}

func (systemFileSystem) Stat(name string) (fs.FileInfo, error) { return os.Lstat(name) }

type systemEnvironment struct{}

func (systemEnvironment) LookupEnv(key string) (string, bool) { return os.LookupEnv(key) }

// systemCommands intentionally supports a much smaller surface than os/exec.
// Discovery is read-only. Execution is restricted to exact registry queries
// needed by the Windows host preflight. Service state uses the Windows API.
type systemCommands struct{}

var discoverableCommands = map[string]struct{}{
	"ffmpeg":       {},
	"flatpak":      {},
	"moonlight":    {},
	"moonlight-qt": {},
	"sunshine":     {},
	"sunshine.exe": {},
	"vainfo":       {},
	"vdpauinfo":    {},
}

func (systemCommands) LookPath(name string) (string, error) {
	if name != filepath.Base(name) {
		return "", errors.New("command discovery requires a base name")
	}
	if _, ok := discoverableCommands[strings.ToLower(name)]; !ok {
		return "", errors.New("command is not allowlisted for discovery")
	}
	return exec.LookPath(name)
}

func (systemCommands) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	base := strings.ToLower(filepath.Base(name))
	if name != filepath.Base(name) || !validCommandArguments(base, args) {
		return CommandResult{ExitCode: -1}, errors.New("command is not allowlisted")
	}
	executable, err := trustedSystemExecutable(base)
	if err != nil {
		return CommandResult{ExitCode: -1}, err
	}

	// Impose a hard ceiling even if a caller supplies a longer-lived context.
	commandCtx, cancel := context.WithTimeout(ctx, maximumCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(commandCtx, executable, args...)
	cmd.Stdin = nil
	var output limitedBuffer
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	err = cmd.Run()
	result := CommandResult{Output: output.String(), ExitCode: 0, Truncated: output.truncated}
	if err == nil {
		return result, nil
	}
	if commandCtx.Err() != nil {
		result.ExitCode = -1
		return result, commandCtx.Err()
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		result.ExitCode = exitError.ExitCode()
		return result, nil
	}
	result.ExitCode = -1
	return result, errors.New("allowlisted command could not be started")
}

func validCommandArguments(command string, args []string) bool {
	switch command {
	case "reg", "reg.exe":
		if len(args) != 4 || !strings.EqualFold(args[0], "query") || !strings.EqualFold(args[2], "/v") {
			return false
		}
		values, ok := allowedRegistryQueries[strings.ToUpper(args[1])]
		if !ok {
			return false
		}
		_, ok = values[strings.ToLower(args[3])]
		return ok
	default:
		return false
	}
}

var allowedRegistryQueries = map[string]map[string]struct{}{
	`HKLM\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION`: {
		"currentbuild":       {},
		"currentbuildnumber": {},
		"installationtype":   {},
		"productname":        {},
	},
	`HKLM\HARDWARE\DESCRIPTION\SYSTEM\BIOS`: {
		"baseboardmanufacturer": {},
		"baseboardproduct":      {},
		"systemmanufacturer":    {},
		"systemproductname":     {},
	},
	`HKLM\SOFTWARE\MICROSOFT\DIRECTX`: {
		"version": {},
	},
	`HKLM\SYSTEM\CURRENTCONTROLSET\CONTROL\SECUREBOOT\STATE`: {
		"uefisecurebootenabled": {},
	},
	`HKLM\SYSTEM\CURRENTCONTROLSET\CONTROL\DEVICEGUARD`: {
		"enablevirtualizationbasedsecurity": {},
	},
	`HKLM\SYSTEM\CURRENTCONTROLSET\CONTROL\DEVICEGUARD\SCENARIOS\HYPERVISORENFORCEDCODEINTEGRITY`: {
		"enabled": {},
	},
}

type limitedBuffer struct {
	buffer    bytes.Buffer
	truncated bool
}

func (b *limitedBuffer) Write(data []byte) (int, error) {
	originalLength := len(data)
	remaining := maximumCommandOutput - b.buffer.Len()
	if remaining <= 0 {
		b.truncated = b.truncated || originalLength > 0
		return originalLength, nil
	}
	if len(data) > remaining {
		data = data[:remaining]
		b.truncated = true
	}
	_, _ = b.buffer.Write(data)
	return originalLength, nil
}

func (b *limitedBuffer) String() string { return b.buffer.String() }

func parseRegistryValue(output, expectedName string) (string, bool) {
	if len(output) > maximumCommandOutput {
		return "", false
	}
	for _, line := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || !strings.EqualFold(fields[0], expectedName) || !strings.HasPrefix(strings.ToUpper(fields[1]), "REG_") {
			continue
		}
		value := strings.TrimSpace(strings.Join(fields[2:], " "))
		if value != "" && len(value) <= 512 {
			return value, true
		}
	}
	return "", false
}

func parseBuild(value string) (int, bool) {
	if value == "" || len(value) > 10 {
		return 0, false
	}
	build, err := strconv.Atoi(value)
	return build, err == nil && build > 0
}
