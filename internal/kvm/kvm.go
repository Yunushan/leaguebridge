// Package kvm provides a narrow, shell-free launcher for a hardware KVM web
// interface. It does not implement KVM video, HID, authentication, or any
// host-side League/Vanguard integration; the device and its browser session
// remain separately managed by the operator.
package kvm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Yunushan/leaguebridge/internal/config"
)

// Environment is the passive executable-discovery surface used by the KVM
// launcher. It deliberately contains no command execution or filesystem write
// operation.
type Environment interface {
	LookPath(file string) (string, error)
}

// Runner is the process boundary used after a validated plan is built. The
// application supplies its shell-free runner, so KVM launching shares the
// same process policy as the Moonlight handoff without making KVM a Moonlight
// backend.
type Runner interface {
	Run(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, name string, args ...string) error
}

// Launcher identifies one allowlisted desktop URL opener or direct browser.
type Launcher struct {
	Name   string   `json:"name"`
	Binary string   `json:"binary"`
	Prefix []string `json:"prefix,omitempty"`

	discovered       bool
	executableInfo   os.FileInfo
	discoveryBinding launcherBinding
}

type launcherBinding struct {
	name           string
	binary         string
	prefix         []string
	executableInfo os.FileInfo
}

func bindLauncher(launcher Launcher) launcherBinding {
	return launcherBinding{
		name:           launcher.Name,
		binary:         launcher.Binary,
		prefix:         append([]string(nil), launcher.Prefix...),
		executableInfo: launcher.executableInfo,
	}
}

func (binding launcherBinding) matches(launcher Launcher) bool {
	if binding.name != launcher.Name || binding.binary != launcher.Binary || len(binding.prefix) != len(launcher.Prefix) {
		return false
	}
	for index, value := range binding.prefix {
		if value != launcher.Prefix[index] {
			return false
		}
	}
	return true
}

// Request contains the explicit operator acknowledgements required before a
// browser process may be launched.
type Request struct {
	Endpoint                string
	AllowHTTP               bool
	PhysicalHostConfirmed   bool
	AcceptUnverifiedHandoff bool
}

// Plan is a fixed browser-launch argument vector. Private fields ensure that a
// decoded or mutated JSON value cannot be replayed as launch authority.
type Plan struct {
	Launcher  Launcher `json:"launcher"`
	Arguments []string `json:"arguments"`
	Warnings  []string `json:"warnings"`

	validated       bool
	launcherBinding launcherBinding
	argumentBinding []string
	endpoint        string
	allowHTTP       bool
}

// launcherNames is deliberately finite. The first entries are desktop URL
// openers; the remaining entries are common Linux/BSD browser binaries for
// desktops that do not install an opener helper. Direct browsers receive the
// endpoint as their only argument, so no profile, extension, or script flags
// can cross this boundary.
var launcherNames = []string{
	"xdg-open",
	"gio",
	"sensible-browser",
	"firefox",
	"firefox-esr",
	"chromium",
	"chromium-browser",
	"google-chrome",
	"google-chrome-stable",
	"brave",
	"brave-browser",
	"qutebrowser",
	"epiphany",
	"vivaldi",
	"vivaldi-stable",
}

var directBrowserNames = map[string]struct{}{
	"firefox":              {},
	"firefox-esr":          {},
	"chromium":             {},
	"chromium-browser":     {},
	"google-chrome":        {},
	"google-chrome-stable": {},
	"brave":                {},
	"brave-browser":        {},
	"qutebrowser":          {},
	"epiphany":             {},
	"vivaldi":              {},
	"vivaldi-stable":       {},
}

// Discover finds a known desktop URL opener or direct browser without starting
// it. The selection is intentionally allowlisted; arbitrary browser commands
// and shell snippets are not accepted.
func Discover(ctx context.Context, env Environment, preferred string) (Launcher, error) {
	if env == nil {
		return Launcher{}, errors.New("KVM browser discovery environment is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	preferred = strings.ToLower(strings.TrimSpace(preferred))
	if preferred == "" {
		preferred = "auto"
	}
	var candidates []string
	switch preferred {
	case "auto":
		candidates = launcherNames
	case "xdg-open", "gio", "sensible-browser":
		candidates = []string{preferred}
	default:
		if _, ok := directBrowserNames[preferred]; ok {
			candidates = []string{preferred}
			break
		}
		return Launcher{}, fmt.Errorf("unsupported KVM browser launcher %q; choose auto, xdg-open, gio, sensible-browser, or an installed allowlisted browser", preferred)
	}
	for _, name := range candidates {
		if err := ctx.Err(); err != nil {
			return Launcher{}, fmt.Errorf("KVM browser discovery canceled: %w", err)
		}
		path, err := env.LookPath(name)
		if err != nil {
			continue
		}
		if err := ctx.Err(); err != nil {
			return Launcher{}, fmt.Errorf("KVM browser discovery canceled: %w", err)
		}
		launcher := Launcher{Name: name, Binary: path, discovered: true}
		if name == "gio" {
			launcher.Prefix = []string{"open"}
		}
		// RealEnvironment has already checked this path during LookPath. Keep a
		// second private snapshot so Execute can reject a replacement between
		// passive discovery and the browser launch. Fixture environments may
		// return a synthetic path for dry-run composition and remain unbound.
		if info, statErr := os.Stat(path); statErr == nil && info.Mode().IsRegular() && (runtime.GOOS == "windows" || info.Mode().Perm()&0o111 != 0) {
			launcher.executableInfo = info
		}
		launcher.discoveryBinding = bindLauncher(launcher)
		return launcher, nil
	}
	if err := ctx.Err(); err != nil {
		return Launcher{}, fmt.Errorf("KVM browser discovery canceled: %w", err)
	}
	return Launcher{}, errors.New("no supported KVM browser launcher was found; install xdg-open, gio, sensible-browser, or an allowlisted browser such as firefox or chromium in the Linux/BSD desktop environment")
}

// ValidateEndpoint accepts only a clean HTTP(S) KVM UI endpoint. Credentials,
// query strings, fragments, and control characters are rejected so session
// tokens are not accidentally placed in a process argument or support output.
func ValidateEndpoint(endpoint string, allowHTTP bool) error {
	return config.ValidateKVMEndpoint(endpoint, allowHTTP)
}

// BuildPlan composes a pure plan. Callers that can launch a browser should use
// BuildDiscoveredPlan so an arbitrary launcher cannot cross the execution
// boundary.
func BuildPlan(launcher Launcher, request Request) (Plan, error) {
	if launcher.Binary == "" {
		return Plan{}, errors.New("KVM browser launcher path is empty")
	}
	if err := validateLauncher(launcher); err != nil {
		return Plan{}, err
	}
	if err := ValidateEndpoint(request.Endpoint, request.AllowHTTP); err != nil {
		return Plan{}, err
	}
	if !request.PhysicalHostConfirmed {
		return Plan{}, errors.New("KVM target is not confirmed as a physical Windows PC or Mac; LeagueBridge refuses VM handoffs")
	}
	if !request.AcceptUnverifiedHandoff {
		return Plan{}, errors.New("KVM control is an unverified physical-hardware handoff, not local Linux/BSD support; pass explicit acknowledgement to continue")
	}

	arguments := append([]string(nil), launcher.Prefix...)
	arguments = append(arguments, request.Endpoint)
	warnings := []string{
		"The KVM browser route is a manual candidate; League and Vanguard remain on the physical Windows or macOS host.",
		"LeagueBridge does not authenticate to, validate, or control the KVM device; use its own protected browser session on a private LAN or VPN.",
		"USB HID behavior and Riot/Vanguard acceptance remain unvalidated; stop immediately if Riot software reports an error.",
	}
	if strings.HasPrefix(strings.ToLower(request.Endpoint), "http://") {
		warnings = append(warnings, "The KVM endpoint uses unencrypted HTTP because --allow-http was supplied; limit it to a trusted LAN bootstrap and prefer HTTPS.")
	}
	return Plan{
		Launcher:        launcher,
		Arguments:       arguments,
		Warnings:        warnings,
		validated:       true,
		launcherBinding: bindLauncher(launcher),
		argumentBinding: append([]string(nil), arguments...),
		endpoint:        request.Endpoint,
		allowHTTP:       request.AllowHTTP,
	}, nil
}

// BuildDiscoveredPlan is the production plan builder.
func BuildDiscoveredPlan(launcher Launcher, request Request) (Plan, error) {
	if !launcher.discovered {
		return Plan{}, errors.New("KVM browser launcher was not discovered through the passive resolver")
	}
	if !launcher.discoveryBinding.matches(launcher) {
		return Plan{}, errors.New("KVM browser launcher changed after discovery")
	}
	return BuildPlan(launcher, request)
}

func validateLauncher(launcher Launcher) error {
	switch launcher.Name {
	case "xdg-open", "sensible-browser":
		if len(launcher.Prefix) != 0 {
			return fmt.Errorf("KVM launcher %q cannot have a command prefix", launcher.Name)
		}
	case "gio":
		if len(launcher.Prefix) != 1 || launcher.Prefix[0] != "open" {
			return errors.New("KVM gio launcher requires the fixed open prefix")
		}
	default:
		if _, ok := directBrowserNames[launcher.Name]; ok {
			if len(launcher.Prefix) != 0 {
				return fmt.Errorf("KVM browser %q cannot have a command prefix", launcher.Name)
			}
			return nil
		}
		return fmt.Errorf("unsupported KVM browser launcher %q", launcher.Name)
	}
	return nil
}

func validateArguments(launcher Launcher, arguments []string, allowHTTP bool) error {
	if err := validateLauncher(launcher); err != nil {
		return err
	}
	if len(arguments) != len(launcher.Prefix)+1 {
		return errors.New("KVM browser argument vector must contain exactly one endpoint URL")
	}
	for index, prefix := range launcher.Prefix {
		if arguments[index] != prefix {
			return errors.New("KVM browser argument vector contains an unexpected command prefix")
		}
	}
	return ValidateEndpoint(arguments[len(arguments)-1], allowHTTP)
}

func argumentsMatch(binding, arguments []string) bool {
	if len(binding) != len(arguments) {
		return false
	}
	for index, argument := range binding {
		if argument != arguments[index] {
			return false
		}
	}
	return true
}

// Execute is the only process boundary for the KVM helper. It accepts only a
// discovered, validated plan, an absolute regular executable, and the exact
// fixed argv captured by the planner.
func Execute(ctx context.Context, runner Runner, stdin io.Reader, stdout, stderr io.Writer, plan Plan) error {
	if !plan.validated {
		return errors.New("refusing to execute an unvalidated KVM plan; construct it with BuildDiscoveredPlan")
	}
	if !plan.Launcher.discovered {
		return errors.New("refusing to execute a KVM plan whose launcher was not discovered through the passive resolver")
	}
	if !plan.launcherBinding.matches(plan.Launcher) {
		return errors.New("refusing to execute a KVM plan whose discovered launcher was changed after planning")
	}
	if !argumentsMatch(plan.argumentBinding, plan.Arguments) {
		return errors.New("refusing to execute a KVM plan whose argument vector was changed after planning")
	}
	if err := validateArguments(plan.Launcher, plan.Arguments, plan.allowHTTP); err != nil {
		return fmt.Errorf("refusing to execute an invalid KVM argument vector: %w", err)
	}
	if !filepath.IsAbs(plan.Launcher.Binary) {
		return errors.New("refusing to execute a non-absolute KVM browser launcher path")
	}
	if plan.Launcher.executableInfo == nil {
		return errors.New("refusing to execute a KVM plan whose browser launcher was not bound by the real environment")
	}
	info, err := os.Stat(plan.Launcher.Binary)
	if err != nil {
		return fmt.Errorf("refusing to execute an unavailable KVM browser launcher: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("refusing to execute a non-regular KVM browser launcher")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		return errors.New("refusing to execute a non-executable KVM browser launcher")
	}
	if !os.SameFile(plan.Launcher.executableInfo, info) {
		return errors.New("refusing to execute a KVM plan whose browser launcher changed after discovery")
	}
	if runner == nil {
		return errors.New("refusing to execute a KVM plan with a nil runner")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("refusing to execute a canceled KVM handoff: %w", err)
	}
	if err := runner.Run(ctx, stdin, stdout, stderr, plan.Launcher.Binary, plan.Arguments...); err != nil {
		return fmt.Errorf("KVM browser handoff failed: %w", err)
	}
	return nil
}
