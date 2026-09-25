package productionpackage

// inspectedFile is one normalized regular file declared in a native package's
// install payload. Its path is absolute within the target filesystem. Native
// format inspectors must reject links, devices, duplicate paths, and unreviewed
// install scripts before returning this summary.
type inspectedFile struct {
	Path   string
	Mode   string
	Size   int64
	SHA256 string
}

// inspectedPackage is a score-free observation of actual package metadata and
// payload bytes, not a publisher signature, repository receipt, or install run.
// Version uses the release tag form (for example, v1.2.3); architecture uses
// the matching nativepackage.Manifest.Package.Architecture value.
type inspectedPackage struct {
	Name         string
	Version      string
	Architecture string
	Files        []inspectedFile
}
