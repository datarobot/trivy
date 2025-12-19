package quantum

import (
	"encoding/json"
	"net/url"
	"path"
	"strings"

	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

type Parser struct {
	logger *log.Logger
}

func NewParser() *Parser {
	return &Parser{
		logger: log.WithPrefix("quantum"),
	}
}

// QuantumSpec represents the structure of quantum.spec.json
type QuantumSpec struct {
	Name         string   `json:"name"`
	LibraryName  string   `json:"library_name"`
	Version      string   `json:"version"`
	FullVersion  string   `json:"fullversion"`
	LibraryType  string   `json:"library_type"`
	License      string   `json:"license"`
	Upstream     string   `json:"upstream"`
	Platform     string   `json:"platform"`
	Python       string   `json:"python"`
	Dependencies []string `json:"dependencies"`
}

// Parse parses quantum.spec.json files
func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var spec QuantumSpec
	if err := json.NewDecoder(r).Decode(&spec); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode quantum.spec.json: %w", err)
	}

	// Extract the canonical package name from upstream URL
	pkgName := p.extractPackageName(spec)
	if pkgName == "" {
		p.logger.Debug("Unable to determine package name from quantum spec",
			log.String("quantum_name", spec.Name))
		return nil, nil, xerrors.New("unable to determine package name")
	}

	// Use the upstream version (without DataRobot suffix)
	version := spec.Version
	if version == "" {
		p.logger.Debug("Version is empty in quantum spec", log.String("name", spec.Name))
		return nil, nil, xerrors.New("version is empty")
	}

	pkg := ftypes.Package{
		ID:      pkgName + "@" + version,
		Name:    pkgName,
		Version: version,
	}

	// Add license if present
	if spec.License != "" {
		pkg.Licenses = []string{spec.License}
	}

	return []ftypes.Package{pkg}, nil, nil
}

// extractPackageName extracts the canonical package name from the quantum spec
func (p *Parser) extractPackageName(spec QuantumSpec) string {
	// Try to extract from upstream URL first
	if spec.Upstream != "" {
		if name := p.extractFromUpstream(spec.Upstream); name != "" {
			return name
		}
	}

	// Fall back to library_name if upstream parsing fails
	if spec.LibraryName != "" {
		return spec.LibraryName
	}

	return ""
}

// extractFromUpstream extracts the package name from an upstream URL
// For example: "https://curl.se/download/curl-7.88.1.tar.gz" -> "curl"
func (p *Parser) extractFromUpstream(upstream string) string {
	u, err := url.Parse(upstream)
	if err != nil {
		p.logger.Debug("Failed to parse upstream URL", log.String("url", upstream), log.Err(err))
		return ""
	}

	// Get the base name from the URL path
	// e.g., "curl-7.88.1.tar.gz"
	basename := path.Base(u.Path)

	// Remove common archive extensions
	for _, ext := range []string{".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip"} {
		basename = strings.TrimSuffix(basename, ext)
	}

	// Try to extract package name by removing version pattern
	// Examples:
	//   "curl-7.88.1" -> "curl"
	//   "openssl-1.1.1" -> "openssl"
	//   "libpng-1.6.37" -> "libpng"
	parts := strings.Split(basename, "-")
	if len(parts) >= 2 {
		// Check if the last part looks like a version (starts with a digit)
		lastPart := parts[len(parts)-1]
		if len(lastPart) > 0 && (lastPart[0] >= '0' && lastPart[0] <= '9') {
			// Return everything except the last part (the version)
			return strings.Join(parts[:len(parts)-1], "-")
		}
	}

	// If we can't determine from the pattern, return the whole basename
	return basename
}
