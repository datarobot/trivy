package quantum

import (
	"context"
	"io"
	"io/fs"
	"os"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python/quantum"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeQuantumPkg, newQuantumAnalyzer)
}

const version = 1

func newQuantumAnalyzer(opt analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &quantumAnalyzer{
		logger:    log.WithPrefix("quantum"),
		pkgParser: quantum.NewParser(),
	}, nil
}

type quantumAnalyzer struct {
	logger    *log.Logger
	pkgParser language.Parser
}

// PostAnalyze analyzes quantum.spec.json files within .dist-info directories
func (a quantumAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application

	required := func(path string, _ fs.DirEntry) bool {
		// Match quantum.spec.json files in .dist-info directories
		return strings.HasSuffix(path, ".dist-info/quantum.spec.json")
	}

	err := fsutils.WalkDir(input.FS, ".", required, func(filePath string, _ fs.DirEntry, r io.Reader) error {
		rsa, ok := r.(xio.ReadSeekerAt)
		if !ok {
			return xerrors.New("invalid reader")
		}

		app, err := a.parse(filePath, rsa, input.Options.FileChecksum)
		if err != nil {
			a.logger.Debug("Failed to parse quantum spec",
				log.String("file", filePath), log.Err(err))
			// Continue processing other files even if one fails
			return nil
		} else if app == nil {
			return nil
		}

		apps = append(apps, *app)
		return nil
	})

	if err != nil {
		return nil, xerrors.Errorf("quantum package walk error: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a quantumAnalyzer) parse(filePath string, r xio.ReadSeekerAt, checksum bool) (*types.Application, error) {
	return language.ParsePackage(types.Quantum, filePath, r, a.pkgParser, checksum)
}

func (a quantumAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	// Match quantum.spec.json files within .dist-info directories
	return strings.Contains(filePath, ".dist-info") && strings.HasSuffix(filePath, "quantum.spec.json")
}

func (a quantumAnalyzer) Type() analyzer.Type {
	return analyzer.TypeQuantumPkg
}

func (a quantumAnalyzer) Version() int {
	return version
}
