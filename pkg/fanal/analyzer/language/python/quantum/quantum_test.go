package quantum

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_quantumAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name            string
		dir             string
		includeChecksum bool
		want            *analyzer.AnalysisResult
		wantErr         string
	}{
		{
			name:            "happy path with quantum packages",
			dir:             "testdata/happy",
			includeChecksum: false,
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Quantum,
						FilePath: "quantum_native_curl-7.88.1.post5+dr.dist-info/quantum.spec.json",
						Packages: types.Packages{
							{
								ID:       "curl@7.88.1",
								Name:     "curl",
								Version:  "7.88.1",
								Licenses: []string{"MIT"},
								FilePath: "quantum_native_curl-7.88.1.post5+dr.dist-info/quantum.spec.json",
							},
						},
					},
					{
						Type:     types.Quantum,
						FilePath: "quantum_native_openssl-1.1.1.post3+dr.dist-info/quantum.spec.json",
						Packages: types.Packages{
							{
								ID:       "openssl@1.1.1",
								Name:     "openssl",
								Version:  "1.1.1",
								Licenses: []string{"OpenSSL"},
								FilePath: "quantum_native_openssl-1.1.1.post3+dr.dist-info/quantum.spec.json",
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newQuantumAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(t.Context(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
				Options: analyzer.AnalysisOptions{
					FileChecksum: tt.includeChecksum,
				},
			})

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.ElementsMatch(t, tt.want.Applications, got.Applications)
		})
	}
}

func Test_quantumAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "quantum spec in dist-info",
			filePath: "quantum_native_curl-7.88.1.dist-info/quantum.spec.json",
			want:     true,
		},
		{
			name:     "quantum spec with complex path",
			filePath: "site-packages/quantum_native_openssl-1.1.1.post3+dr.dist-info/quantum.spec.json",
			want:     true,
		},
		{
			name:     "not a quantum spec file",
			filePath: "quantum_native_curl-7.88.1.dist-info/METADATA",
			want:     false,
		},
		{
			name:     "quantum.spec.json outside dist-info",
			filePath: "random/quantum.spec.json",
			want:     false,
		},
		{
			name:     "regular python package",
			filePath: "python3.8/site-packages/distlib-0.3.1.dist-info/METADATA",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := quantumAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
