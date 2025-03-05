package local

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	"github.com/aquasecurity/trivy/pkg/misconf"
	"github.com/aquasecurity/trivy/pkg/uuid"

	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/config/all"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/pip"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/apk"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/secret"
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/sysfile"
)

func TestArtifact_Inspect(t *testing.T) {
	type fields struct {
		dir string
	}
	tests := []struct {
		name               string
		fields             fields
		artifactOpt        artifact.Option
		scannerOpt         misconf.ScannerOption
		disabledAnalyzers  []analyzer.Type
		disabledHandlers   []types.HandlerType
		putBlobExpectation cache.ArtifactCachePutBlobExpectation
		want               artifact.Reference
		wantErr            string
	}{
		{
			name: "happy path",
			fields: fields{
				dir: "./testdata/alpine",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						OS: types.OS{
							Family: "alpine",
							Name:   "3.11.6",
						},
						PackageInfos: []types.PackageInfo{
							{
								FilePath: "lib/apk/db/installed",
								Packages: types.Packages{
									{
										ID:         "musl@1.1.24-r2",
										Name:       "musl",
										Version:    "1.1.24-r2",
										SrcName:    "musl",
										SrcVersion: "1.1.24-r2",
										Licenses:   []string{"MIT"},
										Arch:       "x86_64",
										Digest:     "sha1:cb2316a189ebee5282c4a9bd98794cc2477a74c6",
										InstalledFiles: []string{
											"lib/libc.musl-x86_64.so.1",
											"lib/ld-musl-x86_64.so.1",
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "host",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
		{
			name: "disable analyzers",
			fields: fields{
				dir: "./testdata/alpine",
			},
			artifactOpt: artifact.Option{
				DisabledAnalyzers: []analyzer.Type{
					analyzer.TypeAlpine,
					analyzer.TypeApk,
					analyzer.TypePip,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "host",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
		{
			name: "sad path PutBlob returns an error",
			fields: fields{
				dir: "./testdata/alpine",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						OS: types.OS{
							Family: "alpine",
							Name:   "3.11.6",
						},
						PackageInfos: []types.PackageInfo{
							{
								FilePath: "lib/apk/db/installed",
								Packages: types.Packages{
									{
										ID:         "musl@1.1.24-r2",
										Name:       "musl",
										Version:    "1.1.24-r2",
										SrcName:    "musl",
										SrcVersion: "1.1.24-r2",
										Licenses:   []string{"MIT"},
										Arch:       "x86_64",
										Digest:     "sha1:cb2316a189ebee5282c4a9bd98794cc2477a74c6",
										InstalledFiles: []string{
											"lib/libc.musl-x86_64.so.1",
											"lib/ld-musl-x86_64.so.1",
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{
					Err: errors.New("error"),
				},
			},
			wantErr: "failed to store blob",
		},
		{
			name: "sad path with no such directory",
			fields: fields{
				dir: "./testdata/unknown",
			},
			wantErr: "walk dir error",
		},
		{
			name: "happy path with single file",
			fields: fields{
				dir: "testdata/requirements.txt",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Applications: []types.Application{
							{
								Type:     "pip",
								FilePath: "requirements.txt",
								Packages: types.Packages{
									{
										Name:    "Flask",
										Version: "2.0.0",
										Locations: []types.Location{
											{
												StartLine: 1,
												EndLine:   1,
											},
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/requirements.txt",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
		{
			name: "happy path with single file using relative path",
			fields: fields{
				dir: "./testdata/requirements.txt",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobID: "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Applications: []types.Application{
							{
								Type:     "pip",
								FilePath: "requirements.txt",
								Packages: types.Packages{
									{
										Name:    "Flask",
										Version: "2.0.0",
										Locations: []types.Location{
											{
												StartLine: 1,
												EndLine:   1,
											},
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/requirements.txt",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set fake UUID for consistent test results
			uuid.SetFakeUUID(t, "3ff14136-e09f-4df9-80ea-%012d")

			c := cache.NewMockArtifactCache(t)
			c.ApplyPutBlobExpectation(tt.putBlobExpectation)

			a, err := NewArtifact(tt.fields.dir, c, walker.NewFS(), tt.artifactOpt)
			require.NoError(t, err)

			got, err := a.Inspect(context.Background())
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

var terraformPolicyMetadata = types.PolicyMetadata{
	ID:                 "TEST001",
	AVDID:              "AVD-TEST-0001",
	Type:               "Terraform Security Check",
	Title:              "Test policy",
	Description:        "This is a test policy.",
	Severity:           "LOW",
	RecommendedActions: "Have a cup of tea.",
	References:         []string{"https://trivy.dev/"},
}

func TestTerraformMisconfigurationScan(t *testing.T) {
	type fields struct {
		dir string
	}
	tests := []struct {
		name               string
		fields             fields
		putBlobExpectation cache.ArtifactCachePutBlobExpectation
		artifactOpt        artifact.Option
		want               artifact.Reference
	}{
		{
			name: "single failure",
			fields: fields{
				dir: "./testdata/misconfig/terraform/single-failure",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "terraform",
								FilePath: "main.tf",
								Failures: types.MisconfResults{
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										Message:        "Empty bucket name!",
										PolicyMetadata: terraformPolicyMetadata,
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.asd",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 1,
											EndLine:   3,
											Code: types.Code{
												Lines: []types.Line{
													{
														Number:      1,
														Content:     "resource \"aws_s3_bucket\" \"asd\" {",
														IsCause:     true,
														Highlighted: "\x1b[38;5;33mresource\x1b[0m \x1b[38;5;37m\"aws_s3_bucket\"\x1b[0m \x1b[38;5;37m\"asd\"\x1b[0m {",
														FirstCause:  true,
													},
													{
														Number:  2,
														IsCause: true,
													},
													{
														Number:      3,
														Content:     "}",
														IsCause:     true,
														Highlighted: "}",
														LastCause:   true,
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/terraform/single-failure",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
		{
			name: "multiple failures",
			fields: fields{
				dir: "./testdata/misconfig/terraform/multiple-failures",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "terraform",
								FilePath: "main.tf",
								Failures: types.MisconfResults{
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										Message:        "Empty bucket name!",
										PolicyMetadata: terraformPolicyMetadata,
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.one",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 1,
											EndLine:   3,
											Code: types.Code{
												Lines: []types.Line{
													{
														Number:      1,
														Content:     "resource \"aws_s3_bucket\" \"one\" {",
														IsCause:     true,
														Highlighted: "\x1b[38;5;33mresource\x1b[0m \x1b[38;5;37m\"aws_s3_bucket\"\x1b[0m \x1b[38;5;37m\"one\"\x1b[0m {",
														FirstCause:  true,
													},
													{
														Number:  2,
														IsCause: true,
													},
													{
														Number:      3,
														Content:     "}",
														IsCause:     true,
														Highlighted: "}",
														LastCause:   true,
													},
												},
											},
										},
									},
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										Message:        "Empty bucket name!",
										PolicyMetadata: terraformPolicyMetadata,
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.two",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 5,
											EndLine:   7,
											Code: types.Code{
												Lines: []types.Line{
													{
														Number:      5,
														Content:     "resource \"aws_s3_bucket\" \"two\" {",
														IsCause:     true,
														Highlighted: "\x1b[38;5;33mresource\x1b[0m \x1b[38;5;37m\"aws_s3_bucket\"\x1b[0m \x1b[38;5;37m\"two\"\x1b[0m {",
														FirstCause:  true,
													},
													{
														Number:  6,
														IsCause: true,
													},
													{
														Number:      7,
														Content:     "}",
														IsCause:     true,
														Highlighted: "}",
														LastCause:   true,
													},
												},
											},
										},
									},
								},
							},
							{
								FileType: "terraform",
								FilePath: "more.tf",
								Failures: types.MisconfResults{
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										Message:        "Empty bucket name!",
										PolicyMetadata: terraformPolicyMetadata,
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.three",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 1,
											EndLine:   3,
											Code: types.Code{
												Lines: []types.Line{
													{
														Number:      1,
														Content:     "resource \"aws_s3_bucket\" \"three\" {",
														IsCause:     true,
														Highlighted: "\x1b[38;5;33mresource\x1b[0m \x1b[38;5;37m\"aws_s3_bucket\"\x1b[0m \x1b[38;5;37m\"three\"\x1b[0m {",
														FirstCause:  true,
													},
													{
														Number:  2,
														IsCause: true,
													},
													{
														Number:      3,
														Content:     "}",
														IsCause:     true,
														Highlighted: "}",
														LastCause:   true,
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/terraform/multiple-failures",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
		{
			name: "no results",
			fields: fields{
				dir: "./testdata/misconfig/terraform/no-results",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/terraform/no-results",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
		{
			name: "passed",
			fields: fields{
				dir: "./testdata/misconfig/terraform/passed",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "terraform",
								FilePath: ".",
								Successes: types.MisconfResults{
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										PolicyMetadata: terraformPolicyMetadata,
										CauseMetadata: types.CauseMetadata{
											Provider: "Generic",
											Service:  "general",
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/terraform/passed",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
		{
			name: "multiple failures busted relative paths",
			fields: fields{
				dir: "./testdata/misconfig/terraform/busted-relative-paths/child/main.tf",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "terraform",
								FilePath: "main.tf",
								Failures: types.MisconfResults{
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										Message:        "Empty bucket name!",
										PolicyMetadata: terraformPolicyMetadata,
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.one",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 1,
											EndLine:   3,
											Code: types.Code{
												Lines: []types.Line{
													{
														Number:      1,
														Content:     "resource \"aws_s3_bucket\" \"one\" {",
														IsCause:     true,
														Highlighted: "\x1b[38;5;33mresource\x1b[0m \x1b[38;5;37m\"aws_s3_bucket\"\x1b[0m \x1b[38;5;37m\"one\"\x1b[0m {",
														FirstCause:  true,
													},
													{
														Number:  2,
														IsCause: true,
													},
													{
														Number:      3,
														Content:     " }",
														IsCause:     true,
														Highlighted: " }",
														LastCause:   true,
													},
												},
											},
										},
									},
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										Message:        "Empty bucket name!",
										PolicyMetadata: terraformPolicyMetadata,
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.two",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 5,
											EndLine:   7,
											Code: types.Code{
												Lines: []types.Line{
													{
														Number:      5,
														Content:     " resource \"aws_s3_bucket\" \"two\" {",
														IsCause:     true,
														Highlighted: "\x1b[38;5;33m resource\x1b[0m \x1b[38;5;37m\"aws_s3_bucket\"\x1b[0m \x1b[38;5;37m\"two\"\x1b[0m {",
														FirstCause:  true,
													},
													{
														Number:  6,
														IsCause: true,
													},
													{
														Number:      7,
														Content:     " }",
														IsCause:     true,
														Highlighted: " }",
														LastCause:   true,
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/terraform/busted-relative-paths/child/main.tf",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
		{
			name: "tfvars outside the scan folder",
			fields: fields{
				dir: "./testdata/misconfig/terraform/tfvar-outside/tf",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					TerraformTFVars: []string{"./testdata/misconfig/terraform/tfvar-outside/main.tfvars"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: types.Terraform,
								FilePath: ".",
								Successes: types.MisconfResults{
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										PolicyMetadata: terraformPolicyMetadata,
										CauseMetadata: types.CauseMetadata{
											Provider: "Generic",
											Service:  "general",
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/terraform/tfvar-outside/tf",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
		{
			name: "relative paths",
			fields: fields{
				dir: "./testdata/misconfig/terraform/relative-paths/child",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: types.Terraform,
								FilePath: "../parent/main.tf",
								Failures: types.MisconfResults{
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										Message:        "Empty bucket name!",
										PolicyMetadata: terraformPolicyMetadata,
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.three",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 1,
											EndLine:   3,
											Code: types.Code{
												Lines: []types.Line{
													{
														Number:      1,
														Content:     "resource \"aws_s3_bucket\" \"three\" {",
														IsCause:     true,
														Highlighted: "\x1b[38;5;33mresource\x1b[0m \x1b[38;5;37m\"aws_s3_bucket\"\x1b[0m \x1b[38;5;37m\"three\"\x1b[0m {",
														FirstCause:  true,
													},
													{
														Number:  2,
														IsCause: true,
													},
													{
														Number:      3,
														Content:     "}",
														IsCause:     true,
														Highlighted: "}",
														LastCause:   true,
													},
												},
											},
										},
									},
								},
							},
							{
								FileType: types.Terraform,
								FilePath: "main.tf",
								Failures: types.MisconfResults{
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										Message:        "Empty bucket name!",
										PolicyMetadata: terraformPolicyMetadata,
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.one",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 1,
											EndLine:   3,
											Code: types.Code{
												Lines: []types.Line{
													{
														Number:      1,
														Content:     "resource \"aws_s3_bucket\" \"one\" {",
														IsCause:     true,
														Highlighted: "\x1b[38;5;33mresource\x1b[0m \x1b[38;5;37m\"aws_s3_bucket\"\x1b[0m \x1b[38;5;37m\"one\"\x1b[0m {",
														FirstCause:  true,
													},
													{
														Number:  2,
														IsCause: true,
													},
													{
														Number:      3,
														Content:     "}",
														IsCause:     true,
														Highlighted: "}",
														LastCause:   true,
													},
												},
											},
										},
									},
								},
							},
							{
								FileType: types.Terraform,
								FilePath: "nested/main.tf",
								Failures: types.MisconfResults{
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										Message:        "Empty bucket name!",
										PolicyMetadata: terraformPolicyMetadata,
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.two",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 1,
											EndLine:   3,
											Code: types.Code{
												Lines: []types.Line{
													{
														Number:      1,
														Content:     "resource \"aws_s3_bucket\" \"two\" {",
														IsCause:     true,
														Highlighted: "\x1b[38;5;33mresource\x1b[0m \x1b[38;5;37m\"aws_s3_bucket\"\x1b[0m \x1b[38;5;37m\"two\"\x1b[0m {",
														FirstCause:  true,
													},
													{
														Number:  2,
														IsCause: true,
													},
													{
														Number:      3,
														Content:     "}",
														IsCause:     true,
														Highlighted: "}",
														LastCause:   true,
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/terraform/relative-paths/child",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set fake UUID for consistent test results
			uuid.SetFakeUUID(t, "3ff14136-e09f-4df9-80ea-%012d")

			c := cache.NewMockArtifactCache(t)
			c.ApplyPutBlobExpectation(tt.putBlobExpectation)
			tt.artifactOpt.DisabledHandlers = []types.HandlerType{
				types.SystemFileFilteringPostHandler,
			}
			tt.artifactOpt.MisconfScannerOption.DisableEmbeddedPolicies = true
			tt.artifactOpt.MisconfScannerOption.Namespaces = []string{"user"}
			tt.artifactOpt.MisconfScannerOption.PolicyPaths = []string{"./testdata/misconfig/terraform/rego"}
			a, err := NewArtifact(tt.fields.dir, c, walker.NewFS(), tt.artifactOpt)
			require.NoError(t, err)

			got, err := a.Inspect(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

const emptyBucketCheck = `package user.something

__rego_metadata__ := {
	"id": "TEST001",
	"avd_id": "AVD-TEST-0001",
	"title": "Test policy",
	"short_code": "empty-bucket-name",
	"severity": "LOW",
	"description": "This is a test policy.",
	"recommended_actions": "Have a cup of tea.",
	"url": "https://trivy.dev/",
}

# taken from defsec rego lib to mimic behaviour
result(msg, cause) = result {
	metadata := object.get(cause, "__defsec_metadata", cause)
	result := {
		"msg": msg,
		"startline": object.get(metadata, "startline", 0),
		"endline": object.get(metadata, "endline", 0),
		"filepath": object.get(metadata, "filepath", ""),
		"explicit": object.get(metadata, "explicit", false),
		"managed": object.get(metadata, "managed", true),
		"fskey": object.get(metadata, "fskey", ""),
		"resource": object.get(metadata, "resource", ""),
	}
}

deny[res] {
	bucket := input.aws.s3.buckets[_]
	bucket.name.value == ""
	res := result("Empty bucket name!", bucket)
}`

var terraformPlanPolicyMetadata = types.PolicyMetadata{
	ID:                 "TEST001",
	AVDID:              "AVD-TEST-0001",
	Type:               "Terraform Plan Snapshot Security Check",
	Title:              "Test policy",
	Description:        "This is a test policy.",
	Severity:           "LOW",
	RecommendedActions: "Have a cup of tea.",
	References:         []string{"https://trivy.dev/"},
}

func TestTerraformPlanSnapshotMisconfScan(t *testing.T) {
	type fields struct {
		dir string
	}
	tests := []struct {
		name               string
		fields             fields
		putBlobExpectation cache.ArtifactCachePutBlobExpectation
		want               artifact.Reference
	}{
		{
			name: "single failure",
			fields: fields{

				dir: "./testdata/misconfig/terraformplan/snapshots/single-failure",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: types.TerraformPlanSnapshot,
								FilePath: "main.tf",
								Failures: types.MisconfResults{
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										Message:        "Empty bucket name!",
										PolicyMetadata: terraformPlanPolicyMetadata,
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.this",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 10,
											EndLine:   12,
											Code: types.Code{
												Lines: []types.Line{
													{
														Number:      10,
														Content:     "resource \"aws_s3_bucket\" \"this\" {",
														IsCause:     true,
														Highlighted: "\x1b[38;5;33mresource\x1b[0m \x1b[38;5;37m\"aws_s3_bucket\"\x1b[0m \x1b[38;5;37m\"this\"\x1b[0m {",
														FirstCause:  true,
													},
													{
														Number:  11,
														IsCause: true,
													},
													{
														Number:      12,
														Content:     "}",
														IsCause:     true,
														Highlighted: "}",
														LastCause:   true,
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/terraformplan/snapshots/single-failure",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
		{
			name: "multiple failures",
			fields: fields{
				dir: "./testdata/misconfig/terraformplan/snapshots/multiple-failures",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: types.TerraformPlanSnapshot,
								FilePath: "main.tf",
								Failures: types.MisconfResults{
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										Message:        "Empty bucket name!",
										PolicyMetadata: terraformPlanPolicyMetadata,
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.one",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 10,
											EndLine:   12,
											Code: types.Code{
												Lines: []types.Line{
													{
														Number:      10,
														Content:     "resource \"aws_s3_bucket\" \"one\" {",
														IsCause:     true,
														Highlighted: "\x1b[38;5;33mresource\x1b[0m \x1b[38;5;37m\"aws_s3_bucket\"\x1b[0m \x1b[38;5;37m\"one\"\x1b[0m {",
														FirstCause:  true,
													},
													{
														Number:  11,
														IsCause: true,
													},
													{
														Number:      12,
														Content:     "}",
														IsCause:     true,
														Highlighted: "}",
														LastCause:   true,
													},
												},
											},
										},
									},
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										Message:        "Empty bucket name!",
										PolicyMetadata: terraformPlanPolicyMetadata,
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.two",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 14,
											EndLine:   16,
											Code: types.Code{
												Lines: []types.Line{
													{
														Number:      14,
														Content:     "resource \"aws_s3_bucket\" \"two\" {",
														IsCause:     true,
														Highlighted: "\x1b[38;5;33mresource\x1b[0m \x1b[38;5;37m\"aws_s3_bucket\"\x1b[0m \x1b[38;5;37m\"two\"\x1b[0m {",
														FirstCause:  true,
													},
													{
														Number:  15,
														IsCause: true,
													},
													{
														Number:      16,
														Content:     "}",
														IsCause:     true,
														Highlighted: "}",
														LastCause:   true,
													},
												},
											},
										},
									},
								},
							},
							{
								FileType: types.TerraformPlanSnapshot,
								FilePath: "more.tf",
								Failures: types.MisconfResults{
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										Message:        "Empty bucket name!",
										PolicyMetadata: terraformPlanPolicyMetadata,
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.three",
											Provider:  "Generic",
											Service:   "general",
											StartLine: 1,
											EndLine:   3,
											Code: types.Code{
												Lines: []types.Line{
													{
														Number:      1,
														Content:     "resource \"aws_s3_bucket\" \"three\" {",
														IsCause:     true,
														Highlighted: "\x1b[38;5;33mresource\x1b[0m \x1b[38;5;37m\"aws_s3_bucket\"\x1b[0m \x1b[38;5;37m\"three\"\x1b[0m {",
														FirstCause:  true,
													},
													{
														Number:  2,
														IsCause: true,
													},
													{
														Number:      3,
														Content:     "}",
														IsCause:     true,
														Highlighted: "}",
														LastCause:   true,
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/terraformplan/snapshots/multiple-failures",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
		{
			name: "passed",
			fields: fields{
				dir: "./testdata/misconfig/terraformplan/snapshots/passed",
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: types.TerraformPlanSnapshot,
								FilePath: ".",
								Successes: types.MisconfResults{
									{
										Namespace:      "user.something",
										Query:          "data.user.something.deny",
										PolicyMetadata: terraformPlanPolicyMetadata,
										CauseMetadata: types.CauseMetadata{
											Provider: "Generic",
											Service:  "general",
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/terraformplan/snapshots/passed",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set fake UUID for consistent test results
			uuid.SetFakeUUID(t, "3ff14136-e09f-4df9-80ea-%012d")

			tmpDir := t.TempDir()
			f, err := os.Create(filepath.Join(tmpDir, "policy.rego"))
			require.NoError(t, err)
			defer f.Close()

			_, err = f.WriteString(emptyBucketCheck)
			require.NoError(t, err)

			c := cache.NewMockArtifactCache(t)
			c.ApplyPutBlobExpectation(tt.putBlobExpectation)

			opt := artifact.Option{
				DisabledHandlers: []types.HandlerType{
					types.SystemFileFilteringPostHandler,
				},
				MisconfScannerOption: misconf.ScannerOption{
					DisableEmbeddedPolicies:  true,
					DisableEmbeddedLibraries: false,
					Namespaces:               []string{"user"},
					PolicyPaths:              []string{tmpDir},
				},
				WalkerOption: walker.Option{
					SkipFiles: []string{"*.tf"},
				},
			}
			a, err := NewArtifact(tt.fields.dir, c, walker.NewFS(), opt)
			require.NoError(t, err)

			got, err := a.Inspect(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCloudFormationMisconfigurationScan(t *testing.T) {
	type fields struct {
		dir string
	}
	tests := []struct {
		name               string
		fields             fields
		putBlobExpectation cache.ArtifactCachePutBlobExpectation
		artifactOpt        artifact.Option
		want               artifact.Reference
	}{
		{
			name: "single failure",
			fields: fields{
				dir: "./testdata/misconfig/cloudformation/single-failure/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					Namespaces:               []string{"user"},
					PolicyPaths:              []string{"./testdata/misconfig/cloudformation/single-failure/rego"},
					DisableEmbeddedLibraries: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "cloudformation",
								FilePath: "main.yaml",
								Failures: types.MisconfResults{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No buckets allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "CloudFormation Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References:         []string{"https://trivy.dev/"},
										},
										CauseMetadata: types.CauseMetadata{
											Resource:  "main.yaml:3-6",
											Provider:  "Cloud",
											Service:   "general",
											StartLine: 3,
											EndLine:   6,
											Code: types.Code{
												Lines: []types.Line{
													{
														Number:      3,
														Content:     "  S3Bucket:",
														IsCause:     true,
														Highlighted: "  \x1b[38;5;33mS3Bucket\x1b[0m:",
														FirstCause:  true,
													},
													{
														Number:      4,
														Content:     "    Type: 'AWS::S3::Bucket'",
														IsCause:     true,
														Highlighted: "    \x1b[38;5;33mType\x1b[0m: \x1b[38;5;37m'AWS::S3::Bucket'",
													},
													{
														Number:      5,
														Content:     "    Properties:",
														IsCause:     true,
														Highlighted: "\x1b[0m    \x1b[38;5;33mProperties\x1b[0m:",
													},
													{
														Number:      6,
														Content:     "      BucketName: public-bucket",
														IsCause:     true,
														Highlighted: "      \x1b[38;5;33mBucketName\x1b[0m: public-bucket",
														LastCause:   true,
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/cloudformation/single-failure/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
		{
			name: "multiple failures",
			fields: fields{
				dir: "./testdata/misconfig/cloudformation/multiple-failures/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					Namespaces:               []string{"user"},
					PolicyPaths:              []string{"./testdata/misconfig/cloudformation/multiple-failures/rego"},
					DisableEmbeddedLibraries: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "cloudformation",
								FilePath: "main.yaml",
								Failures: types.MisconfResults{
									types.MisconfResult{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No buckets allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "CloudFormation Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References:         []string{"https://trivy.dev/"},
										},
										CauseMetadata: types.CauseMetadata{
											Resource:  "main.yaml:2-5",
											Provider:  "Cloud",
											Service:   "general",
											StartLine: 2,
											EndLine:   5,
											Code: types.Code{
												Lines: []types.Line{
													{
														Number:      2,
														Content:     "  S3BucketOne:",
														IsCause:     true,
														Highlighted: "  \x1b[38;5;33mS3BucketOne\x1b[0m:",
														FirstCause:  true,
													},
													{
														Number:      3,
														Content:     "    Type: 'AWS::S3::Bucket'",
														IsCause:     true,
														Highlighted: "    \x1b[38;5;33mType\x1b[0m: \x1b[38;5;37m'AWS::S3::Bucket'",
													},
													{
														Number:      4,
														Content:     "    Properties:",
														IsCause:     true,
														Highlighted: "\x1b[0m    \x1b[38;5;33mProperties\x1b[0m:",
													},
													{
														Number:      5,
														Content:     "      BucketName: bucket-one",
														IsCause:     true,
														Highlighted: "      \x1b[38;5;33mBucketName\x1b[0m: bucket-one",
														LastCause:   true,
													},
												},
											},
										},
									},
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No buckets allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "CloudFormation Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References:         []string{"https://trivy.dev/"},
										},
										CauseMetadata: types.CauseMetadata{
											Resource:  "main.yaml:6-9",
											Provider:  "Cloud",
											Service:   "general",
											StartLine: 6,
											EndLine:   9,
											Code: types.Code{
												Lines: []types.Line{
													{
														Number:      6,
														Content:     "  S3BucketTwo:",
														IsCause:     true,
														Highlighted: "  \x1b[38;5;33mS3BucketTwo\x1b[0m:",
														FirstCause:  true,
													},
													{
														Number:      7,
														Content:     "    Type: 'AWS::S3::Bucket'",
														IsCause:     true,
														Highlighted: "    \x1b[38;5;33mType\x1b[0m: \x1b[38;5;37m'AWS::S3::Bucket'",
													},
													{
														Number:      8,
														Content:     "    Properties:",
														IsCause:     true,
														Highlighted: "\x1b[0m    \x1b[38;5;33mProperties\x1b[0m:",
													},
													{
														Number:      9,
														Content:     "      BucketName: bucket-two",
														IsCause:     true,
														Highlighted: "      \x1b[38;5;33mBucketName\x1b[0m: bucket-two",
														LastCause:   true,
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/cloudformation/multiple-failures/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
		{
			name: "no results",
			fields: fields{
				dir: "./testdata/misconfig/cloudformation/no-results/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					Namespaces:               []string{"user"},
					PolicyPaths:              []string{"./testdata/misconfig/cloudformation/no-results/rego"},
					DisableEmbeddedLibraries: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/cloudformation/no-results/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
		{
			name: "CloudFormation parameters outside the scan directory",
			fields: fields{
				dir: "./testdata/misconfig/cloudformation/params/code/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					Namespaces:               []string{"user"},
					PolicyPaths:              []string{"./testdata/misconfig/cloudformation/params/code/rego"},
					CloudFormationParamVars:  []string{"./testdata/misconfig/cloudformation/params/cfparams.json"},
					DisableEmbeddedLibraries: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "cloudformation",
								FilePath: "main.yaml",
								Successes: types.MisconfResults{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "CloudFormation Security Check",
											Title:              "Bad stuff is bad",
											Description:        "Its not good!",
											Severity:           "HIGH",
											RecommendedActions: "Remove bad stuff",
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "AWS",
											Service:  "sqs",
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/cloudformation/params/code/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
		{
			name: "passed",
			fields: fields{
				dir: "./testdata/misconfig/cloudformation/passed/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					Namespaces:               []string{"user"},
					PolicyPaths:              []string{"./testdata/misconfig/cloudformation/passed/rego"},
					DisableEmbeddedLibraries: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "cloudformation",
								FilePath: "main.yaml",
								Successes: types.MisconfResults{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "CloudFormation Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References:         []string{"https://trivy.dev/"},
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "Cloud",
											Service:  "general",
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/cloudformation/passed/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set fake UUID for consistent test results
			uuid.SetFakeUUID(t, "3ff14136-e09f-4df9-80ea-%012d")

			c := cache.NewMockArtifactCache(t)
			c.ApplyPutBlobExpectation(tt.putBlobExpectation)
			tt.artifactOpt.DisabledHandlers = []types.HandlerType{
				types.SystemFileFilteringPostHandler,
			}
			tt.artifactOpt.MisconfScannerOption.DisableEmbeddedPolicies = true
			a, err := NewArtifact(tt.fields.dir, c, walker.NewFS(), tt.artifactOpt)
			require.NoError(t, err)

			got, err := a.Inspect(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDockerfileMisconfigurationScan(t *testing.T) {
	type fields struct {
		dir string
	}
	tests := []struct {
		name               string
		fields             fields
		putBlobExpectation cache.ArtifactCachePutBlobExpectation
		artifactOpt        artifact.Option
		want               artifact.Reference
	}{
		{
			name: "single failure",
			fields: fields{
				dir: "./testdata/misconfig/dockerfile/single-failure/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					Namespaces:               []string{"user"},
					PolicyPaths:              []string{"./testdata/misconfig/dockerfile/single-failure/rego"},
					DisableEmbeddedLibraries: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "dockerfile",
								FilePath: "Dockerfile",
								Successes: types.MisconfResults{
									types.MisconfResult{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "Dockerfile Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References:         []string{"https://trivy.dev/"},
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "Generic",
											Service:  "general",
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/dockerfile/single-failure/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
		{
			name: "multiple failures",
			fields: fields{
				dir: "./testdata/misconfig/dockerfile/multiple-failures/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					Namespaces:               []string{"user"},
					PolicyPaths:              []string{"./testdata/misconfig/dockerfile/multiple-failures/rego"},
					DisableEmbeddedLibraries: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "dockerfile",
								FilePath: "Dockerfile",
								Successes: types.MisconfResults{
									types.MisconfResult{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "Dockerfile Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References:         []string{"https://trivy.dev/"},
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "Generic",
											Service:  "general",
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/dockerfile/multiple-failures/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
		{
			name: "no results",
			fields: fields{
				dir: "./testdata/misconfig/dockerfile/no-results/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					Namespaces:  []string{"user"},
					PolicyPaths: []string{"./testdata/misconfig/dockerfile/no-results/rego"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/dockerfile/no-results/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
		{
			name: "passed",
			fields: fields{
				dir: "./testdata/misconfig/dockerfile/passed/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					Namespaces:               []string{"user"},
					PolicyPaths:              []string{"./testdata/misconfig/dockerfile/passed/rego"},
					DisableEmbeddedLibraries: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "dockerfile",
								FilePath: "Dockerfile",
								Successes: []types.MisconfResult{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "Dockerfile Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References: []string{
												"https://trivy.dev/",
											},
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "Generic",
											Service:  "general",
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/dockerfile/passed/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set fake UUID for consistent test results
			uuid.SetFakeUUID(t, "3ff14136-e09f-4df9-80ea-%012d")

			c := cache.NewMockArtifactCache(t)
			c.ApplyPutBlobExpectation(tt.putBlobExpectation)
			tt.artifactOpt.DisabledHandlers = []types.HandlerType{
				types.SystemFileFilteringPostHandler,
			}
			tt.artifactOpt.MisconfScannerOption.DisableEmbeddedPolicies = true
			a, err := NewArtifact(tt.fields.dir, c, walker.NewFS(), tt.artifactOpt)
			require.NoError(t, err)

			got, err := a.Inspect(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestKubernetesMisconfigurationScan(t *testing.T) {
	type fields struct {
		dir string
	}
	tests := []struct {
		name               string
		fields             fields
		putBlobExpectation cache.ArtifactCachePutBlobExpectation
		artifactOpt        artifact.Option
		want               artifact.Reference
	}{
		{
			name: "single failure",
			fields: fields{
				dir: "./testdata/misconfig/kubernetes/single-failure/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					Namespaces:               []string{"user"},
					PolicyPaths:              []string{"./testdata/misconfig/kubernetes/single-failure/rego"},
					DisableEmbeddedLibraries: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "kubernetes",
								FilePath: "test.yaml",
								Failures: []types.MisconfResult{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No evil containers allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "Kubernetes Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References: []string{
												"https://trivy.dev/",
											},
										},
										CauseMetadata: types.CauseMetadata{
											Provider:  "Kubernetes",
											Service:   "general",
											StartLine: 7,
											EndLine:   9,
											Code: types.Code{
												Lines: []types.Line{
													{
														Number:      7,
														Content:     "    - command: [ \"sh\", \"-c\", \"echo 'Hello' && sleep 1h\" ]",
														IsCause:     true,
														Highlighted: "    - \x1b[38;5;33mcommand\x1b[0m: [ \x1b[38;5;37m\"sh\"\x1b[0m, \x1b[38;5;37m\"-c\"\x1b[0m, \x1b[38;5;37m\"echo 'Hello' && sleep 1h\"\x1b[0m ]",
														FirstCause:  true,
													},
													{
														Number:      8,
														Content:     "      image: evil",
														IsCause:     true,
														Highlighted: "      \x1b[38;5;33mimage\x1b[0m: evil",
													},
													{
														Number:      9,
														Content:     "      name: evil",
														IsCause:     true,
														Highlighted: "      \x1b[38;5;33mname\x1b[0m: evil",
														LastCause:   true,
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/kubernetes/single-failure/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
		{
			name: "multiple failures",
			fields: fields{
				dir: "./testdata/misconfig/kubernetes/multiple-failures/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					Namespaces:               []string{"user"},
					PolicyPaths:              []string{"./testdata/misconfig/kubernetes/multiple-failures/rego"},
					DisableEmbeddedLibraries: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "kubernetes",
								FilePath: "test.yaml",
								Failures: []types.MisconfResult{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No evil containers allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "Kubernetes Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References: []string{
												"https://trivy.dev/",
											},
										},
										CauseMetadata: types.CauseMetadata{
											Provider:  "Kubernetes",
											Service:   "general",
											StartLine: 7,
											EndLine:   9,
											Code: types.Code{
												Lines: []types.Line{
													{
														Number:      7,
														Content:     "    - command: [ \"sh\", \"-c\", \"echo 'Hello' && sleep 1h\" ]",
														IsCause:     true,
														Highlighted: "    - \x1b[38;5;33mcommand\x1b[0m: [ \x1b[38;5;37m\"sh\"\x1b[0m, \x1b[38;5;37m\"-c\"\x1b[0m, \x1b[38;5;37m\"echo 'Hello' && sleep 1h\"\x1b[0m ]",
														FirstCause:  true,
													},
													{
														Number:      8,
														Content:     "      image: evil",
														IsCause:     true,
														Highlighted: "      \x1b[38;5;33mimage\x1b[0m: evil",
													},
													{
														Number:      9,
														Content:     "      name: evil1",
														IsCause:     true,
														Highlighted: "      \x1b[38;5;33mname\x1b[0m: evil1",
														LastCause:   true,
													},
												},
											},
										},
									},
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No evil containers allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "Kubernetes Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References: []string{
												"https://trivy.dev/",
											},
										},
										CauseMetadata: types.CauseMetadata{
											Provider:  "Kubernetes",
											Service:   "general",
											StartLine: 10,
											EndLine:   12,
											Code: types.Code{
												Lines: []types.Line{
													{
														Number:      10,
														Content:     "    - command: [ \"sh\", \"-c\", \"echo 'Hello' && sleep 1h\" ]",
														IsCause:     true,
														Highlighted: "    - \x1b[38;5;33mcommand\x1b[0m: [ \x1b[38;5;37m\"sh\"\x1b[0m, \x1b[38;5;37m\"-c\"\x1b[0m, \x1b[38;5;37m\"echo 'Hello' && sleep 1h\"\x1b[0m ]",
														FirstCause:  true,
													},
													{
														Number:      11,
														Content:     "      image: evil",
														IsCause:     true,
														Highlighted: "      \x1b[38;5;33mimage\x1b[0m: evil",
													},
													{
														Number:      12,
														Content:     "      name: evil2",
														IsCause:     true,
														Highlighted: "      \x1b[38;5;33mname\x1b[0m: evil2",
														LastCause:   true,
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/kubernetes/multiple-failures/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
		{
			name: "no results",
			fields: fields{
				dir: "./testdata/misconfig/kubernetes/no-results/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					Namespaces:  []string{"user"},
					PolicyPaths: []string{"./testdata/misconfig/kubernetes/no-results/rego"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/kubernetes/no-results/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
		{
			name: "passed",
			fields: fields{
				dir: "./testdata/misconfig/kubernetes/passed/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					Namespaces:               []string{"user"},
					PolicyPaths:              []string{"./testdata/misconfig/kubernetes/passed/rego"},
					DisableEmbeddedLibraries: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "kubernetes",
								FilePath: "test.yaml",
								Successes: []types.MisconfResult{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "Kubernetes Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References: []string{
												"https://trivy.dev/",
											},
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "Kubernetes",
											Service:  "general",
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/kubernetes/passed/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set fake UUID for consistent test results
			uuid.SetFakeUUID(t, "3ff14136-e09f-4df9-80ea-%012d")

			c := cache.NewMockArtifactCache(t)
			c.ApplyPutBlobExpectation(tt.putBlobExpectation)
			tt.artifactOpt.DisabledHandlers = []types.HandlerType{
				types.SystemFileFilteringPostHandler,
			}
			tt.artifactOpt.MisconfScannerOption.DisableEmbeddedPolicies = true
			a, err := NewArtifact(tt.fields.dir, c, walker.NewFS(), tt.artifactOpt)
			require.NoError(t, err)

			got, err := a.Inspect(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAzureARMMisconfigurationScan(t *testing.T) {
	type fields struct {
		dir string
	}
	tests := []struct {
		name               string
		fields             fields
		putBlobExpectation cache.ArtifactCachePutBlobExpectation
		artifactOpt        artifact.Option
		want               artifact.Reference
	}{
		{
			name: "single failure",
			fields: fields{
				dir: "./testdata/misconfig/azurearm/single-failure/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					Namespaces:  []string{"user"},
					PolicyPaths: []string{"./testdata/misconfig/azurearm/single-failure/rego"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "azure-arm",
								FilePath: "deploy.json",
								Failures: types.MisconfResults{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No account allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "Azure ARM Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References:         []string{"https://trivy.dev/"},
										},
										CauseMetadata: types.CauseMetadata{
											Resource:  "resources[0]",
											Provider:  "Cloud",
											Service:   "general",
											StartLine: 30,
											EndLine:   40,
											Code: types.Code{
												Lines: []types.Line{
													{
														Number:      30,
														Content:     "    {",
														IsCause:     true,
														Highlighted: "    {",
														FirstCause:  true,
													},
													{
														Number:      31,
														Content:     "      \"type\": \"Microsoft.Storage/storageAccounts\",",
														IsCause:     true,
														Highlighted: "      \x1b[38;5;33m\"type\"\x1b[0m: \x1b[38;5;37m\"Microsoft.Storage/storageAccounts\"\x1b[0m,",
													},
													{
														Number:      32,
														Content:     "      \"name\": \"[variables('storageAccountName')]\",",
														IsCause:     true,
														Highlighted: "      \x1b[38;5;33m\"name\"\x1b[0m: \x1b[38;5;37m\"[variables('storageAccountName')]\"\x1b[0m,",
													},
													{
														Number:      33,
														Content:     "      \"location\": \"[parameters('location')]\",",
														IsCause:     true,
														Highlighted: "      \x1b[38;5;33m\"location\"\x1b[0m: \x1b[38;5;37m\"[parameters('location')]\"\x1b[0m,",
													},
													{
														Number:      34,
														Content:     "      \"apiVersion\": \"2018-07-01\",",
														IsCause:     true,
														Highlighted: "      \x1b[38;5;33m\"apiVersion\"\x1b[0m: \x1b[38;5;37m\"2018-07-01\"\x1b[0m,",
													},
													{
														Number:      35,
														Content:     "      \"sku\": {",
														IsCause:     true,
														Highlighted: "      \x1b[38;5;33m\"sku\"\x1b[0m: {",
													},
													{
														Number:      36,
														Content:     "        \"name\": \"[parameters('storageAccountType')]\"",
														IsCause:     true,
														Highlighted: "        \x1b[38;5;33m\"name\"\x1b[0m: \x1b[38;5;37m\"[parameters('storageAccountType')]\"",
													},
													{
														Number:      37,
														Content:     "      },",
														IsCause:     true,
														Highlighted: "\x1b[0m      },",
													},
													{
														Number:      38,
														Content:     "      \"kind\": \"StorageV2\",",
														IsCause:     true,
														Highlighted: "      \x1b[38;5;33m\"kind\"\x1b[0m: \x1b[38;5;37m\"StorageV2\"\x1b[0m,",
														LastCause:   true,
													},
													{
														Number:    39,
														IsCause:   false,
														Truncated: true,
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/azurearm/single-failure/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
		{
			name: "multiple failures",
			fields: fields{
				dir: "./testdata/misconfig/azurearm/multiple-failures/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					Namespaces:  []string{"user"},
					PolicyPaths: []string{"./testdata/misconfig/azurearm/multiple-failures/rego"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "azure-arm",
								FilePath: "deploy.json",
								Failures: types.MisconfResults{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No account allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "Azure ARM Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References:         []string{"https://trivy.dev/"},
										},
										CauseMetadata: types.CauseMetadata{
											Resource:  "resources[0]",
											Provider:  "Cloud",
											Service:   "general",
											StartLine: 30,
											EndLine:   40,
											Code: types.Code{
												Lines: []types.Line{
													{
														Number:      30,
														Content:     "    {",
														IsCause:     true,
														Highlighted: "    {",
														FirstCause:  true,
													},
													{
														Number:      31,
														Content:     "      \"type\": \"Microsoft.Storage/storageAccounts\",",
														IsCause:     true,
														Highlighted: "      \x1b[38;5;33m\"type\"\x1b[0m: \x1b[38;5;37m\"Microsoft.Storage/storageAccounts\"\x1b[0m,",
													},
													{
														Number:      32,
														Content:     "      \"name\": \"[variables('storageAccountName')]\",",
														IsCause:     true,
														Highlighted: "      \x1b[38;5;33m\"name\"\x1b[0m: \x1b[38;5;37m\"[variables('storageAccountName')]\"\x1b[0m,",
													},
													{
														Number:      33,
														Content:     "      \"location\": \"[parameters('location')]\",",
														IsCause:     true,
														Highlighted: "      \x1b[38;5;33m\"location\"\x1b[0m: \x1b[38;5;37m\"[parameters('location')]\"\x1b[0m,",
													},
													{
														Number:      34,
														Content:     "      \"apiVersion\": \"2018-07-01\",",
														IsCause:     true,
														Highlighted: "      \x1b[38;5;33m\"apiVersion\"\x1b[0m: \x1b[38;5;37m\"2018-07-01\"\x1b[0m,",
													},
													{
														Number:      35,
														Content:     "      \"sku\": {",
														IsCause:     true,
														Highlighted: "      \x1b[38;5;33m\"sku\"\x1b[0m: {",
													},
													{
														Number:      36,
														Content:     "        \"name\": \"[parameters('storageAccountType')]\"",
														IsCause:     true,
														Highlighted: "        \x1b[38;5;33m\"name\"\x1b[0m: \x1b[38;5;37m\"[parameters('storageAccountType')]\"",
													},
													{
														Number:      37,
														Content:     "      },",
														IsCause:     true,
														Highlighted: "\x1b[0m      },",
													},
													{
														Number:      38,
														Content:     "      \"kind\": \"StorageV2\",",
														IsCause:     true,
														Highlighted: "      \x1b[38;5;33m\"kind\"\x1b[0m: \x1b[38;5;37m\"StorageV2\"\x1b[0m,",
														LastCause:   true,
													},
													{
														Number:    39,
														IsCause:   false,
														Truncated: true,
													},
												},
											},
										},
									},
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No account allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "Azure ARM Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References:         []string{"https://trivy.dev/"},
										},
										CauseMetadata: types.CauseMetadata{
											Resource:  "resources[1]",
											Provider:  "Cloud",
											Service:   "general",
											StartLine: 41,
											EndLine:   51,
											Code: types.Code{
												Lines: []types.Line{
													{
														Number:      41,
														Content:     "    {",
														IsCause:     true,
														Highlighted: "    {",
														FirstCause:  true,
													},
													{
														Number:      42,
														Content:     "      \"type\": \"Microsoft.Storage/storageAccounts\",",
														IsCause:     true,
														Highlighted: "      \x1b[38;5;33m\"type\"\x1b[0m: \x1b[38;5;37m\"Microsoft.Storage/storageAccounts\"\x1b[0m,",
													},
													{
														Number:      43,
														Content:     "      \"name\": \"bucket2\",",
														IsCause:     true,
														Highlighted: "      \x1b[38;5;33m\"name\"\x1b[0m: \x1b[38;5;37m\"bucket2\"\x1b[0m,",
													},
													{
														Number:      44,
														Content:     "      \"location\": \"[parameters('location')]\",",
														IsCause:     true,
														Highlighted: "      \x1b[38;5;33m\"location\"\x1b[0m: \x1b[38;5;37m\"[parameters('location')]\"\x1b[0m,",
													},
													{
														Number:      45,
														Content:     "      \"apiVersion\": \"2018-07-01\",",
														IsCause:     true,
														Highlighted: "      \x1b[38;5;33m\"apiVersion\"\x1b[0m: \x1b[38;5;37m\"2018-07-01\"\x1b[0m,",
													},
													{
														Number:      46,
														Content:     "      \"sku\": {",
														IsCause:     true,
														Highlighted: "      \x1b[38;5;33m\"sku\"\x1b[0m: {",
													},
													{
														Number:      47,
														Content:     "        \"name\": \"[parameters('storageAccountType')]\"",
														IsCause:     true,
														Highlighted: "        \x1b[38;5;33m\"name\"\x1b[0m: \x1b[38;5;37m\"[parameters('storageAccountType')]\"",
													},
													{
														Number:      48,
														Content:     "      },",
														IsCause:     true,
														Highlighted: "\x1b[0m      },",
													},
													{
														Number:      49,
														Content:     "      \"kind\": \"StorageV2\",",
														IsCause:     true,
														Highlighted: "      \x1b[38;5;33m\"kind\"\x1b[0m: \x1b[38;5;37m\"StorageV2\"\x1b[0m,",
														LastCause:   true,
													},
													{
														Number:    50,
														IsCause:   false,
														Truncated: true,
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/azurearm/multiple-failures/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
		{
			name: "no results",
			fields: fields{
				dir: "./testdata/misconfig/azurearm/no-results/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					Namespaces:  []string{"user"},
					PolicyPaths: []string{"./testdata/misconfig/azurearm/no-results/rego"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/azurearm/no-results/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
		{
			name: "passed",
			fields: fields{
				dir: "./testdata/misconfig/azurearm/passed/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					Namespaces:  []string{"user"},
					PolicyPaths: []string{"./testdata/misconfig/azurearm/passed/rego"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "azure-arm",
								FilePath: "deploy.json",
								Successes: types.MisconfResults{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "Azure ARM Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References:         []string{"https://trivy.dev/"},
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "Cloud",
											Service:  "general",
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/azurearm/passed/src",
				Type: artifact.TypeFilesystem,
				ID:   "sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				BlobIDs: []string{
					"sha256:6f4672e139d4066fd00391df614cdf42bda5f7a3f005d39e1d8600be86157098",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set fake UUID for consistent test results
			uuid.SetFakeUUID(t, "3ff14136-e09f-4df9-80ea-%012d")

			c := cache.NewMockArtifactCache(t)
			c.ApplyPutBlobExpectation(tt.putBlobExpectation)
			tt.artifactOpt.DisabledHandlers = []types.HandlerType{
				types.SystemFileFilteringPostHandler,
			}
			tt.artifactOpt.MisconfScannerOption.DisableEmbeddedPolicies = true
			a, err := NewArtifact(tt.fields.dir, c, walker.NewFS(), tt.artifactOpt)
			require.NoError(t, err)

			got, err := a.Inspect(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMixedConfigurationScan(t *testing.T) {
	type fields struct {
		dir string
	}
	tests := []struct {
		name               string
		fields             fields
		putBlobExpectation cache.ArtifactCachePutBlobExpectation
		artifactOpt        artifact.Option
		want               artifact.Reference
	}{
		{
			name: "single failure each within terraform and cloudformation",
			fields: fields{
				dir: "./testdata/misconfig/mixed/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					Namespaces:               []string{"user"},
					PolicyPaths:              []string{"./testdata/misconfig/mixed/rego"},
					DisableEmbeddedLibraries: true,
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: 2,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: "cloudformation",
								FilePath: "main.yaml",
								Failures: types.MisconfResults{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No buckets allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "CloudFormation Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References:         []string{"https://trivy.dev/"},
										},
										CauseMetadata: types.CauseMetadata{
											Resource:  "main.yaml:3-6",
											Provider:  "Cloud",
											Service:   "general",
											StartLine: 3,
											EndLine:   6,
											Code: types.Code{
												Lines: []types.Line{
													{
														Number:      3,
														Content:     "  S3Bucket:",
														IsCause:     true,
														Highlighted: "  \x1b[38;5;33mS3Bucket\x1b[0m:",
														FirstCause:  true,
													},
													{
														Number:      4,
														Content:     "    Type: 'AWS::S3::Bucket'",
														IsCause:     true,
														Highlighted: "    \x1b[38;5;33mType\x1b[0m: \x1b[38;5;37m'AWS::S3::Bucket'",
													},
													{
														Number:      5,
														Content:     "    Properties:",
														IsCause:     true,
														Highlighted: "\x1b[0m    \x1b[38;5;33mProperties\x1b[0m:",
													},
													{
														Number:      6,
														Content:     "      BucketName: public-bucket",
														IsCause:     true,
														Highlighted: "      \x1b[38;5;33mBucketName\x1b[0m: public-bucket",
														LastCause:   true,
													},
												},
											},
										},
									},
								},
							},
							{
								FileType: "terraform",
								FilePath: "main.tf",
								Failures: types.MisconfResults{
									{
										Namespace: "user.something",
										Query:     "data.user.something.deny",
										Message:   "No buckets allowed!",
										PolicyMetadata: types.PolicyMetadata{
											ID:                 "TEST001",
											AVDID:              "AVD-TEST-0001",
											Type:               "Terraform Security Check",
											Title:              "Test policy",
											Description:        "This is a test policy.",
											Severity:           "LOW",
											RecommendedActions: "Have a cup of tea.",
											References:         []string{"https://trivy.dev/"},
										},
										CauseMetadata: types.CauseMetadata{
											Resource:  "aws_s3_bucket.asd",
											Provider:  "Cloud",
											Service:   "general",
											StartLine: 1,
											EndLine:   3,
											Code: types.Code{
												Lines: []types.Line{
													{
														Number:      1,
														Content:     "resource \"aws_s3_bucket\" \"asd\" {",
														IsCause:     true,
														Highlighted: "\x1b[38;5;33mresource\x1b[0m \x1b[38;5;37m\"aws_s3_bucket\"\x1b[0m \x1b[38;5;37m\"asd\"\x1b[0m {",
														FirstCause:  true,
													},
													{
														Number:  2,
														IsCause: true,
													},
													{
														Number:      3,
														Content:     " }",
														IsCause:     true,
														Highlighted: " }",
														LastCause:   true,
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/mixed/src",
				Type: artifact.TypeFilesystem,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cache.NewMockArtifactCache(t)
			c.ApplyPutBlobExpectation(tt.putBlobExpectation)
			tt.artifactOpt.DisabledHandlers = []types.HandlerType{
				types.SystemFileFilteringPostHandler,
			}
			tt.artifactOpt.MisconfScannerOption.DisableEmbeddedPolicies = true
			a, err := NewArtifact(tt.fields.dir, c, walker.NewFS(), tt.artifactOpt)
			require.NoError(t, err)

			got, err := a.Inspect(context.Background())
			require.NoError(t, err)
			require.NotNil(t, got)

			assert.Equal(t, tt.want.Name, got.Name)
			assert.Equal(t, tt.want.Type, got.Type)
		})
	}
}

func TestJSONConfigScan(t *testing.T) {
	type fields struct {
		dir     string
		schemas []string
	}

	tests := []struct {
		name               string
		fields             fields
		artifactOpt        artifact.Option
		putBlobExpectation cache.ArtifactCachePutBlobExpectation
		want               artifact.Reference
	}{
		{
			name: "happy path without custom schema",
			fields: fields{
				dir: "./testdata/misconfig/json/passed/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					Namespaces:  []string{"user"},
					PolicyPaths: []string{"./testdata/misconfig/json/passed/checks"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: types.JSON,
								FilePath: "test1.json",
								Failures: types.MisconfResults{
									{
										Namespace: "user.test_json_check",
										Query:     "data.user.test_json_check.deny",
										Message:   `Service "foo" should not be used`,
										PolicyMetadata: types.PolicyMetadata{
											ID:       "TEST001",
											AVDID:    "TEST001",
											Type:     "JSON Security Check",
											Title:    "Test check",
											Severity: "LOW",
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "Generic",
											Service:  "general",
										},
									},
								},
							},
							{
								FileType: types.JSON,
								FilePath: "test2.json",
								Failures: types.MisconfResults{
									{
										Namespace: "user.test_json_check",
										Query:     "data.user.test_json_check.deny",
										Message:   `Provider "bar" should not be used`,
										PolicyMetadata: types.PolicyMetadata{
											ID:       "TEST001",
											AVDID:    "TEST001",
											Type:     "JSON Security Check",
											Title:    "Test check",
											Severity: "LOW",
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "Generic",
											Service:  "general",
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/json/passed/src",
				Type: artifact.TypeFilesystem,
			},
		},
		{
			name: "happy path with custom schema",
			fields: fields{
				dir:     "./testdata/misconfig/json/with-schema/src",
				schemas: []string{"./testdata/misconfig/json/with-schema/schemas"},
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					Namespaces:  []string{"user"},
					PolicyPaths: []string{"./testdata/misconfig/json/with-schema/checks"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: types.JSON,
								FilePath: "test1.json",
								Failures: types.MisconfResults{
									{
										Namespace: "user.test_json_check",
										Query:     "data.user.test_json_check.deny",
										Message:   `Service "foo" should not be used`,
										PolicyMetadata: types.PolicyMetadata{
											ID:       "TEST001",
											AVDID:    "TEST001",
											Type:     "JSON Security Check",
											Title:    "Test check",
											Severity: "LOW",
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "Generic",
											Service:  "general",
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/json/with-schema/src",
				Type: artifact.TypeFilesystem,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cache.NewMockArtifactCache(t)
			c.ApplyPutBlobExpectation(tt.putBlobExpectation)

			tt.artifactOpt.MisconfScannerOption.DisableEmbeddedPolicies = true
			if len(tt.fields.schemas) > 0 {
				schemas, err := misconf.LoadConfigSchemas(tt.fields.schemas)
				require.NoError(t, err)
				tt.artifactOpt.MisconfScannerOption.ConfigFileSchemas = schemas
			}

			a, err := NewArtifact(tt.fields.dir, c, walker.NewFS(), tt.artifactOpt)
			require.NoError(t, err)

			got, err := a.Inspect(context.Background())
			require.NoError(t, err)
			require.NotNil(t, got)

			assert.Equal(t, tt.want.Name, got.Name)
			assert.Equal(t, tt.want.Type, got.Type)
		})
	}
}

func TestYAMLConfigScan(t *testing.T) {
	type fields struct {
		dir     string
		schemas []string
	}

	tests := []struct {
		name               string
		fields             fields
		artifactOpt        artifact.Option
		putBlobExpectation cache.ArtifactCachePutBlobExpectation
		want               artifact.Reference
	}{
		{
			name: "happy path without custom schema",
			fields: fields{
				dir: "./testdata/misconfig/yaml/passed/src",
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					Namespaces:  []string{"user"},
					PolicyPaths: []string{"./testdata/misconfig/yaml/passed/checks"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: types.YAML,
								FilePath: "test1.yaml",
								Failures: types.MisconfResults{
									{
										Namespace: "user.test_yaml_check",
										Query:     "data.user.test_yaml_check.deny",
										Message:   `Service "foo" should not be used`,
										PolicyMetadata: types.PolicyMetadata{
											ID:       "TEST001",
											AVDID:    "TEST001",
											Type:     "YAML Security Check",
											Title:    "Test check",
											Severity: "LOW",
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "Generic",
											Service:  "general",
										},
									},
								},
							},
							{
								FileType: types.YAML,
								FilePath: "test2.yml",
								Failures: types.MisconfResults{
									{
										Namespace: "user.test_yaml_check",
										Query:     "data.user.test_yaml_check.deny",
										Message:   `Provider "bar" should not be used`,
										PolicyMetadata: types.PolicyMetadata{
											ID:       "TEST001",
											AVDID:    "TEST001",
											Type:     "YAML Security Check",
											Title:    "Test check",
											Severity: "LOW",
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "Generic",
											Service:  "general",
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/yaml/passed/src",
				Type: artifact.TypeFilesystem,
			},
		},
		{
			name: "happy path with custom schema",
			fields: fields{
				dir:     "./testdata/misconfig/yaml/with-schema/src",
				schemas: []string{"./testdata/misconfig/yaml/with-schema/schemas"},
			},
			artifactOpt: artifact.Option{
				MisconfScannerOption: misconf.ScannerOption{
					Namespaces:  []string{"user"},
					PolicyPaths: []string{"./testdata/misconfig/yaml/with-schema/checks"},
				},
			},
			putBlobExpectation: cache.ArtifactCachePutBlobExpectation{
				Args: cache.ArtifactCachePutBlobArgs{
					BlobIDAnything: true,
					BlobInfo: types.BlobInfo{
						SchemaVersion: types.BlobJSONSchemaVersion,
						Misconfigurations: []types.Misconfiguration{
							{
								FileType: types.YAML,
								FilePath: "test1.yaml",
								Failures: types.MisconfResults{
									{
										Namespace: "user.test_yaml_check",
										Query:     "data.user.test_yaml_check.deny",
										Message:   `Service "foo" should not be used`,
										PolicyMetadata: types.PolicyMetadata{
											ID:       "TEST001",
											AVDID:    "TEST001",
											Type:     "YAML Security Check",
											Title:    "Test check",
											Severity: "LOW",
										},
										CauseMetadata: types.CauseMetadata{
											Provider: "Generic",
											Service:  "general",
										},
									},
								},
							},
						},
					},
				},
				Returns: cache.ArtifactCachePutBlobReturns{},
			},
			want: artifact.Reference{
				Name: "testdata/misconfig/yaml/with-schema/src",
				Type: artifact.TypeFilesystem,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cache.NewMockArtifactCache(t)
			c.ApplyPutBlobExpectation(tt.putBlobExpectation)

			tt.artifactOpt.MisconfScannerOption.DisableEmbeddedPolicies = true
			if len(tt.fields.schemas) > 0 {
				schemas, err := misconf.LoadConfigSchemas(tt.fields.schemas)
				require.NoError(t, err)
				tt.artifactOpt.MisconfScannerOption.ConfigFileSchemas = schemas
			}

			a, err := NewArtifact(tt.fields.dir, c, walker.NewFS(), tt.artifactOpt)
			require.NoError(t, err)

			got, err := a.Inspect(context.Background())
			require.NoError(t, err)
			require.NotNil(t, got)

			assert.Equal(t, tt.want.Name, got.Name)
			assert.Equal(t, tt.want.Type, got.Type)
		})
	}
}
