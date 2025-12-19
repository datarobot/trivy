package quantum

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		want     []ftypes.Package
		wantErr  string
	}{
		{
			name: "curl quantum package",
			file: "testdata/curl-quantum.spec.json",
			want: []ftypes.Package{
				{
					ID:       "curl@7.88.1",
					Name:     "curl",
					Version:  "7.88.1",
					Licenses: []string{"MIT"},
				},
			},
		},
		{
			name: "openssl quantum package",
			file: "testdata/openssl-quantum.spec.json",
			want: []ftypes.Package{
				{
					ID:       "openssl@1.1.1",
					Name:     "openssl",
					Version:  "1.1.1",
					Licenses: []string{"OpenSSL"},
				},
			},
		},
		{
			name: "libpng quantum package",
			file: "testdata/libpng-quantum.spec.json",
			want: []ftypes.Package{
				{
					ID:       "libpng@1.6.37",
					Name:     "libpng",
					Version:  "1.6.37",
					Licenses: []string{"libpng"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)
			defer f.Close()

			p := NewParser()
			got, _, err := p.Parse(f)

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParser_extractFromUpstream(t *testing.T) {
	tests := []struct {
		name     string
		upstream string
		want     string
	}{
		{
			name:     "curl with tar.gz",
			upstream: "https://curl.se/download/curl-7.88.1.tar.gz",
			want:     "curl",
		},
		{
			name:     "openssl with tar.gz",
			upstream: "https://www.openssl.org/source/openssl-1.1.1.tar.gz",
			want:     "openssl",
		},
		{
			name:     "libpng with tar.xz",
			upstream: "https://downloads.sourceforge.net/libpng/libpng-1.6.37.tar.xz",
			want:     "libpng",
		},
		{
			name:     "krb5 with tar.gz",
			upstream: "https://web.mit.edu/kerberos/dist/krb5/krb5-1.20.tar.gz",
			want:     "krb5",
		},
		{
			name:     "package with zip",
			upstream: "https://example.com/download/package-1.0.0.zip",
			want:     "package",
		},
		{
			name:     "package with tgz",
			upstream: "https://example.com/download/package-2.1.5.tgz",
			want:     "package",
		},
		{
			name:     "no version in name",
			upstream: "https://example.com/download/mypackage.tar.gz",
			want:     "mypackage",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser()
			got := p.extractFromUpstream(tt.upstream)
			assert.Equal(t, tt.want, got)
		})
	}
}
