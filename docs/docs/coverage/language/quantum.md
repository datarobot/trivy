# Quantum

Trivy supports DataRobot Quantum packages - native system libraries packaged in Python wheel format.

## Overview

DataRobot uses an internal tool called "quantum-builders" that builds relocatable versions of system software (such as curl, krb5, openssl, libpng, etc.) and packages them into Python wheel format. These wheels are then installed into virtual environments using `pip`.

Trivy detects these quantum packages and maps them to their upstream equivalents for CVE detection.

## Support

The following scanners are supported.

| Package manager | SBOM | Vulnerability | License |
|-----------------|:----:|:-------------:|:-------:|
| Quantum         |  ✓   |       ✓       |    ✓    |

The following table provides an outline of the features Trivy offers.

| Package manager | File                  | Transitive dependencies | Dev dependencies | Position |
|-----------------|-----------------------|:-----------------------:|:----------------:|:--------:|
| Quantum         | quantum.spec.json[^1] |            -            |        -         |    ✓     |

## Detection

Trivy searches for `quantum.spec.json` files within `.dist-info` directories. These files are created by quantum-builders' `stamp_env()` function when packaging quantum wheels.

### Quantum Spec Structure

The `quantum.spec.json` file contains metadata about the quantum package:

```json
{
  "name": "quantum-native-curl",
  "library_name": "curl",
  "version": "7.88.1",
  "fullversion": "7.88.1.post5+dr",
  "suffix": ".post5+dr",
  "library_type": "native",
  "license": "MIT",
  "upstream": "https://curl.se/download/curl-7.88.1.tar.gz",
  "platform": "linux-x86_64",
  "python": "any",
  "dependencies": ["quantum-native-openssl==1.1.1.post3+dr"],
  "changelog": []
}
```

### Package Name Extraction

Trivy extracts the canonical package name from the `upstream` field:

1. Parses the upstream URL (e.g., `https://curl.se/download/curl-7.88.1.tar.gz`)
2. Extracts the base filename and removes archive extensions
3. Removes version suffix to get the package name (e.g., `curl-7.88.1` → `curl`)
4. Falls back to the `library_name` field if URL parsing fails

### Version Mapping

Trivy uses the `version` field (upstream version without DataRobot suffix) rather than the `fullversion` field to match against vulnerability databases.

For example:
- `version`: `7.88.1` (used for CVE matching)
- `fullversion`: `7.88.1.post5+dr` (internal DataRobot version)

## Vulnerability Detection

Quantum packages are checked against the Conan ecosystem in the vulnerability database, which covers C/C++ packages and their vulnerabilities from:

- GitLab Advisory Database
- National Vulnerability Database (NVD)
- Other C/C++ security advisories

## Example

Given a container with quantum packages installed:

```bash
$ trivy image my-image:latest
```

Trivy will:
1. Detect `.dist-info/quantum.spec.json` files
2. Parse metadata to extract library name and version
3. Create package entries (e.g., `curl@7.88.1`)
4. Check against vulnerability databases
5. Report any CVEs found

## Limitations

- Transitive dependencies are not analyzed (quantum packages list dependencies but Trivy treats each package independently)
- Only native C/C++ library quantum packages are supported
- Vulnerability data is limited to what's available in the Conan/GitLab Advisory Database

[^1]: Located in `.dist-info` directories, e.g., `quantum_native_curl-7.88.1.post5+dr.dist-info/quantum.spec.json`
