# PRDSEC-2938: junit.tpl names package, version, target and type for vulnerabilities

Jira: [PRDSEC-2938](https://datarobot.atlassian.net/browse/PRDSEC-2938)

## Problem
The SDTK daily security scan copies the junit failure text into Jira tickets. For vulnerabilities that text is only `Severity`, `Package Path (if available)` and `Description`. Trivy sets `PkgPath` only for language packages, so OS-package findings (apk/dpkg) show a blank path, and the ticket never names the package, installed version or image. 932 of 1,102 tickets carrying that line are blank.

## Change
`contrib/junit.tpl`, vulnerability test cases only. The failure text now reads:

```
Severity: HIGH
Package: libbrotlicommon1 1.2.0-r6
Fixed Version: 1.2.0-r7
Target: datarobotdev/ocr-dr:latest (alpine 3.22)
Type: os-pkgs/alpine
Package Path (if available): OS package (alpine package database)
Description: ...
```

- `Fixed Version` prints `none` when Trivy has no fixed version.
- `Package Path` falls back to `OS package (<type> package database)` for `os-pkgs` results and `n/a` for other results with no path.
- Values are passed through `escapeXML`. Test case names, `classname` and `file` are unchanged, so SDTK dedup hashes do not move.
- drone-trivy downloads this file from `main_datarobot` at image build time, so the change reaches the scan once drone-trivy is rebuilt.

## Testing
- Rendered with `trivy convert --format template --template @contrib/junit.tpl` (Trivy 0.72.0) on a sample report with one apk finding and one Python finding; output is well-formed XML and shows the lines above.
- Parsed the rendered XML with the SDTK `read_scan_results` from the companion sdtk branch.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
