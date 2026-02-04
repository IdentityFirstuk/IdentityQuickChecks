# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- GitHub Actions CI/CD workflow for automated testing
- PowerShell 7 compatibility layer (`IdentityFirst.QuickChecks.Compatibility.psm1`)
- Pester unit tests for core functionality
- Pester unit tests for EntraID and Azure checks
- CONTRIBUTING.md with coding standards and guidelines
- Code review documentation (`docs/CODE-REVIEW.md`)

### Changed

- Fixed encoding issues in Lite, EntraID, Extended, and Validation modules
- Improved PowerShell 5.1 syntax compatibility
- Added configurable thresholds to all modules
- Added finding helper functions

## [1.1.0] - 2026-01-30

### Added

- PowerShell 7 cross-platform support
- Compatibility layer for Windows-only functions
- GitHub Actions CI/CD pipeline

### Fixed

- Encoding issues causing PowerShell 5.1 parse errors
- Unicode character compatibility across PowerShell versions

### Changed

- Improved error handling in all modules
- Enhanced documentation

## [1.0.0] - 2024-12-01

### Added

- Initial release of IdentityFirst QuickChecks
- Core identity checks (BreakGlassReality, IdentityNamingHygiene, PasswordPolicyDrift, PrivilegedNestingAbuse)
- Identity trust checks (ExternalTrustMapping, IdentityAttackSurface)
- EntraID checks (LegacyAuthReality, AppConsentReality, GuestCreep, MfaCoverageGap, HybridSyncReality)
- AWS identity inventory
- GCP identity inventory
- Module manifest and documentation

---

## Release Procedures

### Creating a New Release

1. **Update version number** in `VERSION.txt`

2. **Update this CHANGELOG.md** with changes since last release

3. **Run tests**:
   ```powershell
   Invoke-Pester -Path Tests/ -OutputFormat NUnitXml -OutputFile test-results.xml
   ```

4. **Create release artifact**:
   ```powershell
   .\Package-QuickChecks.ps1 -Version "1.1.0"
   ```

5. **Create GitHub release**:
   - Tag: `v1.1.0`
   - Title: Release 1.1.0
   - Attach: `IdentityFirst.QuickChecks-v1.1.0.zip`

### Version Numbering

Given a version number MAJOR.MINOR.PATCH, increment the:

1. **MAJOR** version when you make incompatible API changes
2. **MINOR** version when you add functionality in a backward-compatible manner
3. **PATCH** version when you make backward-compatible bug fixes

Additional labels for pre-release and build metadata are available as extensions to the MAJOR.MINOR.PATCH format.

---

## Categories

Each change should be categorized using these prefixes:

- `Added`: New features
- `Changed`: Changes in existing functionality
- `Deprecated`: Soon-to-be removed features
- `Removed`: Features that have been removed
- `Fixed`: Bug fixes
- `Security`: Vulnerability patches

---

## Security Releases

For security-related releases, use the following format:

## [1.0.1] - 2024-12-15 [Security]

### Fixed

- CVE-XXXX-XXXX: Description of vulnerability
- Related issue: #123

---

## Example Entry

### [1.2.0] - 2026-02-15

### Added

- New `Invoke-GuestCreep.ps1` script for detecting stale guest accounts (#45)
- PowerShell 7 compatibility for all EntraID modules

### Changed

- Updated `Invoke-MfaCoverageGap.ps1` to prioritize privileged users (#38)
- Improved error handling in `Invoke-EntraEnhancedIdentity.ps1`

### Fixed

- Resolved encoding issue in `IdentityFirst.QuickChecks.Validation.psm1` (#52)
- Fixed null reference exception in `Invoke-AppConsentReality.ps1`

### Security

- Added input validation for all Graph API calls

---

## Auto-Generation

This CHANGELOG can be auto-generated from Git commits using:

- [git-changelog](https://github.com/git-changelog/git-changelog)
- [Conventional Commits](https://www.conventionalcommits.org/)

### Conventional Commits Format

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

Types:
- `feat`: A new feature
- `fix`: A bug fix
- `docs`: Documentation only changes
- `style`: Changes that do not affect the meaning of the code (white-space, formatting, etc)
- `refactor`: A code change that neither fixes a bug nor adds a feature
- `perf`: A code change that improves performance
- `test`: Adding missing tests or correcting existing tests
- `chore`: Changes to the build process or auxiliary tools

Example:
```
feat(EntraID): add guest account age detection

Implement detection of guest accounts older than 180 days

Closes #45
```

---

## Retention

Keep this changelog for all released versions. Archive old versions by moving them to `docs/CHANGELOG-Archive.md`.
