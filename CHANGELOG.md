# Changelog

## 0.2.2 (unreleased)

### Fixed

- Align runtime `__version__` with distribution metadata; add an installed-package version regression.
- Reject malformed receipt structures and invalid tolerances; report INCOMPARABLE when no numeric measurements overlap (#19).
- Report callback exceptions and malformed callback evidence as ERROR, with no mutation-detection score (#18).

### Packaging

- Sync the canonical release gate, including isolated installed-wheel probes and dependency checks, and add its wheel-isolation regressions.

The implementation fixes above are changes since 0.2.1 already present on main. This release preparation changes version identity, packaging validation, and tests. Earlier releases are documented in the repository's GitHub Releases.
