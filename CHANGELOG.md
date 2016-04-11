# Changelog
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

<!--
### Added - for new features.
### Changed - for changes in existing functionality.
### Deprecated - for once-stable features removed in upcoming releases.
### Removed - for deprecated features removed in this release.
### Fixed - for any bug fixes.
### Security - to invite users to upgrade in case of vulnerabilities.
-->

## [Unreleased]

## Changed
- Improved travis-ci integration to test against 1.5.0 and above
- Updated `libc` dependency (0.2.2 -> 0.2.9)
- Updated `pam-sys` dependency (0.3.0 -> 0.4.0)
- Updated `users` dependency (0.4.4 -> 0.5.1)

## [0.3.1] - 2016-01-14
### Changed
- Relicensed to dual MIT/Apache-2.0
- Improved travis-ci integration to use container based builds

## [0.3.0] - 2015-12-08
### Added
- CHANGELOG.md
- `pam-auth` now builds on Rust stable (and beta)!
- Better travis-ci integration (test on stable, beta and nightly)

### Changed
- Updated `libc` dependency (0.1.8 -> 0.2.2)
- Updated `pam-sys` dependency (0.2.1 -> 0.3.0)
- Updated `users` dependency (0.4.2 -> 0.4.4)


[Unreleased]: https://github.com/mrfloya/pam-auth/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/mrfloya/pam-auth/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/mrfloya/pam-auth/compare/v0.2.0...v0.3.0
