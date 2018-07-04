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

## [0.5.5] - 2018-07-04
### Changed
- Updated `libc` dependency (0.2.39 -> 0.2.42)
- Updated `pam-sys` dependency (0.5.5 -> 0.5.6)

## [0.5.4] - 2018-03-21
### Changed
- Updated `libc` dependency (0.2.33 -> 0.2.39)
- Updated `pam-sys` dependency (0.5.4 -> 0.5.5)
- Updated `users` dependency (0.5.2 -> 0.5.3)

### Fixed
- Fix build on OSX and linux-arm

## [0.5.3] - 2017-12-04
### Changed
- Only provide official support for Rust stable, beta and nightly (mainly through travis)
- Updated `libc` dependency (0.2.20 -> 0.2.33)
- Updated `pam-sys` dependency (0.5.3 -> 0.5.4)
- Addded `cache: cargo` directive to speedup CI

## [0.5.2] - 2017-06-19
### Fixed
- Fixed missing null terminations in PAM `converse` function (Pull request #6)

## [0.5.1] - 2017-05-25
### Fixed
- Removed use of unstable feature `ptr_as_ref` to build on 1.5.0 again

## [0.5.0] - 2017-02-18
### Added
- Add travis-ci badge to `Cargo.toml`
- Added custom error type `PamError` and result type
- Added `env` module for PAM environment modules

### Changed
- Moved `Authenticator` to its own module
- Removed custom `strdup` function in `ffi` and replaced it with the `libc` version
- Tracked `pam-sys`
    - Use of Rust types where applicable
    - Removal of obsolete `unsafe` blocks
- Changed `Authenticator::open_session` to also insert the PAM environment variables into the process environment

## [0.4.1] 2017-01-20
### Added
- Added license badge to `README.md`

### Changed
- Updated `libc` dependency (0.2.9 -> 0.2.20)
- Updated `pam-sys` dependency (0.4.0 -> 0.4.3)
- Updated `users` dependency (0.5.1 -> 0.5.2)
- Moved call to `pam_setcred` from `Authenticator::authenticate()` to `Authenticator::open_session`
- Moved documentation to [docs.rs](https://docs.rs/pam-auth/)

### Fixed
- Fixed possibly undefined behaviour (taking a pointer of a dropped `CString`) in `Authenticator::new(..)`

### Removed
- Removed `.travis-update-gh-pages.sh` and obsolete rust versions from `.travis.yml`

## [0.4.0] - 2016-04-11
### Changed
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


[Unreleased]: https://github.com/1wilkens/pam-auth/compare/v0.5.5...HEAD
[0.5.5]: https://github.com/1wilkens/pam-auth/compare/v0.5.4...v0.5.5
[0.5.3]: https://github.com/1wilkens/pam-auth/compare/v0.5.3...v0.5.4
[0.5.3]: https://github.com/1wilkens/pam-auth/compare/v0.5.2...v0.5.3
[0.5.2]: https://github.com/1wilkens/pam-auth/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/1wilkens/pam-auth/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/1wilkens/pam-auth/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/1wilkens/pam-auth/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/1wilkens/pam-auth/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/1wilkens/pam-auth/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/1wilkens/pam-auth/compare/v0.2.0...v0.3.0
