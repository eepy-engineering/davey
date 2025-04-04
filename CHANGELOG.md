# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2] - 2025-04-04

### Added

- Functions for decryptor passthrough: `DAVESession.canPassthrough`, `DAVESession.setPassthroughMode`

### Fixed:

- Fixed setting an external sender possibly not re-creating the group.

## [0.1.1] - 2025-03-21

### Fixed:

- Fixed an issue where encryption did not properly set the codec and led to encryption failures.

## [0.1.0] - 2025-03-21

### Added

- Initial version of package.

[unreleased]: https://github.com/Snazzah/davey/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/Snazzah/davey/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Snazzah/davey/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Snazzah/davey/releases/tag/v0.1.0
