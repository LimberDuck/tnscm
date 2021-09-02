# Changelog

All notable changes to [**TNSCM** *(Tenable Nessus CLI Manager)* by LimberDuck][1] project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.4] - 2021-09-02

### Added

- possibility to delete policies `tnscm policy --delete`
- possibility to delete scans `tnscm scan --delete`
- possibility to list settings `tnscm settings --list`

### Changed

- information about scan status for `tnscm scan --list`

## [0.0.3] - 2021-08-31

### Added

- new format option to display data - `--format csv`
- data filtering possibility using [JMESPath](https://jmespath.org), see [Example filters](https://github.com/LimberDuck/tnscm#example-filters).

## [0.0.2] - 2021-08-25

### Added

- `plugin --family-list` lists parameters `id`, `name`, `count`

### Changed

- date format for returned dates

## [0.0.1] - 2021-08-24

- initial release

[0.0.4]: https://github.com/LimberDuck/tnscm/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/LimberDuck/tnscm/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/LimberDuck/tnscm/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/LimberDuck/tnscm/releases/tag/v0.0.1

[1]: https://github.com/LimberDuck/tnscm
