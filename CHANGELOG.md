# Changelog

All notable changes to [**TNSCM** *(Tenable Nessus CLI Manager)* by LimberDuck][1] project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.6] - 2025-09-01

### Added

#### CLI

- New option:
  - `tnscm --update-check` / `tnscm -u` - will return confirmation if you are using the latest version of TNSCM.

- Requirements update
  - from:
    - click>=8.1.8
    - keyring>=25.5.0
    - oauthlib>=3.2.2
    - requests>=2.32.3
    - pandas>=2.0.3
  - to:
    - click>=8.2.1
    - keyring>=25.6.0
    - oauthlib>=3.3.1
    - requests>=2.32.5
    - pandas>=2.3.2

- tests for python
  - removed: 3.8, 3.9

## [0.0.5] - 2025-02-22

### Changed

- code formatted with [black](https://black.readthedocs.io)
- requirements update
  - from:
    - click>=8.0.1
    - keyring>=23.0.1
    - oauthlib>=3.1.1
    - requests>=2.25.1
    - pandas>=1.3.2
    - tabulate>=0.8.9
    - jmespath>=0.10.0
  - to:
    - click>=8.1.8
    - keyring>=25.5.0
    - oauthlib>=3.2.2
    - requests>=2.32.3
    - pandas>=2.0.3
    - tabulate>=0.9.0
    - jmespath>=1.0.1

- tests for python
  - added: 3.10, 3.11, 3.12, 3.13
  - removed: 3.7



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

[0.0.5]: https://github.com/LimberDuck/tnscm/compare/v0.0.4...v0.0.4
[0.0.4]: https://github.com/LimberDuck/tnscm/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/LimberDuck/tnscm/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/LimberDuck/tnscm/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/LimberDuck/tnscm/releases/tag/v0.0.1

[1]: https://github.com/LimberDuck/tnscm
