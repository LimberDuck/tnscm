# Changelog

All notable changes to [LimberDuck TNSCM][1] project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-31

### Added

- `--ca-cert FILE` option for all commands to verify the Nessus server certificate with a custom CA (e.g. Nessus CA from `https://<host>:8834/getcert`)
- `tnscm scan --download` to download scan results
  - `--limit DURATION` runs started in the last DURATION, e.g. `7d`, `12h`, `30m`, `45s` or combined `1d6h`, `--folder` folder id or name, `--scan-id` / `--history-id` exact scan or run
  - `--runs [all|latest]` all history runs of each scan or only the newest
  - `--output-dir`, `--file-format [nessus|csv]`, `--overwrite`
  - progress bar in terminal, plain output with `--no-progress` or in pipelines
- `tnscm scan --list-folders` to list folders
- `tnscm scan --compare SCAN_ID:HISTORY_ID SCAN_ID:HISTORY_ID` to compare findings per host of two scan runs (`new`, `fixed`, `severity changed`, `same`), `--diff` to show only changes
  - each run is summarized with start and end time, elapsed time, status and number of plugins per severity
- `tnscm policy --download` to download (export) all policies or given with `--policy-id` as `.nessus` files, with `--output-dir` and `--overwrite`
- `tnscm policy --upload FILE` to upload (import) policies from `.nessus` files, can be repeated
- `tnscm server --health` to get scanner health alerts and statistics, exit code `1` on critical alert
- `tnscm server --license` to get license and plugin feed status, `--warn-days N` and `--feed-max-age DURATION` to warn about license expiration and old plugin set, exit code `1` on any warning
- `tnscm policy --compare ID ID` to compare all settings, plugin families and individual plugins of two policies, `--diff` to show only differences
  - settings are shown by their location in Nessus UI, e.g. `Discovery > Host Discovery > Ping the remote host > General Settings > Test the local Nessus host`
  - credentials are shown by category and type (e.g. `Host > SSH > username`) and credentials of the same type are compared between policies
  - when plugin family is mixed (some plugins disabled) in any policy, family status is followed by status of each plugin of the family (with plugin name) in both policies
- `tnscm plugin --plugin-id ID` to show details of given plugin with link to its on-line description on tenable.com, can be repeated
- `tnscm plugin --plugin-file NAME` to show details of plugin by its file name (e.g. `scan_info.nasl`), comma separated list as in `dependency` attribute accepted, can be repeated
- `tnscm plugin --depends-on` and `--required-by` with `--plugin-id` or `--plugin-file` to show tree of plugins on which given plugin depends and plugins which depend on it, each plugin as `[id] [name] [file name]`
  - `--depth INTEGER` how many levels to show, default `1` (direct dependencies or dependents only), `0` for all levels
  - `--max-plugins INTEGER` list plugins of one level only if there are at most this many, default `100`, `0` for no limit
  - plugins with more dependencies or dependents than shown are marked with note, e.g. `depends on 3 more, increase --max-plugins INTEGER`
  - summary with number of verified plugins, time it took and average time per plugin
- `tnscm settings` advanced settings management, all options can be repeated
  - `--get NAME` value of selected setting
  - `--edit NAME=VALUE` change setting
  - `--add NAME=VALUE` add custom setting (or set again built-in setting reset to default)
  - `--delete NAME` delete custom setting or reset built-in setting to default
  - changes are shown and confirmed before applying, skip with `--yes`
- `tnscm scan --list-history` to list scans with historical entries (runs) and folder name, can be limited with `--folder`, `--limit` and `--runs latest` (newest run of each scan, same selection as `--download`)
- `tnscm scan --list` can be limited with `--folder`
- `--filter-options` option for all commands to show all fields of first item which can be used with `--filter` (runs `-f "[0]" --format json`)
- `--hide-banner` and `--hide-address` options for all commands to hide tool name and version, and Nessus address, e.g. to get clean `csv` / `json` output in pipelines
- `--no-keyring` option for all commands to not read or save password in OS credential manager (keyring), e.g. on pipeline agents, use with `--password`; no need to set `PYTHON_KEYRING_BACKEND=keyring.backends.null.Keyring` anymore

### Changed

- Requirements update
  - from:
    - click>=8.2.1
    - keyring>=25.6.0
    - oauthlib>=3.3.1
    - requests>=2.32.5
    - pandas>=2.3.2
    - tabulate>=0.9.0
    - jmespath>=1.0.1
    - packaging>=25.0
  - to:
    - click>=8.5.0
    - keyring>=25.7.0
    - requests>=2.34.2
    - pandas>=3.1.0
    - tabulate>=0.10.0
    - jmespath>=1.1.0
    - packaging>=26.3
- Python versions tested in pipeline
  - from: 3.10, 3.11, 3.12, 3.13
  - to: 3.11, 3.12, 3.13, 3.14, 3.15
  - Python 3.10 is no longer supported

### Fixed

- API errors now exit with code `1` instead of `0`
- wrong `--filter` expression shows short error with hint instead of traceback, syntax is checked before connecting to Nessus
- API connection layer reworked
  - clear one-line error messages (with Nessus error text) on stderr instead of tracebacks for unreachable server, SSL problems, timeouts and wrong credentials
  - requests time out instead of hanging forever, `503` (Nessus starting) is retried
  - one HTTPS session reused for all requests
  - scan downloads are streamed to disk instead of being held in memory
  - one failed scan download no longer stops the whole batch

### Removed

- `tnscm scan --delete` removed (deleting scans via API is not available in Nessus Professional)
- `-f` option removed for format, now only longer version is available: `--format`



## [0.0.7] - 2025-09-01

### Added

- Requirements update
  - new:
    - packaging>=25.0

## [0.0.6] - 2025-09-01

### Added

#### CLI

- New option:
  - `tnscm --update-check` / `tnscm -u` - will return confirmation if you are using the latest version of TNSCM.

### Changed

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

[0.1.0]: https://github.com/LimberDuck/tnscm/compare/v0.0.7...v0.1.0
[0.0.7]: https://github.com/LimberDuck/tnscm/compare/v0.0.6...v0.0.7
[0.0.6]: https://github.com/LimberDuck/tnscm/compare/v0.0.5...v0.0.6
[0.0.5]: https://github.com/LimberDuck/tnscm/compare/v0.0.4...v0.0.4
[0.0.4]: https://github.com/LimberDuck/tnscm/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/LimberDuck/tnscm/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/LimberDuck/tnscm/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/LimberDuck/tnscm/releases/tag/v0.0.1

[1]: https://github.com/LimberDuck/tnscm
