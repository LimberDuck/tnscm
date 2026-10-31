# LimberDuck TNSCM

**LimberDuck TNSCM** a CLI Manager for Tenable Nessus which enables you to perform certain actions on Nessus by (C) Tenable, Inc. via Nessus API.

[![pepy - Downloads](https://img.shields.io/pepy/dt/tnscm?logo=PyPI)](https://pepy.tech/projects/tnscm) [![PyPI Downloads](https://static.pepy.tech/badge/tnscm/month)](https://pepy.tech/projects/tnscm)
[![Latest Release version](https://img.shields.io/github/v/release/LimberDuck/tnscm?label=Latest%20release)](https://github.com/LimberDuck/tnscm/releases) 
[![GitHub Release Date](https://img.shields.io/github/release-date/limberduck/tnscm?label=released&logo=GitHub)](https://github.com/LimberDuck/tnscm/releases)
[![License](https://img.shields.io/github/license/LimberDuck/tnscm.svg)](https://github.com/LimberDuck/tnscm/blob/main/LICENSE) 
[![Repo size](https://img.shields.io/github/repo-size/LimberDuck/tnscm.svg)](https://github.com/LimberDuck/tnscm) 
[![Code size](https://img.shields.io/github/languages/code-size/LimberDuck/tnscm.svg)](https://github.com/LimberDuck/tnscm) 
[![Supported platform](https://img.shields.io/badge/platform-windows%20%7C%20macos%20%7C%20linux-lightgrey.svg)](https://github.com/LimberDuck/tnscm)
<!-- [![PyPI - Downloads](https://img.shields.io/pypi/dm/tnscm?logo=PyPI)](https://pypistats.org/packages/tnscm) -->
<!-- [![Stars from users](https://img.shields.io/github/stars/LimberDuck/tnscm?label=Stars%20from%20users)](https://github.com/LimberDuck/tnscm)  -->

> [!NOTE]
> **Visit [LimberDuck.org][LimberDuck] to find out more!**

![](https://limberduck.org/en/latest/_images/tnscm.png)

## Main features

Initial version of **TNSCM** lets you perform actions like:

* plugin
  * family list
  * details for given plugin id
* policy
  * list
  * compare two policies (all or only different settings)
  * download (export) as .nessus files
  * delete
* scan
  * list (optionally per folder)
  * list with history (per folder, last N days)
  * folder list
  * download results (last N days, per folder, exact scan / history run)
  * compare findings of two scan runs (new, fixed, severity changed)
* server info
  * status
  * licensed IPs
  * version
* advanced settings
  * list
  * get selected
  * edit
  * add custom setting
  * delete / reset to default
* user list

To filter data to specific values you can use [JMESPath](https://jmespath.org).

## Installation

> **Note:**
> It's advisable to use python virtual environment for below instructions. Read more about python virtual environment in [The Hitchhiker’s Guide to Python!](https://docs.python-guide.org/dev/virtualenvs/)
> 
>Read about [virtualenvwrapper in The Hitchhiker’s Guide to Python!](https://docs.python-guide.org/dev/virtualenvs/#virtualenvwrapper): [virtualenvwrapper](https://virtualenvwrapper.readthedocs.io) provides a set of commands which makes working with virtual environments much more pleasant.


1. Install **TNSCM**
    
    `pip install tnscm`

    > To upgrade to newer version run:
    >
    > `pip install -U tnscm`

2. Run **TNSCM**

    `tnscm`

### Commands

| option / command | `plugin` | `policy` | `scan` | `server` | `settings` | `user` |
|------------------|:--------:|:--------:|:------:|:--------:|:----------:|:------:|
| `--help`         | yes      | yes      | yes    | yes      | yes        | yes    |
| `--list`         |          | yes      | yes    |          | yes        | yes    |
| `--family-list`  | yes      |          |        |          |            |        |
| `--plugin-id`    | yes      |          |        |          |            |        |
| `--plugin-file`  | yes      |          |        |          |            |        |
| `--depends-on`   | yes      |          |        |          |            |        |
| `--required-by`  | yes      |          |        |          |            |        |
| `--depth`        | yes      |          |        |          |            |        |
| `--max-plugins`  | yes      |          |        |          |            |        |
| `--list-history` |          |          | yes    |          |            |        |
| `--list-folders` |          |          | yes    |          |            |        |
| `--download`     |          | yes      | yes    |          |            |        |
| `--policy-id`    |          | yes      |        |          |            |        |
| `--upload`       |          | yes      |        |          |            |        |
| `--diff`         |          | yes      | yes    |          |            |        |
| `--edit`         |          |          |        |          | yes        |        |
| `--add`          |          |          |        |          | yes        |        |
| `--get`          |          |          |        |          | yes        |        |
| `--delete`       |          | yes      |        |          | yes        |        |
| `--compare`      |          | yes      | yes    |          |            |        |
| `--filter`       | yes      | yes      | yes    |          | yes        | yes    |
| `--format`       | yes      | yes      | yes    |          | yes        | yes    |
| `--limit`        |          |          | yes    |          |            |        |
| `--folder`       |          |          | yes    |          |            |        |
| `--scan-id`      |          |          | yes    |          |            |        |
| `--history-id`   |          |          | yes    |          |            |        |
| `--runs`         |          |          | yes    |          |            |        |
| `--output-dir`   |          | yes      | yes    |          |            |        |
| `--file-format`  |          |          | yes    |          |            |        |
| `--overwrite`    |          | yes      | yes    |          |            |        |
| `--no-progress`  |          |          | yes    |          |            |        |
| `--yes`          |          |          |        |          | yes        |        |
| `--filter-options` | yes    | yes      | yes    |          | yes        | yes    |
| `--status`       |          |          |        | yes      |            |        |
| `--ips`          |          |          |        | yes      |            |        |
| `--health`       |          |          |        | yes      |            |        |
| `--license`      |          |          |        | yes      |            |        |
| `--warn-days`    |          |          |        | yes      |            |        |
| `--feed-max-age` |          |          |        | yes      |            |        |
| `--version`      |          |          |        | yes      |            |        |
| `--insecure`, `-k` | yes    | yes      | yes    | yes      | yes        | yes    |
| `--ca-cert`      | yes      | yes      | yes    | yes      | yes        | yes    |
| `--hide-banner`  | yes      | yes      | yes    | yes      | yes        | yes    |
| `--hide-address` | yes      | yes      | yes    | yes      | yes        | yes    |
| `--no-keyring`   | yes      | yes      | yes    | yes      | yes        | yes    |

### Pipelines

By default password is read from and saved in OS credential manager (macOS Keychain, Windows Credential Manager)
using [keyring](https://pypi.org/project/keyring/). Pipeline agents usually don't have one,
so use `--no-keyring` with `--password`, keyring is then not used at all:

`tnscm scan -a 127.0.0.1 --port 8834 -u user -p "$NESSUS_PASSWORD" --no-keyring --download --limit 1d --hide-banner`

### Server health and licence

Scanner health alerts (e.g. slow DNS lookups, not enough memory) and statistics (CPU, memory, disk space),
exit code `1` when any alert is critical:

`tnscm server -a 127.0.0.1 --port 8834 --health`

License and plugin feed status, exit code `1` when any check is `warning`
(e.g. plugin feed download failed, license expires soon, plugin set is too old):

`tnscm server -a 127.0.0.1 --port 8834 --license --warn-days 30 --feed-max-age 2d`

Use it in a monitoring job:

`tnscm server -a 127.0.0.1 --port 8834 -u user -p "$NESSUS_PASSWORD" --no-keyring --license --warn-days 30 --feed-max-age 2d --hide-banner || echo "check Nessus!"`

### Certificate verification

Nessus uses its own certificate authority (CA), which is not trusted by default, so connection fails with
`SSL certificate of <address> can't be verified`. You can:

- trust the Nessus CA with `--ca-cert` (certificate has to be valid for the address you connect to):

  `curl -sk https://127.0.0.1:8834/getcert -o nessus-ca.pem`

  `tnscm server -a 127.0.0.1 --port 8834 --status --ca-cert nessus-ca.pem`

- or skip verification with `-k` / `--insecure`:

  `tnscm server -a 127.0.0.1 --port 8834 --status -k`

### Clean output

Use `--hide-banner` to skip tool name and version, and `--hide-address` to skip Nessus address, e.g. to use output in scripts:

`tnscm settings -a 127.0.0.1 --port 8834 --get max_hosts -f "[0].value" --format json --hide-banner --hide-address`

### Example filters

To check possible keys and values by returning only first entry (works with every command, runs `-f "[0]" --format json`):

`--filter-options`

To get only name and id columns:

`--filter "[].{id: id, name: name}"`

To sort by `id` column:

`--filter "sort_by([], &id)[].{id: id, name: name}"`

To filter returned data to these items which `name` contain `exampl`:

`--filter "[? contains(name, 'exampl')].{id: id, name: name}"`

To filter returned data to these items which `name` contain `exampl1` or `exampl2`:

`--filter "[? contains(name, 'exampl1') || contains(name, 'exampl2')].{id: id, name: name}"`

To filter returned data to item which `id` is equal to number `10`:

``--filter '[?id==`10`].{id: id, name: name}'``

To filter returned data to item which `name` is equal to string `test name`:

`--filter "[?name == 'test name'].{id: id, name: name}"`

To filter returned data to items which `name` is different than string `test name`:

`--filter "[?name != 'test name'].{id: id, name: name}"`

### Policy download

Download (export) all policies, or selected ones, as `.nessus` files.
File name contains policy id, name and last modification time, so changed policy is saved to a new file
and unchanged one is skipped, use `--overwrite` to download it again:

`tnscm policy -a 127.0.0.1 --port 8834 --download --output-dir ./policies`

`tnscm policy -a 127.0.0.1 --port 8834 --download --policy-id 19 --policy-id 22`

### Policy upload

Upload (import) policies from `.nessus` files, e.g. downloaded with `--download` from another Nessus:

`tnscm policy -a 127.0.0.1 --port 8834 --upload ./policies/127.0.0.1_19_My_policy_20261024-142541.nessus`

If a policy with the same name exists, Nessus adds a suffix to the name, e.g. `My policy_01`.

### Policy comparison

Compare all settings, plugin families and individual plugins of two policies (ids from `tnscm policy --list`).
Each row shows both values and result: `same`, `different` or `only in <policy>`:

`tnscm policy -a 127.0.0.1 --port 8834 --compare 19 20`

Show only differences:

`tnscm policy -a 127.0.0.1 --port 8834 --compare 19 20 --diff`

Show only differences in plugins:

`tnscm policy -a 127.0.0.1 --port 8834 --compare 19 20 --diff --filter "[?section=='plugins']"`

### Plugin details

Show all details of given plugin:

`tnscm plugin -a 127.0.0.1 --port 8834 --plugin-id 156860`

Compare selected details of several plugins (attributes which occur many times, like `cve` or `xref`, are lists):

`tnscm plugin -a 127.0.0.1 --port 8834 --plugin-id 156860 --plugin-id 19506 --filter "[].{id: id, name: name, risk_factor: risk_factor, cvss3: cvss3_base_score, cve: cve}" --format json`

Show details of plugins by their file name, e.g. taken from `dependency` attribute (comma separated list is accepted):

`tnscm plugin -a 127.0.0.1 --port 8834 --plugin-file "nessus_product_setup.nasl, patches_summary.nbin" --filter "[].{id: id, name: name, fname: fname}"`

### Plugin dependencies

Show tree of plugins on which given plugin depends (`--depends-on`) and plugins which depend on it (`--required-by`).
By default only direct dependencies and dependents are shown (`--depth 1`), use `--depth 0` for all levels.
Plugins of one level are listed only if there are at most `--max-plugins` of them (default `100`, `0` for no limit).

`tnscm plugin -a 127.0.0.1 --port 8834 --plugin-id 57399 --required-by`

`tnscm plugin -a 127.0.0.1 --port 8834 --plugin-id 19506 --depends-on --depth 4`

```
[19506] [Nessus Scan Information] [scan_info.nasl] depends on
├── [83955] [Nessus Product Information] [nessus_product_setup.nasl]
└── [66334] [Patch Report] [patches_summary.nbin]
    └── [64294] [Patch Management Windows Auditing Conflicts] [patch_management_auditing.nasl]
        ├── [38153] [Microsoft Windows Summary of Missing Patches] [smb_missing_msft_patches.nasl]
        │   ├── [13855] [Microsoft Windows Installed Hotfixes] [smb_hotfixes.nasl] - depends on 2 more, use --depth INTEGER
        │   └── [57033] [Microsoft Patch Bulletin Feasibility Check] [ms_bulletin_checks_possible.nasl] - depends on 8 more, use --depth INTEGER
        └── [67099] [Post-Scan Rules Application] [pluginrules.nbin] 

verified 8 plugins in 1m 24s, 10.5s per plugin
```

Each lookup by file name takes a few seconds on Nessus side, so summary at the bottom shows how many plugins were verified, how long it took and average time per plugin.

### Scan runs comparison

Compare findings per host of two scan runs given as `SCAN_ID:HISTORY_ID` (from `tnscm scan --list-history`).
Runs can belong to the same or different scans, older run is always treated as first.
Each finding (host + plugin) is marked as `new`, `fixed`, `severity changed` or `same`:

`tnscm scan -a 127.0.0.1 --port 8834 --compare 12:13 12:14`

Show only changes:

`tnscm scan -a 127.0.0.1 --port 8834 --compare 12:13 12:14 --diff`

Show only new critical and high findings:

`tnscm scan -a 127.0.0.1 --port 8834 --compare 12:13 12:14 --diff --filter "[?result=='new' && contains(['critical', 'high'], \"12:14\")]"`

### Advanced settings

Get value of selected settings (use `--filter "[0].value"` to print value only):

`tnscm settings -a 127.0.0.1 --port 8834 --get max_hosts --get max_checks`

Change existing settings (planned changes are shown and confirmed first):

`tnscm settings -a 127.0.0.1 --port 8834 --edit max_hosts=128 --edit max_checks=4`

Add new custom setting:

`tnscm settings -a 127.0.0.1 --port 8834 --add my_custom_setting=value`

Delete custom setting, or reset built-in setting to its default value:

`tnscm settings -a 127.0.0.1  --port 8834 --delete my_custom_setting`

> **Note:** Nessus hides a built-in setting reset to default from the list, so it can't be changed with `--edit` anymore.
> Use `--add` to set it again, e.g. `--add max_hosts=256`.

Use `--yes` to apply without confirmation, e.g. in pipelines.
`--edit` and `--delete` accept only listed names and `--add` only names which are not listed, use `--list` to check current names and values.

### Scan results download

Each scan run (history entry) is saved as a separate file named
`<address>_<scan id>_<history id>_<scan name>_<run start>.nessus`.
Only runs with status `completed` or `imported` are downloaded, others are reported as skipped.
Files which already exist are skipped, use `--overwrite` to download them again.

List folders to know their ids and names:

`tnscm scan -a 127.0.0.1 --port 8834 --list-folders`

List scans with history in given folder from last 30 days:

`tnscm scan -a 127.0.0.1 --port 8834 --list-history --folder "My Scans" --limit 30d`

Preview newest run of each scan, the same runs `--download --runs latest` would download:

`tnscm scan -a 127.0.0.1 --port 8834 --list-history --runs latest`

Download all scan runs from last 7 days in given folder to `./reports`:

`tnscm scan -a 127.0.0.1 --port 8834 --download --limit 7d --folder "My Scans" --output-dir ./reports`

`--limit` takes number with unit `d` (days), `h` (hours), `m` (minutes) or `s` (seconds), units can be combined (here: last 30 hours):

`tnscm scan -a 127.0.0.1 --port 8834 --download --limit 1d6h`

Download only the newest run of each scan from last 7 days:

`tnscm scan -a 127.0.0.1 --port 8834 --download --limit 7d --runs latest`

Download the newest completed run of given scan, or all its runs:

`tnscm scan -a 127.0.0.1 --port 8834 --download --scan-id 12`

`tnscm scan -a 127.0.0.1 --port 8834 --download --scan-id 12 --runs all`

Download exact scan run:

`tnscm scan -a 127.0.0.1 --port 8834 --download --scan-id 12 --history-id 13`

Progress bar is shown in terminal only. In pipelines (or with `--no-progress`) one line per scan run is printed
and a summary `downloaded X, skipped Y, failed Z`. Exit code is `1` if any download failed.

`tnscm scan -a 127.0.0.1 --port 8834 --download --limit 1d --no-progress --file-format csv`

> **Note:** Nessus doesn't allow exports in trial mode, such server responds with `403`.

## Meta

### Change log

See [CHANGELOG].


### Licence

MIT: [LICENSE].


### Authors

[Damian Krawczyk] created **TNSCM** *(Tenable Nessus CLI Manager)* by LimberDuck.

[Damian Krawczyk]: https://damiankrawczyk.com
[LimberDuck]: https://limberduck.org
[CHANGELOG]: https://github.com/LimberDuck/tnscm/blob/main/CHANGELOG.md
[LICENSE]: https://github.com/LimberDuck/tnscm/blob/main/LICENSE



pyinstaller --onefile  --name tnscm tnscm/__main__.py

chmod +x tnscm
xattr -dr com.apple.quarantine tnscm
mv tnscm /usr/local/bin/tnscm

sudo ln -s /opt/tnscm/tnscm /usr/local/bin/tnscm


[{'scan_type': 'vuln', 'isWas': None, 'folder_id': 3, 'type': 'local', 'read': True, 'last_modification_date': 1755148504, 'creation_date': 1755147396, 'status': 'completed', 'uuid': 'a8ea4587-1da7-755e-0bd7-1601534e8af8bec201d1faa12f4a', 'shared': False, 'user_permissions': 128, 'owner': 'damian', 'timezone': None, 'rrules': None, 'starttime': None, 'enabled': False, 'control': True, 'live_results': 0, 'name': 'dmbp', 'id': 23}, {'scan_type': 'vuln', 'isWas': None, 'folder_id': 3, 'type': 'local', 'read': True, 'last_modification_date': 1751095386, 'creation_date': 1751094433, 'status': 'completed', 'uuid': '974aab0b-1018-f88b-39ee-c5164defa1cf51b3e5fbc002e5fc', 'shared': False, 'user_permissions': 128, 'owner': 'damian', 'timezone': None, 'rrules': None, 'starttime': None, 'enabled': False, 'control': True, 'live_results': 0, 'name': 'ubuntu', 'id': 5}, {'scan_type': 'vuln', 'isWas': None, 'folder_id': 3, 'type': 'local', 'read': True, 'last_modification_date': 1747040513, 'creation_date': 1747040502, 'status': 'completed', 'uuid': '71c2d4bc-afe9-7862-7698-4ee21cec0b144b411ca7028ad666', 'shared': False, 'user_permissions': 128, 'owner': 'damian', 'timezone': None, 'rrules': None, 'starttime': None, 'enabled': False, 'control': True, 'live_results': 0, 'name': 'printer', 'id': 18}, {'scan_type': 'vuln', 'isWas': None, 'folder_id': 3, 'type': 'local', 'read': True, 'last_modification_date': 1746901140, 'creation_date': 1746900833, 'status': 'completed', 'uuid': '2adb3b07-7790-dbd9-5ade-850e0621f1addf1328e2f61c76ab', 'shared': False, 'user_permissions': 128, 'owner': 'damian', 'timezone': None, 'rrules': None, 'starttime': None, 'enabled': False, 'control': True, 'live_results': 0, 'name': '192.168.1.1', 'id': 15}, {'scan_type': 'vuln', 'isWas': None, 'folder_id': 3, 'type': 'local', 'read': True, 'last_modification_date': 1746881600, 'creation_date': 1746880877, 'status': 'completed', 'uuid': '179fa6a3-b7d2-6761-6e9d-5a3325aef0eaf8bceeb2e9453fc5', 'shared': False, 'user_permissions': 128, 'owner': 'damian', 'timezone': None, 'rrules': None, 'starttime': None, 'enabled': False, 'control': True, 'live_results': 0, 'name': '192.168.8.1', 'id': 12}, {'scan_type': 'discovery', 'isWas': None, 'folder_id': 3, 'type': 'local', 'read': True, 'last_modification_date': 1746196901, 'creation_date': 1746196790, 'status': 'completed', 'uuid': '532e19cf-3740-0d33-724d-0a1c7a65a56b6fe77a4c70505799', 'shared': False, 'user_permissions': 128, 'owner': 'damian', 'timezone': None, 'rrules': None, 'starttime': None, 'enabled': False, 'control': True, 'live_results': 0, 'name': '192.168.8.0/24', 'id': 9}]



URL: https://192.168.1.119:8834/scans/23?history_id=25&limit=2500&includeHostDetailsForHostDiscovery=true
URL: https://192.168.1.119:8834/scans/23?history_id=24&limit=2500&includeHostDetailsForHostDiscovery=true



[{'alt_targets_used': False, 'scheduler': 0, 'node_name': None, 'node_host': None, 'scan_group': None, 'node_id': None, 'schedule_type': 'manual', 'status': 'completed', 'type': 'local', 'uuid': '84d9b26c-6b27-c1f2-2d48-7b8c79b44a06efa64c9703386eb4', 'last_modification_date': '2025-06-28 10:18:22', 'creation_date': '2025-06-28 10:00:13', 'owner_id': 2, 'history_id': 24, 'scan_folder_id': 3, 'scan_id': 23, 'scan_name': 'dmbp', 'scan_owner': 'damian'}, {'alt_targets_used': False, 'scheduler': 0, 'node_name': None, 'node_host': None, 'scan_group': None, 'node_id': None, 'schedule_type': 'manual', 'status': 'completed', 'type': 'local', 'uuid': 'a8ea4587-1da7-755e-0bd7-1601534e8af8bec201d1faa12f4a', 'last_modification_date': '2025-08-14 07:15:04', 'creation_date': '2025-08-14 06:56:36', 'owner_id': 2, 'history_id': 25, 'scan_folder_id': 3, 'scan_id': 23, 'scan_name': 'dmbp', 'scan_owner': 'damian'}, {'alt_targets_used': False, 'scheduler': 0, 'node_name': None, 'node_host': None, 'scan_group': None, 'node_id': None, 'schedule_type': 'manual', 'status': 'completed', 'type': 'local', 'uuid': '3a45315f-54ea-c5b8-ed5b-a968f07cdeacba3b0bea345db411', 'last_modification_date': '2025-04-10 20:34:54', 'creation_date': '2025-04-10 20:30:12', 'owner_id': 2, 'history_id': 6, 'scan_folder_id': 3, 'scan_id': 5, 'scan_name': 'ubuntu', 'scan_owner': 'damian'}, {'alt_targets_used': False, 'scheduler': 0, 'node_name': None, 'node_host': None, 'scan_group': None, 'node_id': None, 'schedule_type': 'manual', 'status': 'completed', 'type': 'local', 'uuid': '1e3807ce-d8fe-d4c8-107e-91a8f723bd6fc83d2d784482cc72', 'last_modification_date': '2025-04-10 21:15:25', 'creation_date': '2025-04-10 21:10:58', 'owner_id': 2, 'history_id': 7, 'scan_folder_id': 3, 'scan_id': 5, 'scan_name': 'ubuntu', 'scan_owner': 'damian'}, {'alt_targets_used': False, 'scheduler': 0, 'node_name': None, 'node_host': None, 'scan_group': None, 'node_id': None, 'schedule_type': 'manual', 'status': 'completed', 'type': 'local', 'uuid': '974aab0b-1018-f88b-39ee-c5164defa1cf51b3e5fbc002e5fc', 'last_modification_date': '2025-06-28 09:23:06', 'creation_date': '2025-06-28 09:07:13', 'owner_id': 2, 'history_id': 20, 'scan_folder_id': 3, 'scan_id': 5, 'scan_name': 'ubuntu', 'scan_owner': 'damian'}, {'alt_targets_used': False, 'scheduler': 0, 'node_name': None, 'node_host': None, 'scan_group': None, 'node_id': None, 'schedule_type': 'manual', 'status': 'completed', 'type': 'local', 'uuid': '71c2d4bc-afe9-7862-7698-4ee21cec0b144b411ca7028ad666', 'last_modification_date': '2025-05-12 11:01:53', 'creation_date': '2025-05-12 11:01:42', 'owner_id': 2, 'history_id': 19, 'scan_folder_id': 3, 'scan_id': 18, 'scan_name': 'printer', 'scan_owner': 'damian'}, {'alt_targets_used': False, 'scheduler': 0, 'node_name': None, 'node_host': None, 'scan_group': None, 'node_id': None, 'schedule_type': 'manual', 'status': 'completed', 'type': 'local', 'uuid': '2adb3b07-7790-dbd9-5ade-850e0621f1addf1328e2f61c76ab', 'last_modification_date': '2025-05-10 20:19:00', 'creation_date': '2025-05-10 20:13:53', 'owner_id': 2, 'history_id': 16, 'scan_folder_id': 3, 'scan_id': 15, 'scan_name': '192.168.1.1', 'scan_owner': 'damian'}, {'alt_targets_used': False, 'scheduler': 0, 'node_name': None, 'node_host': None, 'scan_group': None, 'node_id': None, 'schedule_type': 'manual', 'status': 'completed', 'type': 'local', 'uuid': '179fa6a3-b7d2-6761-6e9d-5a3325aef0eaf8bceeb2e9453fc5', 'last_modification_date': '2025-05-10 14:53:20', 'creation_date': '2025-05-10 14:41:17', 'owner_id': 2, 'history_id': 13, 'scan_folder_id': 3, 'scan_id': 12, 'scan_name': '192.168.8.1', 'scan_owner': 'damian'}, {'alt_targets_used': False, 'scheduler': 0, 'node_name': None, 'node_host': None, 'scan_group': None, 'node_id': None, 'schedule_type': 'manual', 'status': 'completed', 'type': 'local', 'uuid': '532e19cf-3740-0d33-724d-0a1c7a65a56b6fe77a4c70505799', 'last_modification_date': '2025-05-02 16:41:41', 'creation_date': '2025-05-02 16:39:50', 'owner_id': 2, 'history_id': 10, 'scan_folder_id': 3, 'scan_id': 9, 'scan_name': '192.168.8.0/24', 'scan_owner': 'damian'}]


Overview
Authorization
agent-groups
add-agent
add-agents
configure
create
delete-group
delete-groups
delete-agent
delete-agents
details
list
agents
delete
delete-bulk
unlink
unlink-bulk
list
list-one
editor
audits
audits-token-download
details
edit
list
plugin-description
file
upload
folders
create
delete
edit
list
groups
add-user
create
delete
delete-bulk
delete-user
edit
list
list-users
mail
change
view
migration
get-settings
update-settings
status
start
stop
scan-history
scan-history-settings
update-scan-history-settings
start-scan-history-migration
stop-scan-history-migration
skip-scan-history
skip-scan-history-bulk
reset-scan-history
reset-scan-history-bulk
permissions
change
list
plugin-rules
create
delete
delete-bulk
edit
list
details
plugins
families
family-details
plugin-details
policies
configure
copy
create
delete
delete-bulk
details
import
export
export-token-download
list
profiles
add-profile
add-profile-members
delete-profiles
delete-profile-members
delete-profile-from-agents
get-profile
get-profile-members
list
set-profile-for-agent
unset-profile-for-agent
update-profile
proxy
change
view
scanners
control-scans
delete
delete-bulk
details
edit
get-aws-targets
get-scanner-key
get-scans
list
toggle-link-state
scans
attachment-prepare
configure
copy
create
delete
delete-bulk
delete-history
details
export-formats
export-download
export-request
export-status
host-details
import
kill
launch
list
pause
plugin-output
read-status
resume
schedule
stop
timezones
server
properties
status
restart
session
create
destroy
edit
get
password
keys
settings
health-alert-list
health-stats
list-advanced
modify-advanced
modify-plugin-detail-locale
get-plugin-detail-locale
software-update
schedule
settings
terrascan
get-info
set-desired
download
get-config
save-config
delete-config
edit-config
get-configs
delete-configs
get-default-config
get-scans
launch-scan
delete-scan
download-scan-result
download-scan-result-command-output
tokens
status
download
users
create
delete
delete-bulk
details
edit
list
password
keys


get scans from last 7 days

masOS
```bash
python -m tnscm scan -k -a 192.168.1.119 --port 8834 -u damian --list-history --filter "[? creation_date >= '$(date -v-7d +"%Y-%m-%d %H:%M:%S")'].{id: id, name: name, creation_date: creation_date}"
```

Linux
```bash
python -m tnscm scan -k -a 192.168.1.119 --port 8834 -u damian --list-history --filter "[? creation_date >= '$(date -d "7 days ago" +"%Y-%m-%d %H:%M:%S")'].{id: id, name: name, creation_date: creation_date}"
```

Windows (Powershell)
```bash
python -m tnscm scan -k -a 192.168.1.119 --port 8834 -u damian --list-history --filter "[? creation_date >= '$(powershell -NoProfile -Command \"(Get-Date).AddDays(-7).ToString('yyyy-MM-dd HH:mm:ss')\")'].{id: id, name: name, creation_date: creation_date}"

```