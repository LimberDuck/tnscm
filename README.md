# TNSCM

**TNSCM** *(Tenable Nessus CLI Manager)* by LimberDuck is a CLI tool which enables you to perform certain actions on Nessus by (C) Tenable, Inc. via Nessus API.

[![PyPI - Downloads](https://img.shields.io/pypi/dm/tnscm?logo=PyPI)](https://pypi.org/project/tnscm/) [![License](https://img.shields.io/github/license/LimberDuck/tnscm.svg)](https://github.com/LimberDuck/tnscm/blob/main/LICENSE) [![Repo size](https://img.shields.io/github/repo-size/LimberDuck/tnscm.svg)](https://github.com/LimberDuck/tnscm) [![Code size](https://img.shields.io/github/languages/code-size/LimberDuck/tnscm.svg)](https://github.com/LimberDuck/tnscm) [![Supported platform](https://img.shields.io/badge/platform-windows%20%7C%20macos%20%7C%20linux-lightgrey.svg)](https://github.com/LimberDuck/tnscm)


## Main features

Initial version of **TNSCM** lets you get Nessus:

* plugin family list
* policy list
* scan list
* user list
* server info
  * status
  * licensed IPs
  * version

Additionaly, list items can by filtered using [JMESPath](https://jmespath.org).

## How to

1. Install
    
    `pip install tnscm`

2. Run

    `tnscm`

### Example filters

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

To filter returned data to item which `name` is equal to number `test name`:

`--filter "[?name == 'test name'].{id: id, name: name}"`

## Meta

### Change log

See [CHANGELOG].


### Licence

MIT: [LICENSE].


### Authors

[Damian Krawczyk] created **TNSCM** *(Tenable Nessus CLI Manager)* by LimberDuck.

[Damian Krawczyk]: https://damiankrawczyk.com
[CHANGELOG]: https://github.com/LimberDuck/tnscm/blob/main/CHANGELOG.md
[LICENSE]: https://github.com/LimberDuck/tnscm/blob/main/LICENSE
