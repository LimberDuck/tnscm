# TNSCM

**TNSCM** *(Tenable Nessus CLI Manager)* by LimberDuck is a CLI tool which enables you to perform certain actions on Nessus by (C) Tenable, Inc. via Nessus API.

[![Latest Release version](https://img.shields.io/github/v/release/LimberDuck/tnscm?label=Latest%20release)](https://github.com/LimberDuck/tnscm/releases) 
[![GitHub Release Date](https://img.shields.io/github/release-date/limberduck/tnscm?label=released&logo=GitHub)](https://github.com/LimberDuck/tnscm/releases) 
[![PyPI - Downloads](https://img.shields.io/pypi/dm/tnscm?logo=PyPI)](https://pypistats.org/packages/tnscm)

<!-- [![Stars from users](https://img.shields.io/github/stars/LimberDuck/tnscm?label=Stars%20from%20users)](https://github.com/LimberDuck/tnscm)  -->
[![License](https://img.shields.io/github/license/LimberDuck/tnscm.svg)](https://github.com/LimberDuck/tnscm/blob/main/LICENSE) 
[![Repo size](https://img.shields.io/github/repo-size/LimberDuck/tnscm.svg)](https://github.com/LimberDuck/tnscm) 
[![Code size](https://img.shields.io/github/languages/code-size/LimberDuck/tnscm.svg)](https://github.com/LimberDuck/tnscm) 
[![Supported platform](https://img.shields.io/badge/platform-windows%20%7C%20macos%20%7C%20linux-lightgrey.svg)](https://github.com/LimberDuck/tnscm)


## Main features

Initial version of **TNSCM** lets you perform actions like:

* plugin family list
* policy
  * list
  * delete
* scan
  * list
  * delete
* server info
  * status
  * licensed IPs
  * version
* advanced settings list
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
| `--list-family`  | yes      |          |        |          |            |        |
| `--delete`       |          | yes      | yes    |          |            |        |
| `--filter`       | yes      | yes      | yes    |          | yes        | yes    |
| `--format`       | yes      | yes      | yes    |          | yes        | yes    |
| `--status`       |          |          |        | yes      |            |        |
| `--ips`          |          |          |        | yes      |            |        |
| `--version`      |          |          |        | yes      |            |        |

### Example filters

To check possible keys and values by returning only first entry:

`--filter "[] | [0]" --format json`

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
