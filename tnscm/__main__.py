from tnscm._version import __version__
from tnscm.modules.tnsapi import TnsApi, TnsApiError
import click
import pandas as pd
from tabulate import tabulate
import getpass
import keyring
from keyring.backends import Windows, macOS
import platform
import sys
import collections
import datetime
import hashlib
import json
import os
import re
import time
import jmespath
from tnscm import utilities
from tnscm import __about__

os_user = getpass.getuser().lower()

if platform.system() == "Windows":
    keyring.set_keyring(Windows.WinVaultKeyring())
elif platform.system() == "Darwin":
    keyring.set_keyring(macOS.Keyring())


FILTER_HINT = (
    "Put text values in single quotes and numbers in backticks, "
    "e.g. \"[?host=='127.0.0.1']\" or '[?plugin_id==`19506`]'. "
    "See https://jmespath.org/ for more examples."
)


FILTER_OPTIONS_FILTER = "[0]"
FILTER_OPTIONS_FORMAT = "json"


def _filter_options_callback(ctx, param, value):
    # eager, so it is processed before --filter and --format
    ctx.meta["filter_options"] = value


def _format_callback(ctx, param, value):
    if ctx.meta.get("filter_options"):
        return FILTER_OPTIONS_FORMAT
    return value


DURATION_UNITS = {"d": 86400, "h": 3600, "m": 60, "s": 1}


def _parse_duration(ctx, param, value):
    """Turn duration like 7d, 12h, 30m, 45s or 1d6h into seconds."""
    if value is None:
        return None
    parts = re.findall(r"(\d+)([dhms])", value.lower())
    if not parts or "".join(n + u for n, u in parts) != value.lower():
        raise click.BadParameter(
            "use number with unit d, h, m or s, e.g. 7d, 12h, 30m, 1d6h, got '{}'".format(
                value
            )
        )
    return sum(int(number) * DURATION_UNITS[unit] for number, unit in parts)


_keyring_settings = {"enabled": True}


def _no_keyring_callback(ctx, param, no_keyring):
    _keyring_settings["enabled"] = not no_keyring


def _check_filter(ctx, param, value):
    """Validate JMESPath syntax of --filter before connecting to Nessus."""
    if ctx.meta.get("filter_options"):
        return FILTER_OPTIONS_FILTER
    if value:
        try:
            jmespath.compile(value)
        except jmespath.exceptions.JMESPathError as e:
            raise click.BadParameter("{}\n{}".format(e, FILTER_HINT))
    return value


_login_options = [
    click.option(
        "--address",
        "-a",
        default=["127.0.0.1"],
        multiple=True,
        prompt="address",
        help="address to which you want to login",
        show_default="127.0.0.1",
    ),
    click.option(
        "--port",
        default="443",
        help="port to which you want to login",
        show_default="443",
    ),
    click.option(
        "--username",
        "-u",
        default=os_user,
        prompt="username",
        help="username which you want to use to login",
        show_default="current user",
    ),
    click.option("--password", "-p", help="password which you want to use to login"),
    click.option(
        "--no-keyring",
        is_flag=True,
        expose_value=False,
        callback=_no_keyring_callback,
        help="don't read or save password in OS credential manager (keyring), "
        "e.g. in pipelines, use with --password",
    ),
    click.option(
        "--insecure",
        "-k",
        is_flag=True,
        help="perform insecure SSL connections and transfers",
    ),
    click.option(
        "--ca-cert",
        type=click.Path(exists=True, dir_okay=False),
        help="CA certificate (PEM) to verify the Nessus server certificate, e.g. a custom or Nessus CA",
    ),
    click.option(
        "--format",
        default="table",
        callback=_format_callback,
        help="data format to display [table,json,csv]",
        show_default="table",
    ),
    click.option(
        "--filter",
        "-f",
        callback=_check_filter,
        help="filter data with JMESPath. See https://jmespath.org/ for more information and examples.",
    ),
    click.option(
        "--filter-options",
        is_flag=True,
        is_eager=True,
        expose_value=False,
        callback=_filter_options_callback,
        help="show all fields of first item which can be used with --filter "
        '(runs -f "[0]" --format json)',
    ),
]

_output_settings = {"show_address": True}


def _banner_callback(ctx, param, hide_banner):
    if not hide_banner and not ctx.resilient_parsing:
        print("LimberDuck {} v.{}".format(__about__.__package_name__, __version__))


def _address_callback(ctx, param, hide_address):
    _output_settings["show_address"] = not hide_address


def _print_address(address, *values):
    """Print Nessus address (unless --hide-address) followed by given values."""
    parts = ([address] if _output_settings["show_address"] else []) + [
        str(value) for value in values
    ]
    if parts:
        print(*parts)


_general_options = [
    click.option("-v", "--verbose", count=True),
    click.option(
        "--hide-banner",
        is_flag=True,
        expose_value=False,
        callback=_banner_callback,
        help="don't print tool name and version",
    ),
    click.option(
        "--hide-address",
        is_flag=True,
        expose_value=False,
        callback=_address_callback,
        help="don't print Nessus address before results",
    ),
]


def add_options(options):
    def _add_options(func):
        for option in reversed(options):
            func = option(func)
        return func

    return _add_options


def set_vault_password(address, username, password):
    password_from_vault = keyring.get_password(address, username)
    if password_from_vault is None:
        keyring.set_password(address, username, password)
        if platform.system() == "Windows":
            print("Credentials successfully saved to Windows Credential Manager.")
            print(
                "Windows OS: Your credentials will be stored here "
                "Control Panel > Credential Manager > Windows Credential > Generic Credentials. "
                "You can remove or update it anytime."
            )

        if platform.system() == "Darwin":
            print("Credentials successfully saved to macOS Credential Manager.")
            print(
                "macOS: Your credentials will be stored here "
                'Keychain Access > search for "' + address + '". '
                "You can remove or update it anytime."
            )

    elif password_from_vault is not None and password_from_vault != password:
        print(
            "Password for {} @ {} already exist in OS Credential Manager and "
            "is different than provided by you!".format(username, address)
        )

        vault_update_answer = (
            input(
                "Do you want to update password in "
                "OS Credential Manager? (yes): ".format(username, address)
            )
            or "yes"
        )

        if vault_update_answer == "yes":
            keyring.set_password(address, username, password)
            if platform.system() == "Windows":
                print("Credentials successfully saved to Windows Credential Manager.")
                print(
                    "Windows OS: Your credentials will be stored here "
                    "Control Panel > Credential Manager > Windows Credential > Generic Credentials. "
                    "You can remove or update it anytime."
                )

            if platform.system() == "Darwin":
                print("Credentials successfully saved to macOS Credential Manager.")
                print(
                    "macOS: Your credentials will be stored here "
                    'Keychain Access > search for "' + address + '". '
                    "You can remove or update it anytime."
                )


def get_vault_password(address, username, verbose):
    password = None
    if platform.system() == "Windows" or platform.system() == "Darwin":
        if verbose:
            print("Looking for password in OS Credential Manager")
        password_from_vault = keyring.get_password(address, username)
        if password_from_vault:
            password = password_from_vault
            if verbose:
                print("Password found.")
        else:
            if verbose:
                print("Password not found.")

    return password


def password_check(address, username, password, verbose):
    if not _keyring_settings["enabled"]:
        # e.g. pipeline agent without OS credential manager, keyring is not touched at all
        if password:
            return password
        if not sys.stdin.isatty():
            raise click.UsageError(
                "--no-keyring needs --password when not run in a terminal"
            )
        return click.prompt("password", hide_input=True)

    if not password:
        password = get_vault_password(address, username, verbose)

    if not password:
        password = click.prompt("password", hide_input=True, confirmation_prompt=True)
        set_vault_password(address, username, password)

    if password:
        set_vault_password(address, username, password)

    return password


def dataframe_table(data, sortby=None, groupby=None, tablefmt=None):
    pd.set_option("display.max_rows", None)
    pd.set_option("display.max_columns", None)
    pd.set_option("display.width", None)
    pd.set_option("display.max_colwidth", None)
    df = pd.DataFrame(data)
    df.head()
    if sortby:
        df = df.sort_values(by=sortby)
    if groupby:
        df = df.groupby(groupby)[groupby[0]].count().reset_index(name="count")
    s = pd.Series(data=list(range(1, len(df) + 1)), dtype="object")
    df = df.set_index(s)
    if tablefmt:
        df = str(tabulate(df, headers="keys", tablefmt=tablefmt))
    return df


PACKAGE_NAME = __about__.__package_name__


@click.group(
    invoke_without_command=True,
    help="TNSCM - manages Tenable Nessus servers from command line",
    epilog=f"Additional information:\n\n"
    f"https://limberduck.org/en/latest/tools/{PACKAGE_NAME}\n"
    f"https://github.com/LimberDuck/{PACKAGE_NAME}\n"
    f"https://github.com/LimberDuck/{PACKAGE_NAME}/releases\n",
)
@click.version_option(
    __version__, "--version", "-v", message=f"{PACKAGE_NAME} v.%(version)s"
)
@click.option(
    "--update-check",
    "-u",
    is_flag=True,
    help="Check if a new version is available and exit.",
)
@click.pass_context
def cli(ctx, update_check):
    if ctx.invoked_subcommand is None and not update_check:
        click.echo(ctx.get_help())
        ctx.exit(0)
    if ctx.invoked_subcommand is None and update_check:
        utilities.check_for_update()


HEALTH_SEVERITY_NAMES = {1: "info", 3: "warning", 5: "critical"}


def _health_alert_rows(alerts):
    return [
        {
            "severity": HEALTH_SEVERITY_NAMES.get(
                alert.get("severity"), alert.get("severity")
            ),
            "alert": alert.get("alert", ""),
            "description": alert.get("description", ""),
        }
        for alert in alerts or []
    ]


def _health_stats_rows(stats):
    """Most useful current scanner statistics as attribute / value rows."""
    current = (stats or {}).get("perf_stats_current") or (
        (stats or {}).get("perf_stats_history") or [{}]
    )[-1]

    def free_of(free_key, total_key):
        return "{} of {} MB".format(current.get(free_key), current.get(total_key))

    rows = [
        ("Nessus CPU", "{} %".format(current.get("nessus_cpu"))),
        ("CPU load average", current.get("cpu_load_avg")),
        ("CPU cores", current.get("sys_cores")),
        ("Nessus memory", "{} MB".format(current.get("nessus_mem"))),
        ("System RAM", "{} MB".format(current.get("sys_ram"))),
        ("Data disk free", free_of("nessus_data_disk_free", "nessus_data_disk_total")),
        ("Log disk free", free_of("nessus_log_disk_free", "nessus_log_disk_total")),
        ("Temp disk free", free_of("temp_disk_free", "temp_disk_total")),
        ("Running scans", current.get("num_scans")),
        ("Scanned hosts", current.get("num_hosts")),
        ("DNS failures", current.get("dns_failures")),
        ("Reverse DNS failures", current.get("dns_reverse_failures")),
        ("Plugins failed to compile", current.get("plugins_failed_to_compile_count")),
    ]
    return [{"attribute": name, "value": value} for name, value in rows]


def _age_text(seconds):
    days, rest = divmod(int(max(seconds, 0)), 86400)
    return "{}d {}h".format(days, rest // 3600)


def _license_rows(properties, warn_days=None, feed_max_age=None):
    """
    Licence and plugin feed checks with status ok / warning.
    Only selected fields are used, server properties contain secrets like activation code.
    """
    license_info = properties.get("license") or {}
    now = time.time()
    rows = []

    def add(check, value, warning=False):
        rows.append(
            {"check": check, "value": value, "status": "warning" if warning else "ok"}
        )

    add("type", license_info.get("name") or properties.get("nessus_type", ""))
    add("version", properties.get("server_version", ""))
    add("evaluation", "yes" if license_info.get("eval") else "no")

    licensed_ips, used_ips = license_info.get("ips"), properties.get("used_ip_count")
    if licensed_ips is not None and used_ips is not None:
        add(
            "IPs",
            "{} used of {}".format(used_ips, licensed_ips),
            int(used_ips) >= int(licensed_ips),
        )

    expiration = license_info.get("expiration_date") or properties.get("expiration")
    if expiration:
        days_left = (int(expiration) - now) / 86400
        add(
            "license expiration",
            "{} ({} days left)".format(_ts(expiration), int(days_left)),
            days_left < 0 or (warn_days is not None and days_left <= warn_days),
        )

    plugin_set = properties.get("plugin_set")
    if plugin_set:
        try:
            # plugin set id is its publication time, e.g. 202610231756
            published = datetime.datetime.strptime(
                str(plugin_set)[:12], "%Y%m%d%H%M"
            ).replace(tzinfo=datetime.timezone.utc)
            age = now - published.timestamp()
            add(
                "plugin set",
                "{} ({:%Y-%m-%d %H:%M} UTC, {} old)".format(
                    plugin_set, published, _age_text(age)
                ),
                feed_max_age is not None and age > feed_max_age,
            )
        except ValueError:
            add("plugin set", plugin_set)

        loaded = properties.get("loaded_plugin_set")
        if loaded:
            add(
                "loaded plugin set",
                "same as downloaded" if loaded == plugin_set else loaded,
                loaded != plugin_set,
            )

    if properties.get("feed_error"):
        add("plugin feed", properties.get("feed_error_message") or "error", True)

    add(
        "restart needed",
        "yes" if properties.get("restart_needed") else "no",
        bool(properties.get("restart_needed")),
    )
    new_version = (properties.get("update") or {}).get("new_version")
    add("new version available", new_version if new_version else "no")
    return rows


def _print_rows(rows, filter, format):
    if filter:
        rows = jmespath.search(filter, rows)
    if rows:
        _print_data(rows, format)
    else:
        print("No items!")


@cli.command()
@add_options(_login_options)
@add_options(_general_options)
@click.option("--status", is_flag=True, help="Get server status")
@click.option(
    "--ips",
    is_flag=True,
    help="Use to see number of licensed IPs, active IPs and left IPs",
)
@click.option("--version", is_flag=True, help="Get server version")
@click.option(
    "--health",
    is_flag=True,
    help="Get scanner health alerts and statistics, exit code 1 on critical alert",
)
@click.option(
    "--license",
    "license_check",
    is_flag=True,
    help="Get licence and plugin feed status, exit code 1 on any warning",
)
@click.option(
    "--warn-days",
    type=click.IntRange(min=0),
    metavar="N",
    help="with --license warn when licence expires in N days or less",
)
@click.option(
    "--feed-max-age",
    metavar="DURATION",
    callback=_parse_duration,
    help="with --license warn when plugin set is older than DURATION, e.g. 2d, 12h",
)
def server(
    address,
    port,
    username,
    password,
    insecure,
    ca_cert,
    format,
    filter,
    status,
    ips,
    version,
    health,
    license_check,
    warn_days,
    feed_max_age,
    verbose,
):
    """get Nessus server info"""

    if (warn_days is not None or feed_max_age is not None) and not license_check:
        raise click.UsageError(
            "--warn-days and --feed-max-age can be used only with --license"
        )

    any_failed = False

    for one_address in address:
        one_password = password_check(one_address, username, password, verbose)

        tnscon = TnsApi(one_address, port, insecure, ca_cert)
        tnscon.login(username, one_password)

        if status:
            server_status = tnscon.server_status_get()
            _print_address(one_address, server_status)
        if ips:
            server_properties = tnscon.server_properties_get()
            licensed_ips = server_properties["license"]["ips"]
            active_ips = server_properties["used_ip_count"]
            left_ips = int(licensed_ips) - int(active_ips)
            left_ips_percentage = str(
                int(100 - 100 * int(active_ips) / int(licensed_ips))
            )
            _print_address(
                one_address,
                "{} - {} = {} ({}%) remaining IPs".format(
                    int(licensed_ips), int(active_ips), left_ips, left_ips_percentage
                ),
            )

        if version:
            nessus_type = tnscon.server_properties_get()["nessus_type"]
            server_version = tnscon.server_properties_get()["server_version"]
            _print_address(one_address, nessus_type, server_version)

        if health:
            _print_address(one_address)
            alerts = tnscon.server_health_alerts_get()
            print("Alerts:")
            _print_rows(_health_alert_rows(alerts), filter, format)
            print("\nStatistics:")
            _print_rows(
                _health_stats_rows(tnscon.server_health_stats_get()), filter, format
            )
            any_failed = any_failed or any(
                alert.get("severity") == 5 for alert in alerts or []
            )

        if license_check:
            _print_address(one_address)
            rows = _license_rows(
                tnscon.server_properties_get(), warn_days, feed_max_age
            )
            _print_rows(rows, filter, format)
            any_failed = any_failed or any(row["status"] == "warning" for row in rows)

        tnscon.logout()

    if any_failed:
        sys.exit(1)


@cli.command()
@add_options(_login_options)
@add_options(_general_options)
@click.option("--list", is_flag=True, help="Get user list")
def user(
    address, port, username, password, insecure, ca_cert, format, filter, list, verbose
):
    """get Nessus user info"""

    for one_address in address:
        one_password = password_check(one_address, username, password, verbose)

        tnscon = TnsApi(one_address, port, insecure, ca_cert)
        tnscon.login(username, one_password)

        if list:
            _print_address(one_address)
            users_on_nessus = tnscon.users_get()

            for user_on_nessus in users_on_nessus:
                if "lastlogin" in user_on_nessus:
                    user_on_nessus.update(
                        {
                            "lastlogin": str(
                                datetime.datetime.fromtimestamp(
                                    0
                                    if user_on_nessus["lastlogin"] is None
                                    else user_on_nessus["lastlogin"]
                                )
                            )
                        }
                    )

            default_filter = (
                "[].{"
                "id: id, "
                "username: username, "
                "name: name, "
                "lastlogin: lastlogin}"
            )

            if filter:
                expression = jmespath.compile(filter)
            else:
                expression = jmespath.compile(default_filter)

            users_on_nessus = expression.search(users_on_nessus)

            if format == "table":
                print(dataframe_table(users_on_nessus))
            elif format == "csv":
                print(dataframe_table(users_on_nessus).to_csv(index=False), "\n")
            else:
                print(users_on_nessus)

        else:
            print("No option given!")

        tnscon.logout()


def _flatten_policy(details, path=()):
    """Flatten nested policy details to {(section, key, ...): value}, empty sections are skipped."""
    flat = {}
    for key, value in details.items():
        key_path = path + (str(key),)
        if isinstance(value, dict):
            flat.update(_flatten_policy(value, key_path))
        elif isinstance(value, list):
            if value:
                flat[key_path] = json.dumps(value)
        else:
            flat[key_path] = "" if value is None else str(value)
    return flat


def _policy_setting_paths(editor):
    """
    Map setting id to its location in Nessus UI built from policy editor data, e.g.
    test_local_nessus_host -> "Discovery > Host Discovery > Ping the remote host >
    General Settings > Test the local Nessus host".
    """
    paths = {}

    def walk(node, trail):
        if isinstance(node, list):
            for item in node:
                walk(item, trail)
            return
        if not isinstance(node, dict):
            return

        is_input = "id" in node and "type" in node
        if is_input:
            own_label = node.get("label") or node.get("name") or str(node["id"])
            paths.setdefault(node["id"], " > ".join(trail + [own_label]))
        else:
            own_label = node.get("title")

        child_trail = trail
        if own_label and own_label not in trail:
            child_trail = trail + [own_label]
        for value in node.values():
            if isinstance(value, (dict, list)):
                walk(value, child_trail)

    walk(editor.get("settings") or {}, [])
    # global options of credential types, e.g. SSH "Attempt least privilege"
    for category in (editor.get("credentials") or {}).get("data") or []:
        for credential_type in category.get("types") or []:
            walk(
                credential_type.get("settings") or {},
                [
                    "Credentials",
                    category.get("name", ""),
                    credential_type.get("name", ""),
                ],
            )
    return paths


def _name_policy_credentials(editor, flat):
    """
    Replace credential instance ids with their category and type, e.g.
    ("credentials", "edit", "23", "username") -> ("credentials", "Host", "SSH", "username"),
    so credentials of the same type are compared between policies.
    """
    if not any(path[0] == "credentials" for path in flat):
        return flat

    instance_names = {}
    for category in (editor.get("credentials") or {}).get("data") or []:
        for credential_type in category.get("types") or []:
            instances = credential_type.get("instances") or []
            for number, instance in enumerate(instances, 1):
                type_name = credential_type["name"]
                if number > 1:
                    type_name = "{} #{}".format(type_name, number)
                instance_names[str(instance["id"])] = (category["name"], type_name)

    named = {}
    for path, value in flat.items():
        if path[0] == "credentials" and len(path) >= 3 and path[2] in instance_names:
            path = ("credentials",) + instance_names[path[2]] + path[3:]
        named[path] = value
    return named


def _expand_mixed_plugin_families(tnscon, flat_policies):
    """
    For plugin families which are mixed in any policy set status of every plugin
    of the family in every policy. Return {plugin id: plugin name}.
    """
    mixed_families = sorted(
        {
            path[1]
            for flat in flat_policies
            for path, value in flat.items()
            if path[0] == "plugins" and path[2:] == ("status",) and value == "mixed"
        }
    )
    if not mixed_families:
        return {}

    family_ids = {f["name"]: f["id"] for f in tnscon.plugins_families_get() or []}
    plugin_names = {}
    for family in mixed_families:
        if family not in family_ids:
            continue
        family_details = tnscon.plugin_family_details_get(family_ids[family]) or {}
        family_plugins = family_details.get("plugins") or []
        for flat in flat_policies:
            family_status = flat.get(("plugins", family, "status"))
            for family_plugin in family_plugins:
                plugin_id = str(family_plugin["id"])
                plugin_names[plugin_id] = family_plugin["name"]
                key = ("plugins", family, "individual", plugin_id)
                if family_status == "mixed":
                    # Nessus lists only enabled plugins of a mixed family
                    flat.setdefault(key, "disabled")
                elif family_status:
                    flat[key] = family_status
    return plugin_names


def _policy_path_sort_key(path):
    """Sort plugin family status before its individual plugins, plugins by id."""
    if path[0] == "plugins" and len(path) >= 4 and path[2] == "individual":
        plugin_id = int(path[3]) if path[3].isdigit() else 0
        return (path[0], path[1], 1, plugin_id, " > ".join(path[3:]))
    if path[0] == "plugins" and len(path) >= 3:
        return (path[0], path[1], 0, 0, " > ".join(path[2:]))
    return (path[0], " > ".join(path[1:]), 0, 0, "")


def _compare_policies(
    labels, flat_policies, plugin_names=None, setting_paths=None, policy_ids=None
):
    """One row per setting with both values and result: same, different or only in <policy id>."""
    policy_ids = policy_ids or labels
    first, second = flat_policies
    plugin_names = plugin_names or {}
    setting_paths = setting_paths or {}
    rows = []
    for path in sorted(set(first) | set(second), key=_policy_path_sort_key):
        section = path[0]
        if section == "plugins" and len(path) == 4 and path[2] == "individual":
            setting = "{} > {} {}".format(
                path[1], path[3], plugin_names.get(path[3], "")
            ).rstrip()
        else:
            # plugin family names can contain dots, so nested keys are joined with " > "
            setting = " > ".join(path[1:])
        if path not in second:
            result = "only in {}".format(policy_ids[0])
        elif path not in first:
            result = "only in {}".format(policy_ids[1])
        elif first[path] == second[path]:
            result = "same"
        else:
            result = "different"
        if section == "settings":
            # location in Nessus UI, setting id when it isn't shown in UI
            setting = setting_paths.get(setting, setting)
        rows.append(
            {
                "section": section,
                "setting": setting or section,
                labels[0]: first.get(path, ""),
                labels[1]: second.get(path, ""),
                "result": result,
            }
        )
    return rows


@cli.command()
@add_options(_login_options)
@add_options(_general_options)
@click.option("--list", is_flag=True, help="Get scan policy list")
@click.option("--delete", is_flag=True, help="Delete scan policy")
@click.option(
    "--compare",
    type=int,
    nargs=2,
    metavar="ID ID",
    help="compare all settings of two policies",
)
@click.option(
    "--diff",
    is_flag=True,
    help="with --compare show only settings which are different",
)
@click.option(
    "--download",
    is_flag=True,
    help="download (export) policies as .nessus files, all or given with --policy-id",
)
@click.option(
    "--policy-id",
    type=int,
    multiple=True,
    help="policy id to download, can be repeated",
)
@click.option(
    "--output-dir",
    default=".",
    type=click.Path(file_okay=False),
    help="directory for downloaded files",
    show_default=True,
)
@click.option(
    "--overwrite", is_flag=True, help="download again files that already exist"
)
@click.option(
    "--upload",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False),
    help="upload (import) policy from .nessus file, e.g. made by --download, can be repeated",
)
def policy(
    address,
    port,
    username,
    password,
    insecure,
    ca_cert,
    format,
    filter,
    list,
    delete,
    compare,
    diff,
    download,
    policy_id,
    output_dir,
    overwrite,
    upload,
    verbose,
):
    """get Nessus policy info"""

    if policy_id and not download:
        raise click.UsageError("--policy-id can be used only with --download")

    any_failed = False

    for one_address in address:
        one_password = password_check(one_address, username, password, verbose)

        tnscon = TnsApi(one_address, port, insecure, ca_cert)
        tnscon.login(username, one_password)

        if list:
            _print_address(one_address)
            scan_policies_on_nessus = tnscon.policies_get()
            if scan_policies_on_nessus is None:
                print("No items!")
                sys.exit(1)

            for scan_policy_on_nessus in scan_policies_on_nessus:
                if "creation_date" in scan_policy_on_nessus:
                    scan_policy_on_nessus.update(
                        {
                            "creation_date": str(
                                datetime.datetime.fromtimestamp(
                                    int(scan_policy_on_nessus["creation_date"])
                                )
                            )
                        }
                    )
                if "last_modification_date" in scan_policy_on_nessus:
                    scan_policy_on_nessus.update(
                        {
                            "last_modification_date": str(
                                datetime.datetime.fromtimestamp(
                                    int(scan_policy_on_nessus["last_modification_date"])
                                )
                            )
                        }
                    )

            default_filter = (
                "[].{"
                "id: id, "
                "name: name, "
                "owner: owner, "
                "creation_date: creation_date, "
                "last_modification_date: last_modification_date}"
            )

            if filter:
                expression = jmespath.compile(filter)
            else:
                expression = jmespath.compile(default_filter)

            scan_policies_on_nessus = expression.search(scan_policies_on_nessus)

            if scan_policies_on_nessus is not None:
                if format == "table":
                    print(dataframe_table(scan_policies_on_nessus))
                elif format == "csv":
                    print(
                        dataframe_table(scan_policies_on_nessus).to_csv(index=False),
                        "\n",
                    )
                else:
                    print(scan_policies_on_nessus)
            else:
                print("{} doesn't have any policies!".format(username))

        if delete:
            _print_address(one_address)
            scan_policies_on_nessus = tnscon.policies_get()

            if scan_policies_on_nessus is None:
                print("No items!")
                sys.exit(1)

            for scan_policy_on_nessus in scan_policies_on_nessus:
                if "creation_date" in scan_policy_on_nessus:
                    scan_policy_on_nessus.update(
                        {
                            "creation_date": str(
                                datetime.datetime.fromtimestamp(
                                    int(scan_policy_on_nessus["creation_date"])
                                )
                            )
                        }
                    )
                if "last_modification_date" in scan_policy_on_nessus:
                    scan_policy_on_nessus.update(
                        {
                            "last_modification_date": str(
                                datetime.datetime.fromtimestamp(
                                    int(scan_policy_on_nessus["last_modification_date"])
                                )
                            )
                        }
                    )

            default_filter = (
                "[].{"
                "id: id, "
                "name: name, "
                "owner: owner, "
                "creation_date: creation_date, "
                "last_modification_date: last_modification_date}"
            )

            if filter:
                expression = jmespath.compile(filter)
            else:
                expression = jmespath.compile(default_filter)

            scan_policies_on_nessus = expression.search(scan_policies_on_nessus)

            if scan_policies_on_nessus is not None:
                if format == "table":
                    print(dataframe_table(scan_policies_on_nessus))
                elif format == "csv":
                    print(
                        dataframe_table(scan_policies_on_nessus).to_csv(index=False),
                        "\n",
                    )
                else:
                    print(scan_policies_on_nessus)

                if len(scan_policies_on_nessus) == 1:
                    item_or_items = "policy"
                else:
                    item_or_items = "policies"

                if "id" not in scan_policies_on_nessus[0]:
                    print(
                        "\nYou can't delete POLICY without POLICY ID. Use ID in your filter!"
                    )
                    sys.exit(0)

                if click.confirm(
                    "\nDo you want to delete {} {} listed above?".format(
                        len(scan_policies_on_nessus), item_or_items
                    )
                ):
                    for scan_policy_on_nessus in scan_policies_on_nessus:
                        scan_policy_id = scan_policy_on_nessus["id"]
                        print("Deleting policy id {}".format(scan_policy_id))
                        tnscon.policies_delete(scan_policy_id)
                else:
                    print("Nothing will be deleted")

            else:
                print("{} doesn't have any policies!".format(username))

        if compare:
            _print_address(one_address)
            policies_by_id = {p["id"]: p for p in tnscon.policies_get() or []}
            missing_ids = [p_id for p_id in compare if p_id not in policies_by_id]
            if missing_ids:
                raise click.BadParameter(
                    "policy id {} not found. Use --list to see available policies.".format(
                        ", ".join(map(str, missing_ids))
                    ),
                    param_hint="--compare",
                )

            labels = [
                "{} ({})".format(policies_by_id[p_id]["name"], p_id) for p_id in compare
            ]
            if labels[0] == labels[1]:
                raise click.BadParameter(
                    "give two different policy ids", param_hint="--compare"
                )

            flat_policies = []
            setting_paths = {}
            for p_id in compare:
                editor = tnscon.policy_editor_get(p_id) or {}
                for setting_id, setting_path in _policy_setting_paths(editor).items():
                    setting_paths.setdefault(setting_id, setting_path)
                flat_policies.append(
                    _name_policy_credentials(
                        editor, _flatten_policy(tnscon.policy_details_get(p_id))
                    )
                )
            plugin_names = _expand_mixed_plugin_families(tnscon, flat_policies)
            comparison = _compare_policies(
                labels, flat_policies, plugin_names, setting_paths, compare
            )

            counts = collections.Counter(
                "only in one" if row["result"].startswith("only in") else row["result"]
                for row in comparison
            )
            if diff:
                comparison = [row for row in comparison if row["result"] != "same"]

            if filter:
                comparison = jmespath.search(filter, comparison)

            if comparison:
                _print_data(comparison, format)
            else:
                print("No differences!")

            if format == "table":
                print(
                    "\n{} settings compared: {} same, {} different, {} only in one policy".format(
                        sum(counts.values()),
                        counts["same"],
                        counts["different"],
                        counts["only in one"],
                    )
                )

        if download:
            _print_address(one_address)
            policies_on_nessus = tnscon.policies_get() or []
            if policy_id:
                found_ids = {p["id"] for p in policies_on_nessus}
                missing_ids = [p_id for p_id in policy_id if p_id not in found_ids]
                if missing_ids:
                    raise click.BadParameter(
                        "policy id {} not found. Use --list to see available policies.".format(
                            ", ".join(map(str, missing_ids))
                        ),
                        param_hint="--policy-id",
                    )
                policies_on_nessus = [
                    p for p in policies_on_nessus if p["id"] in policy_id
                ]

            if not policies_on_nessus:
                print("Nothing to download!")
            else:
                counts = _download_policies(
                    tnscon, one_address, policies_on_nessus, output_dir, overwrite
                )
                any_failed = any_failed or counts["failed"] > 0

        if upload:
            _print_address(one_address)
            counts = _upload_policies(tnscon, upload)
            any_failed = any_failed or counts["failed"] > 0

        if not (list or delete or compare or download or upload):
            print("No option given!")

        tnscon.logout()

    if any_failed:
        sys.exit(1)


EXPORTABLE_STATUSES = ("completed", "imported")
EXPORT_POLL_SECONDS = 2
EXPORT_TIMEOUT_SECONDS = 600


def _ts(value):
    return str(datetime.datetime.fromtimestamp(int(value)))


def _print_data(data, format):
    if format == "table":
        print(dataframe_table(data))
    elif format == "csv":
        print(dataframe_table(data).to_csv(index=False), "\n")
    else:
        print(data)


def _resolve_folders(tnscon, folder_args):
    """Map folder ids or names given with --folder to folder ids."""
    folders = tnscon.folders_get() or []
    folder_ids = []
    for folder_arg in folder_args:
        matches = [
            f["id"]
            for f in folders
            if str(f["id"]) == folder_arg or f["name"].lower() == folder_arg.lower()
        ]
        if not matches:
            raise click.BadParameter(
                "folder '{}' not found. Use --list-folders to see available folders.".format(
                    folder_arg
                ),
                param_hint="--folder",
            )
        folder_ids.extend(matches)
    return folder_ids


SEVERITY_NAMES = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}


def _parse_scan_runs(ctx, param, values):
    """Turn SCAN_ID:HISTORY_ID option values into (scan id, history id) pairs."""
    if not values:
        return None
    runs = []
    for value in values:
        scan_id, separator, history_id = value.partition(":")
        if not (separator and scan_id.isdigit() and history_id.isdigit()):
            raise click.BadParameter("use SCAN_ID:HISTORY_ID, got '{}'".format(value))
        runs.append((int(scan_id), int(history_id)))
    return runs


def _scan_run_findings(tnscon, scan_id, history_id):
    """Return run info and {(hostname, plugin id): finding} for one scan run."""
    try:
        details = tnscon.scans_details_get(scan_id, history_id)
    except TnsApiError as e:
        if e.status_code != 404:
            raise
        details = {}
    history_ids = [h["history_id"] for h in details.get("history") or []]
    if history_id not in history_ids:
        raise click.BadParameter(
            "scan {} has no history id {}. Use --list-history to see available runs.".format(
                scan_id, history_id
            ),
            param_hint="--compare",
        )

    findings = {}
    for host in details.get("hosts") or []:
        host_details = tnscon.scan_host_details_get(
            scan_id, host["host_id"], history_id
        )
        for vulnerability in host_details.get("vulnerabilities") or []:
            findings[(host["hostname"], vulnerability["plugin_id"])] = vulnerability
    return details["info"], findings


def _scan_run_summary(label, run_info, run_findings):
    """One line describing scan run: times, status and findings per severity."""
    scan_start = int(run_info.get("scan_start") or 0)
    scan_end = int(run_info.get("scan_end") or 0)
    elapsed = (
        str(datetime.timedelta(seconds=scan_end - scan_start))
        if scan_start and scan_end >= scan_start
        else ""
    )
    severity_counts = collections.Counter(
        finding["severity"] for finding in run_findings.values()
    )
    per_severity = ", ".join(
        "{} {}".format(name, severity_counts[severity])
        for severity, name in sorted(SEVERITY_NAMES.items(), reverse=True)
    )
    return (
        "{} = {}, started {}, ended {}, elapsed {}, status {}, "
        "{} findings ({})".format(
            label,
            run_info.get("name"),
            _ts(scan_start) if scan_start else "",
            _ts(scan_end) if scan_end else "",
            elapsed,
            run_info.get("status"),
            len(run_findings),
            per_severity,
        )
    )


def _compare_scan_runs(labels, run_findings):
    """One row per host and plugin: new, fixed, severity changed or same."""
    older, newer = run_findings
    keyed_rows = []
    for key in set(older) | set(newer):
        hostname, plugin_id = key
        older_finding, newer_finding = older.get(key), newer.get(key)
        finding = newer_finding or older_finding
        if older_finding is None:
            result = "new"
        elif newer_finding is None:
            result = "fixed"
        elif older_finding["severity"] != newer_finding["severity"]:
            result = "severity changed"
        else:
            result = "same"
        row = {
            "host": hostname,
            "plugin_id": plugin_id,
            "plugin_name": finding["plugin_name"],
            labels[0]: (
                SEVERITY_NAMES.get(older_finding["severity"], "")
                if older_finding
                else ""
            ),
            labels[1]: (
                SEVERITY_NAMES.get(newer_finding["severity"], "")
                if newer_finding
                else ""
            ),
            "result": result,
        }
        # per host: most severe findings first
        keyed_rows.append(((hostname, -finding["severity"], plugin_id), row))
    return [row for _, row in sorted(keyed_rows, key=lambda keyed_row: keyed_row[0])]


def _get_scans(tnscon, folder_ids):
    if not folder_ids:
        return tnscon.scans_get() or []
    scans = []
    for folder_id in folder_ids:
        for scan in tnscon.scans_get(folder_id) or []:
            # folder_id is not returned when listing a single folder
            scan.setdefault("folder_id", folder_id)
            scans.append(scan)
    return scans


def _collect_runs(tnscon, folder_ids=None, scan_ids=None, max_age=None):
    """Flatten scans and their history into one row per run (history entry)."""
    folder_names = {f["id"]: f["name"] for f in tnscon.folders_get() or []}
    scans = _get_scans(tnscon, folder_ids)

    if scan_ids:
        found_ids = {scan["id"] for scan in scans}
        missing_ids = [scan_id for scan_id in scan_ids if scan_id not in found_ids]
        if missing_ids:
            raise click.BadParameter(
                "scan id {} not found.".format(", ".join(map(str, missing_ids))),
                param_hint="--scan-id",
            )
        scans = [scan for scan in scans if scan["id"] in scan_ids]

    since = time.time() - max_age if max_age is not None else None

    runs = []
    for scan in scans:
        history = tnscon.scans_history_get(scan["id"])
        if not history:
            history = [
                {
                    "history_id": "",
                    "creation_date": scan.get("creation_date"),
                    "last_modification_date": scan.get("last_modification_date"),
                    "status": scan.get("status"),
                }
            ]

        for history_entry in history:
            run = dict(history_entry)
            run.update(
                {
                    "folder_id": scan["folder_id"],
                    "folder_name": folder_names.get(scan["folder_id"], ""),
                    "id": scan["id"],
                    "name": scan["name"],
                    "owner": scan["owner"],
                }
            )
            if since is not None and int(run.get("creation_date") or 0) < since:
                continue
            runs.append(run)

    runs.sort(
        key=lambda r: (
            r["folder_name"],
            r["name"],
            r["id"],
            int(r.get("creation_date") or 0),
        )
    )
    return runs


def _select_runs(runs, scan_ids, history_id, max_age, which_runs):
    if history_id is not None:
        return [run for run in runs if run["history_id"] == history_id]
    if which_runs is None:
        which_runs = "latest" if scan_ids and max_age is None else "all"
    if which_runs == "latest":
        # latest exportable run per scan, or latest run so its status gets reported
        latest = {}
        for run in runs:
            current = latest.get(run["id"])
            if (
                current is None
                or run["status"] in EXPORTABLE_STATUSES
                or current["status"] not in EXPORTABLE_STATUSES
            ):
                latest[run["id"]] = run
        return [*latest.values()]
    return runs


def _run_label(run):
    return "{} (scan {}, history {})".format(run["name"], run["id"], run["history_id"])


def _safe_file_name(parts, file_format):
    """Join parts into file name, characters other than letters, digits, . _ - become _."""
    safe_parts = [re.sub(r"[^A-Za-z0-9._-]+", "_", str(p)).strip("_") for p in parts]
    return "{}.{}".format("_".join(safe_parts), file_format)


def _run_file_name(address, run, file_format):
    started = datetime.datetime.fromtimestamp(int(run.get("creation_date") or 0))
    parts = [
        address,
        run["id"],
        run["history_id"],
        run["name"],
        started.strftime("%Y%m%d-%H%M%S"),
    ]
    return _safe_file_name(parts, file_format)


def _upload_policies(tnscon, files):
    """Import each .nessus policy file, return counts of imported and failed."""
    counts = {"imported": 0, "failed": 0}
    for path in files:
        try:
            imported = tnscon.policy_import(path) or {}
            outcome = "imported"
            message = "policy {} {}".format(
                imported.get("id", ""), imported.get("name", "")
            ).strip()
        except (TnsApiError, OSError, KeyError, ValueError) as e:
            outcome, message = "failed", str(e)
        counts[outcome] += 1
        print("{:<8} {} - {}".format(outcome, path, message), flush=True)

    print("imported {imported}, failed {failed}".format(**counts), flush=True)
    return counts


def _download_policies(tnscon, address, policies, output_dir, overwrite):
    """Save each policy as .nessus file, return counts of saved, skipped and failed."""
    os.makedirs(output_dir, exist_ok=True)
    counts = {"saved": 0, "skipped": 0, "failed": 0}

    for policy in policies:
        modified = datetime.datetime.fromtimestamp(
            int(policy.get("last_modification_date") or 0)
        )
        out_path = os.path.join(
            output_dir,
            _safe_file_name(
                [
                    address,
                    policy["id"],
                    policy["name"],
                    modified.strftime("%Y%m%d-%H%M%S"),
                ],
                "nessus",
            ),
        )

        if os.path.exists(out_path) and not overwrite:
            outcome, message = "skipped", "already exists: {}".format(out_path)
        else:
            part_path = out_path + ".part"
            try:
                tnscon.policy_export(policy["id"], part_path)
                os.replace(part_path, out_path)
                outcome, message = "saved", out_path
            except (TnsApiError, OSError) as e:
                outcome, message = "failed", str(e)
            finally:
                if os.path.exists(part_path):
                    os.remove(part_path)

        counts[outcome] += 1
        print(
            "{:<8} {} (policy {}) - {}".format(
                outcome, policy["name"], policy["id"], message
            ),
            flush=True,
        )

    print(
        "downloaded {saved}, skipped {skipped}, failed {failed}".format(**counts),
        flush=True,
    )
    return counts


def _export_run(tnscon, scan_id, history_id, file_format, out_path, on_wait=None):
    """Request an export, wait until Nessus prepares it and save it to out_path."""
    export = tnscon.scan_export_request(scan_id, history_id or None, file_format)
    file_id = export["file"]

    start_time = time.time()
    while True:
        status = tnscon.scan_export_status(scan_id, file_id)["status"]
        if status == "ready":
            break
        if status == "error":
            raise RuntimeError("export failed on Nessus side")
        elapsed = int(time.time() - start_time)
        if elapsed > EXPORT_TIMEOUT_SECONDS:
            raise RuntimeError(
                "export not ready after {}s".format(EXPORT_TIMEOUT_SECONDS)
            )
        if on_wait:
            on_wait(elapsed)
        time.sleep(EXPORT_POLL_SECONDS)

    part_path = out_path + ".part"
    try:
        tnscon.scan_export_download(scan_id, file_id, part_path)
        os.replace(part_path, out_path)
    finally:
        if os.path.exists(part_path):
            os.remove(part_path)


def _download_run(
    tnscon, address, run, file_format, output_dir, overwrite, on_wait=None
):
    """Return (outcome, message) where outcome is saved, skipped or failed."""
    if run["status"] not in EXPORTABLE_STATUSES:
        return "skipped", "status is {}".format(run["status"])

    out_path = os.path.join(output_dir, _run_file_name(address, run, file_format))
    if os.path.exists(out_path) and not overwrite:
        return "skipped", "already exists: {}".format(out_path)

    try:
        _export_run(
            tnscon, run["id"], run["history_id"], file_format, out_path, on_wait
        )
    except (TnsApiError, RuntimeError, OSError) as e:
        return "failed", str(e)
    return "saved", out_path


def _download_runs(
    tnscon, address, runs, file_format, output_dir, overwrite, show_progress
):
    os.makedirs(output_dir, exist_ok=True)
    counts = {"saved": 0, "skipped": 0, "failed": 0}

    def report(outcome, run, message):
        counts[outcome] += 1
        print("{:<8} {} - {}".format(outcome, _run_label(run), message), flush=True)

    if show_progress:
        results = []
        with click.progressbar(
            length=len(runs),
            label="Downloading",
            file=sys.stderr,
            show_pos=True,
            item_show_func=lambda item: item,
        ) as bar:
            for run in runs:
                label = _run_label(run)
                bar.update(0, label)
                outcome, message = _download_run(
                    tnscon,
                    address,
                    run,
                    file_format,
                    output_dir,
                    overwrite,
                    on_wait=lambda elapsed: bar.update(
                        0, "{} - exporting {}s".format(label, elapsed)
                    ),
                )
                results.append((outcome, run, message))
                bar.update(1, label)
        for outcome, run, message in results:
            report(outcome, run, message)
    else:
        for run in runs:
            outcome, message = _download_run(
                tnscon, address, run, file_format, output_dir, overwrite
            )
            report(outcome, run, message)

    print(
        "downloaded {saved}, skipped {skipped}, failed {failed}".format(**counts),
        flush=True,
    )
    return counts


@cli.command()
@add_options(_login_options)
@add_options(_general_options)
@click.option("--list", is_flag=True, help="Get scan list")
@click.option("--list-history", is_flag=True, help="Get scan list with history")
@click.option("--list-folders", is_flag=True, help="Get folder list")
@click.option("--download", is_flag=True, help="Download scan results")
@click.option(
    "--folder",
    multiple=True,
    help="folder id or name to limit --list, --list-history and --download to, can be repeated",
)
@click.option(
    "--limit",
    "max_age",
    metavar="DURATION",
    callback=_parse_duration,
    help="limit --list-history and --download to runs started in the last DURATION: "
    "number with unit d (days), h (hours), m (minutes) or s (seconds), "
    "units can be combined, e.g. 7d, 12h, 30m, 1d6h",
)
@click.option(
    "--scan-id",
    type=int,
    multiple=True,
    help="scan id to download, can be repeated; without --limit its latest completed run is downloaded",
)
@click.option(
    "--history-id",
    type=int,
    help="exact scan run (history id) to download, requires one --scan-id",
)
@click.option(
    "--runs",
    "which_runs",
    type=click.Choice(["all", "latest"]),
    help="which history runs of each scan to list or download: all or only the newest "
    "(newest completed if any)  [default: all, for --download with --scan-id alone: latest]",
)
@click.option(
    "--output-dir",
    default=".",
    type=click.Path(file_okay=False),
    help="directory for downloaded files",
    show_default=True,
)
@click.option(
    "--file-format",
    default="nessus",
    type=click.Choice(["nessus", "csv"]),
    help="downloaded file format",
    show_default=True,
)
@click.option(
    "--overwrite", is_flag=True, help="download again files that already exist"
)
@click.option(
    "--no-progress",
    is_flag=True,
    help="print one line per scan instead of progress bar (default when output is not a terminal)",
)
@click.option(
    "--compare",
    nargs=2,
    metavar="SCAN_ID:HISTORY_ID SCAN_ID:HISTORY_ID",
    callback=_parse_scan_runs,
    help="compare findings per host of two scan runs, e.g. 12:13 12:14",
)
@click.option(
    "--diff",
    is_flag=True,
    help="with --compare show only new, fixed and changed findings",
)
def scan(
    address,
    port,
    username,
    password,
    insecure,
    ca_cert,
    format,
    filter,
    list,
    list_history,
    list_folders,
    download,
    folder,
    max_age,
    scan_id,
    history_id,
    which_runs,
    output_dir,
    file_format,
    overwrite,
    no_progress,
    compare,
    diff,
    verbose,
):
    """get Nessus scan details info"""

    if download and not scan_id and max_age is None:
        raise click.UsageError("--download needs --limit or --scan-id")
    if history_id is not None and len(scan_id) != 1:
        raise click.UsageError("--history-id needs exactly one --scan-id")
    if history_id is not None and which_runs:
        raise click.UsageError("--runs can't be used together with --history-id")

    show_progress = not no_progress and sys.stdout.isatty()
    any_failed = False

    for one_address in address:
        one_password = password_check(one_address, username, password, verbose)

        tnscon = TnsApi(one_address, port, insecure, ca_cert)
        tnscon.login(username, one_password)

        folder_ids = _resolve_folders(tnscon, folder) if folder else None

        if list_folders:
            _print_address(one_address)
            folders_on_nessus = tnscon.folders_get()
            if not folders_on_nessus:
                print("No items!")
            else:
                for folder_on_nessus in folders_on_nessus:
                    # Nessus omits unread_count for folders without unread scans
                    folder_on_nessus["unread_count"] = int(
                        folder_on_nessus.get("unread_count") or 0
                    )
                default_filter = (
                    "[].{id: id, name: name, type: type, unread_count: unread_count}"
                )
                expression = jmespath.compile(filter or default_filter)
                _print_data(expression.search(folders_on_nessus), format)

        if list:
            _print_address(one_address)
            scans_on_nessus = _get_scans(tnscon, folder_ids)
            if not scans_on_nessus:
                print("No items!")
                sys.exit(1)

            for scan_on_nessus in scans_on_nessus:
                for date_key in ("creation_date", "last_modification_date"):
                    if date_key in scan_on_nessus:
                        scan_on_nessus[date_key] = (
                            _ts(scan_on_nessus[date_key])
                            if scan_on_nessus[date_key]
                            else ""
                        )

            default_filter = (
                "[].{"
                "folder_id: folder_id, "
                "name: name, "
                "owner: owner, "
                "id: id, "
                "creation_date: creation_date, "
                "last_modification_date: last_modification_date, "
                "status: status}"
            )

            expression = jmespath.compile(filter or default_filter)
            _print_data(expression.search(scans_on_nessus), format)

        if list_history:
            _print_address(one_address)
            runs = _collect_runs(tnscon, folder_ids, max_age=max_age)
            runs = _select_runs(runs, (), None, max_age, which_runs)
            if not runs:
                print("No items!")
            else:
                for run in runs:
                    for date_key in ("creation_date", "last_modification_date"):
                        # scans which never ran have 0 or no dates
                        run[date_key] = _ts(run[date_key]) if run.get(date_key) else ""

                default_filter = (
                    "[].{"
                    "folder_id: folder_id, "
                    "folder_name: folder_name, "
                    "name: name, "
                    "owner: owner, "
                    "id: id, "
                    "history_id: history_id, "
                    "creation_date: creation_date, "
                    "last_modification_date: last_modification_date, "
                    "status: status}"
                )

                expression = jmespath.compile(filter or default_filter)
                _print_data(expression.search(runs), format)

        if download:
            _print_address(one_address)
            runs = _collect_runs(tnscon, folder_ids, scan_id, max_age)
            runs = _select_runs(runs, scan_id, history_id, max_age, which_runs)
            if not runs:
                print("Nothing to download!")
            else:
                counts = _download_runs(
                    tnscon,
                    one_address,
                    runs,
                    file_format,
                    output_dir,
                    overwrite,
                    show_progress,
                )
                any_failed = any_failed or counts["failed"] > 0

        if compare:
            _print_address(one_address)
            runs_to_compare = compare
            if runs_to_compare[0] == runs_to_compare[1]:
                raise click.BadParameter(
                    "give two different scan runs", param_hint="--compare"
                )

            compared_runs = [
                (run_scan_id, run_history_id)
                + _scan_run_findings(tnscon, run_scan_id, run_history_id)
                for run_scan_id, run_history_id in runs_to_compare
            ]
            # older run first, so "new" and "fixed" are meaningful
            compared_runs.sort(key=lambda run: int(run[2].get("scan_start") or 0))

            labels = []
            for run_scan_id, run_history_id, run_info, run_findings in compared_runs:
                label = "{}:{}".format(run_scan_id, run_history_id)
                labels.append(label)
                print(_scan_run_summary(label, run_info, run_findings))
            print()

            comparison = _compare_scan_runs(labels, [run[3] for run in compared_runs])
            counts = collections.Counter(row["result"] for row in comparison)
            if diff:
                comparison = [row for row in comparison if row["result"] != "same"]
            if filter:
                comparison = jmespath.search(filter, comparison)

            if comparison:
                _print_data(comparison, format)
            else:
                print("No differences!")

            if format == "table":
                print(
                    "\n{} findings compared: {} same, {} new, {} fixed, {} severity changed".format(
                        sum(counts.values()),
                        counts["same"],
                        counts["new"],
                        counts["fixed"],
                        counts["severity changed"],
                    )
                )

    if any_failed:
        sys.exit(1)


def _plugin_details_flat(details):
    """Merge plugin attributes into one dict, repeated attributes become lists."""
    flat = {
        "id": details["id"],
        "name": details["name"],
        "family_name": details["family_name"],
        "url": "https://www.tenable.com/plugins/nessus/{}".format(details["id"]),
    }
    for attribute in details.get("attributes") or []:
        name = attribute["attribute_name"]
        value = attribute["attribute_value"]
        if name not in flat:
            flat[name] = value
        elif isinstance(flat[name], list):
            flat[name].append(value)
        else:
            flat[name] = [flat[name], value]
    return flat


def _plugin_value_text(value):
    return ", ".join(value) if isinstance(value, list) else value


def _lookup_progress(message):
    """Show slow lookups on terminal only, so piped output stays clean."""
    if sys.stderr.isatty():
        click.echo("\r\033[K" + message, err=True, nl=False)


def _plugin_dependency_info(tnscon, plugin_id, cache):
    """Return id, name, file name and dependency file names of plugin, cached by id."""
    if plugin_id not in cache["plugins"]:
        flat = _plugin_details_flat(tnscon.plugin_details_get(plugin_id))
        dependency = flat.get("dependency") or []
        if not isinstance(dependency, list):
            dependency = [dependency]
        cache["plugins"][plugin_id] = {
            "id": flat["id"],
            "name": flat["name"],
            "fname": flat.get("fname", ""),
            "dependency": [
                name.strip()
                for value in dependency
                for name in value.split(",")
                if name.strip()
            ],
        }
    return cache["plugins"][plugin_id]


def _plugin_ids_by_file(tnscon, fname, cache, trail=()):
    """
    Plugin ids with given file name, cached as each lookup takes seconds.
    :param trail: file names of plugins above in the tree, shown in progress
    """
    if fname not in cache["files"]:
        _lookup_progress(
            "looking up plugin file {}".format(" > ".join(trail + (fname,)))
        )
        found, _ = tnscon.plugins_search("fname", fname)
        cache["files"][fname] = [p["id"] for p in found]
    return cache["files"][fname]


def _dependency_row(relation, level, plugin, note=""):
    return {
        "relation": relation,
        "level": level,
        "id": plugin["id"],
        "name": plugin["name"],
        "fname": plugin["fname"],
        "note": note,
    }


def _too_many_row(relation, level, count):
    """Row with number of plugins not listed because of --max-plugins."""
    note = "{} {} more, increase --max-plugins INTEGER".format(relation, count)
    return _dependency_row(relation, level, {"id": "", "name": "", "fname": ""}, note)


def _add_child_rows(rows, parent_row, child_rows):
    """Add child rows under parent, or only their number as note of parent."""
    only_row = child_rows[0] if len(child_rows) == 1 else None
    if only_row and only_row["id"] == only_row["name"] == only_row["fname"] == "":
        parent_row["note"] = only_row["note"]
    else:
        rows.extend(child_rows)


def _depends_on_rows(
    tnscon, plugin, cache, max_depth, max_count, level=1, shown=None, trail=()
):
    """Plugins on which given plugin depends, up to max_depth levels (0 = all), depth first."""
    shown = {plugin["id"]} if shown is None else shown
    if max_count and len(plugin["dependency"]) > max_count:
        return [_too_many_row("depends on", level, len(plugin["dependency"]))]
    rows = []
    for fname in plugin["dependency"]:
        plugin_ids = _plugin_ids_by_file(tnscon, fname, cache, trail)
        if not plugin_ids:
            rows.append(
                _dependency_row(
                    "depends on",
                    level,
                    {"id": "", "name": "", "fname": fname},
                    "plugin not found",
                )
            )
        for plugin_id in plugin_ids:
            dependency = _plugin_dependency_info(tnscon, plugin_id, cache)
            if plugin_id in shown:
                note = "dependencies listed above" if dependency["dependency"] else ""
                rows.append(_dependency_row("depends on", level, dependency, note))
                continue
            shown.add(plugin_id)
            if max_depth and level >= max_depth and dependency["dependency"]:
                note = "depends on {} more, increase --depth INTEGER".format(
                    len(dependency["dependency"])
                )
                rows.append(_dependency_row("depends on", level, dependency, note))
                continue
            row = _dependency_row("depends on", level, dependency)
            rows.append(row)
            if not max_depth or level < max_depth:
                _add_child_rows(
                    rows,
                    row,
                    _depends_on_rows(
                        tnscon,
                        dependency,
                        cache,
                        max_depth,
                        max_count,
                        level + 1,
                        shown,
                        trail + (fname,),
                    ),
                )
    return rows


def _required_by_rows(
    tnscon, plugin, cache, max_depth, max_count, level=1, shown=None, trail=()
):
    """Plugins which depend on given plugin, up to max_depth levels (0 = all)."""
    shown = {plugin["id"]} if shown is None else shown
    if not plugin["fname"]:
        return []
    trail = trail + (plugin["fname"],)
    _lookup_progress("looking up plugins which depend on {}".format(" > ".join(trail)))
    found, count = tnscon.plugins_search(
        "dependency", plugin["fname"], max_count=max_count or None
    )
    if max_count and count > max_count:
        return [_too_many_row("required by", level, count)]
    rows = []
    for found_plugin in sorted(found, key=lambda p: p["id"]):
        dependent = _plugin_dependency_info(tnscon, found_plugin["id"], cache)
        if dependent["id"] in shown:
            rows.append(
                _dependency_row("required by", level, dependent, "listed above")
            )
            continue
        shown.add(dependent["id"])
        if max_depth and level >= max_depth and dependent["fname"]:
            # count only, so the last level doesn't look like it has no dependents
            _lookup_progress(
                "counting plugins which depend on {}".format(
                    " > ".join(trail + (dependent["fname"],))
                )
            )
            _, dependents_count = tnscon.plugins_search(
                "dependency", dependent["fname"], max_count=0
            )
            note = (
                "required by {} more, increase --depth INTEGER".format(dependents_count)
                if dependents_count
                else ""
            )
            rows.append(_dependency_row("required by", level, dependent, note))
            continue
        row = _dependency_row("required by", level, dependent)
        rows.append(row)
        if not max_depth or level < max_depth:
            _add_child_rows(
                rows,
                row,
                _required_by_rows(
                    tnscon,
                    dependent,
                    cache,
                    max_depth,
                    max_count,
                    level + 1,
                    shown,
                    trail,
                ),
            )
    return rows


def _duration_text(seconds):
    """Duration as 1h 2m 3s, 2m 3s or 3.4s."""
    if round(seconds, 1) < 60:
        return "{:.1f}s".format(seconds)
    minutes, secs = divmod(int(round(seconds)), 60)
    hours, minutes = divmod(minutes, 60)
    return (
        "{}h {}m {}s".format(hours, minutes, secs)
        if hours
        else "{}m {}s".format(minutes, secs)
    )


def _dependency_tree_text(root_text, relation, rows):
    """
    Dependency rows (depth first, with level) drawn as a tree, like file structure.
    """
    only_row = rows[0] if len(rows) == 1 else None
    if only_row and only_row["id"] == only_row["name"] == only_row["fname"] == "":
        # plugins not listed, only their number
        return "{} - {}".format(root_text, only_row["note"])
    lines = ["{} {}".format(root_text, relation)]
    if not rows:
        lines.append("└── no plugins")
    for index, row in enumerate(rows):
        prefix = ""
        for level in range(1, row["level"] + 1):
            # is there another plugin on this level below, under the same parent
            more = False
            for later in rows[index + 1 :]:
                if later["level"] < level:
                    break
                if later["level"] == level:
                    more = True
                    break
            if level < row["level"]:
                prefix += "│   " if more else "    "
            else:
                prefix += "├── " if more else "└── "
        text = " ".join(
            "[{}]".format(value)
            for value in (row["id"], row["name"], row["fname"])
            if value != ""
        )
        if row["note"]:
            text += " - {}".format(row["note"])
        lines.append(prefix + text)
    return "\n".join(lines)


@cli.command()
@add_options(_login_options)
@add_options(_general_options)
@click.option("--family-list", is_flag=True, help="Get plugins families list")
@click.option(
    "--plugin-id",
    type=int,
    multiple=True,
    help="get details of given plugin, can be repeated",
)
@click.option(
    "--plugin-file",
    multiple=True,
    help="get details of plugin with given file name, e.g. scan_info.nasl, "
    "comma separated list (as in dependency) allowed, can be repeated",
)
@click.option(
    "--depends-on",
    is_flag=True,
    help="with --plugin-id or --plugin-file show tree of plugins on which given plugin "
    "depends, only direct dependencies unless --depth is given",
)
@click.option(
    "--required-by",
    is_flag=True,
    help="with --plugin-id or --plugin-file show tree of plugins which depend on given "
    "plugin, only direct dependents unless --depth is given",
)
@click.option(
    "--depth",
    type=click.IntRange(min=0),
    metavar="INTEGER",
    default=1,
    # value is optional, --depth alone means default
    is_flag=False,
    flag_value=1,
    show_default=True,
    help="with --depends-on and --required-by how many levels of plugins to show, "
    "1 for direct dependencies or dependents only, 0 for all levels",
)
@click.option(
    "--max-plugins",
    type=click.IntRange(min=0),
    metavar="INTEGER",
    default=100,
    is_flag=False,
    flag_value=100,
    show_default=True,
    help="with --depends-on and --required-by list plugins of one level only if there "
    "are at most this many, otherwise show their number, 0 for no limit",
)
def plugin(
    address,
    port,
    username,
    password,
    insecure,
    ca_cert,
    format,
    filter,
    family_list,
    plugin_id,
    plugin_file,
    depends_on,
    required_by,
    depth,
    max_plugins,
    verbose,
):
    """get Nessus plugin info"""

    if (depends_on or required_by) and not (plugin_id or plugin_file):
        raise click.UsageError(
            "--depends-on and --required-by need --plugin-id or --plugin-file"
        )

    # dependency attribute lists file names as "a.nasl, b.nbin"
    plugin_files = [
        name.strip()
        for value in plugin_file
        for name in value.split(",")
        if name.strip()
    ]

    for one_address in address:
        one_password = password_check(one_address, username, password, verbose)

        tnscon = TnsApi(one_address, port, insecure, ca_cert)
        tnscon.login(username, one_password)

        if family_list:
            _print_address(one_address)
            plugins_families_on_nessus = tnscon.plugins_families_get()

            default_filter = "[].{" "id: id, " "name: name, " "count: count}"

            if filter:
                expression = jmespath.compile(filter)
            else:
                expression = jmespath.compile(default_filter)

            plugins_families_on_nessus = expression.search(plugins_families_on_nessus)

            if format == "table":
                print(dataframe_table(plugins_families_on_nessus))
            elif format == "csv":
                print(
                    dataframe_table(plugins_families_on_nessus).to_csv(index=False),
                    "\n",
                )
            else:
                print(plugins_families_on_nessus)

        if plugin_id or plugin_files:
            _print_address(one_address)
            plugin_ids = list(plugin_id)
            for one_plugin_file in plugin_files:
                found, _ = tnscon.plugins_search("fname", one_plugin_file)
                if not found:
                    raise click.BadParameter(
                        "plugin file {} not found.".format(one_plugin_file),
                        param_hint="--plugin-file",
                    )
                plugin_ids.extend(p["id"] for p in found if p["id"] not in plugin_ids)

            plugins_details = []
            for one_plugin_id in plugin_ids:
                details = tnscon.plugin_details_get(one_plugin_id)
                if not details:
                    raise click.BadParameter(
                        "plugin id {} not found.".format(one_plugin_id),
                        param_hint="--plugin-id",
                    )
                plugins_details.append(_plugin_details_flat(details))

            if depends_on or required_by:
                cache = {"plugins": {}, "files": {}}
                started = time.monotonic()
                trees = []
                for one_plugin_id in plugin_ids:
                    root = _plugin_dependency_info(tnscon, one_plugin_id, cache)
                    trees.append(
                        (
                            root,
                            (
                                _depends_on_rows(
                                    tnscon, root, cache, depth, max_plugins
                                )
                                if depends_on
                                else None
                            ),
                            (
                                _required_by_rows(
                                    tnscon, root, cache, depth, max_plugins
                                )
                                if required_by
                                else None
                            ),
                        )
                    )
                _lookup_progress("")
                elapsed = time.monotonic() - started
                verified = len(cache["plugins"])

                rows = []
                for root, depends_on_rows, required_by_rows in trees:
                    rows.append(_dependency_row("plugin", 0, root))
                    rows.extend(depends_on_rows or [])
                    rows.extend(required_by_rows or [])

                if filter:
                    _print_data(jmespath.search(filter, rows), format)
                elif format == "table":
                    for root, depends_on_rows, required_by_rows in trees:
                        root_text = "[{}] [{}] [{}]".format(
                            root["id"], root["name"], root["fname"]
                        )
                        for relation, tree_rows in (
                            ("depends on", depends_on_rows),
                            ("is required by", required_by_rows),
                        ):
                            if tree_rows is not None:
                                print(
                                    _dependency_tree_text(
                                        root_text, relation, tree_rows
                                    ),
                                    "\n",
                                )
                    print(
                        "verified {} plugin{} in {}, {} per plugin".format(
                            verified,
                            "" if verified == 1 else "s",
                            _duration_text(elapsed),
                            _duration_text(elapsed / verified),
                        )
                    )
                else:
                    _print_data(rows, format)
            elif filter:
                _print_data(jmespath.search(filter, plugins_details), format)
            elif format == "table":
                for plugin_details in plugins_details:
                    print(
                        tabulate(
                            [
                                [key, _plugin_value_text(value)]
                                for key, value in plugin_details.items()
                            ],
                            headers=["attribute", "value"],
                            maxcolwidths=[None, 120],
                            disable_numparse=True,
                        ),
                        "\n",
                    )
            elif format == "csv":
                _print_data(
                    [
                        {key: _plugin_value_text(value) for key, value in p.items()}
                        for p in plugins_details
                    ],
                    format,
                )
            else:
                print(plugins_details)

        if not (family_list or plugin_id or plugin_files):
            print("No option given!")

        tnscon.logout()


def _parse_settings(ctx, param, values):
    """Turn NAME=VALUE option values into (name, value) pairs."""
    parsed = []
    for value in values:
        name, separator, setting_value = value.partition("=")
        if not separator or not name.strip():
            raise click.BadParameter("use NAME=VALUE, got '{}'".format(value))
        parsed.append((name.strip(), setting_value))
    return parsed


def _settings_changes(current_settings, edits, adds, deletes):
    """Build API changes and a summary to show before applying them."""
    settings_by_name = {s["name"]: s for s in current_settings}
    changes = []
    summary = []

    for name in deletes:
        if name not in settings_by_name:
            raise click.BadParameter(
                "setting '{}' not found. Use --list to see available settings.".format(
                    name
                ),
                param_hint="--delete",
            )
        changes.append(
            {"action": "remove", "id": settings_by_name[name]["id"], "name": name}
        )
        summary.append(
            {
                "action": "delete / reset to default",
                "name": name,
                "current_value": settings_by_name[name]["value"],
                "new_value": "",
            }
        )

    for name, value in edits:
        if name not in settings_by_name:
            raise click.BadParameter(
                "setting '{}' not found. Use --add to create a custom setting "
                "or to set a built-in setting which was reset to default.".format(name),
                param_hint="--edit",
            )
        changes.append(
            {
                "action": "edit",
                "id": settings_by_name[name]["id"],
                "name": name,
                "value": value,
            }
        )
        summary.append(
            {
                "action": "edit",
                "name": name,
                "current_value": settings_by_name[name]["value"],
                "new_value": value,
            }
        )

    for name, value in adds:
        if name in settings_by_name:
            raise click.BadParameter(
                "setting '{}' already exists. Use --edit to change it.".format(name),
                param_hint="--add",
            )
        changes.append({"action": "add", "name": name, "value": value})
        summary.append(
            {"action": "add", "name": name, "current_value": "", "new_value": value}
        )

    return changes, summary


def _apply_settings_changes(tnscon, changes):
    """Apply edits and deletes in one request, then each add on its own."""
    batch = [change for change in changes if change["action"] != "add"]
    if batch:
        tnscon.settings_advanced_modify(batch)

    for change in changes:
        if change["action"] != "add":
            continue
        try:
            tnscon.settings_advanced_modify([change])
        except TnsApiError as e:
            if e.status_code != 400 or "already exists" not in str(e):
                raise
            # A built-in setting reset to default is hidden from the list, but Nessus
            # still knows it and refuses to add it. Its id is the md5 of its name.
            tnscon.settings_advanced_modify(
                [
                    {
                        "action": "edit",
                        "id": hashlib.md5(change["name"].encode()).hexdigest(),
                        "name": change["name"],
                        "value": change["value"],
                    }
                ]
            )


@cli.command()
@add_options(_login_options)
@add_options(_general_options)
@click.option("--list", is_flag=True, help="Get settings list")
@click.option(
    "--get",
    multiple=True,
    metavar="NAME",
    help="get value of selected advanced setting, can be repeated",
)
@click.option(
    "--edit",
    multiple=True,
    metavar="NAME=VALUE",
    callback=_parse_settings,
    help="change value of existing advanced setting, can be repeated",
)
@click.option(
    "--add",
    multiple=True,
    metavar="NAME=VALUE",
    callback=_parse_settings,
    help="add new custom advanced setting, can be repeated",
)
@click.option(
    "--delete",
    multiple=True,
    metavar="NAME",
    help="delete custom advanced setting or reset built-in one to its default value, can be repeated",
)
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    help="apply --edit / --add / --delete without confirmation",
)
def settings(
    address,
    port,
    username,
    password,
    insecure,
    ca_cert,
    format,
    filter,
    list,
    get,
    edit,
    add,
    delete,
    yes,
    verbose,
):
    """get and change Nessus advanced settings"""

    for one_address in address:
        one_password = password_check(one_address, username, password, verbose)

        tnscon = TnsApi(one_address, port, insecure, ca_cert)
        tnscon.login(username, one_password)

        if list:
            _print_address(one_address)
            advanced_settings_on_nessus = tnscon.settings_advanced_get()

            default_filter = "[].{" "id: id, " "name: name, " "value: value}"

            if filter:
                expression = jmespath.compile(filter)
            else:
                expression = jmespath.compile(default_filter)

            advanced_settings_on_nessus = expression.search(advanced_settings_on_nessus)

            if format == "table":
                print(dataframe_table(advanced_settings_on_nessus))
            elif format == "csv":
                print(
                    dataframe_table(advanced_settings_on_nessus).to_csv(index=False),
                    "\n",
                )
            else:
                print(advanced_settings_on_nessus)

        if get:
            _print_address(one_address)
            settings_by_name = {s["name"]: s for s in tnscon.settings_advanced_get()}
            missing_names = [name for name in get if name not in settings_by_name]
            if missing_names:
                raise click.BadParameter(
                    "setting {} not found. Use --list to see available settings.".format(
                        ", ".join("'{}'".format(name) for name in missing_names)
                    ),
                    param_hint="--get",
                )
            selected_settings = [
                {"name": name, "value": settings_by_name[name]["value"]} for name in get
            ]
            if filter:
                selected_settings = jmespath.search(filter, selected_settings)
            _print_data(selected_settings, format)

        if edit or add or delete:
            _print_address(one_address)
            current_settings = tnscon.settings_advanced_get()
            changes, summary = _settings_changes(current_settings, edit, add, delete)
            _print_data(summary, format)

            if yes or click.confirm(
                "\nDo you want to apply {} change(s) listed above?".format(len(changes))
            ):
                _apply_settings_changes(tnscon, changes)
                values_by_name = {
                    s["name"]: s["value"] for s in tnscon.settings_advanced_get()
                }
                result = [
                    {
                        "name": change["name"],
                        "value": values_by_name.get(
                            change["name"], "(removed / default)"
                        ),
                    }
                    for change in changes
                ]
                print("Applied {} change(s). Current values:".format(len(changes)))
                _print_data(result, format)
            else:
                print("Nothing will be changed")

        if not (list or get or edit or add or delete):
            print("No option given!")

        tnscon.logout()


def main():

    try:
        cli()
    except TnsApiError as e:
        print("Error: {}".format(e), file=sys.stderr)
        sys.exit(1)
    except jmespath.exceptions.JMESPathError as e:
        # valid syntax, but filter doesn't fit the data, e.g. contains() on a number
        print("Error: invalid --filter: {}\n{}".format(e, FILTER_HINT), file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
