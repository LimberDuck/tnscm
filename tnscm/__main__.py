from tnscm._version import __version__
from tnscm.modules.tnsapi import TnsApi
import click
import pandas as pd
from tabulate import tabulate
import getpass
import keyring
from keyring.backends import Windows, macOS
import platform
import sys
from oauthlib.oauth2.rfc6749.errors import CustomOAuth2Error
import datetime
import jmespath

os_user = getpass.getuser().lower()

if platform.system() == "Windows":
    keyring.set_keyring(Windows.WinVaultKeyring())
elif platform.system() == "Darwin":
    keyring.set_keyring(macOS.Keyring())


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
    click.option(
        "--password", 
        "-p", 
        help="password which you want to use to login"
    ),
    click.option(
        "--insecure",
        "-k",
        is_flag=True,
        help="perform insecure SSL connections and transfers",
    ),
    click.option(
        "--format",
        "-f",
        default="table",
        help="data format to display [table,json,csv]",
        show_default="table",
    ),
    click.option(
        "--filter",
        "-f",
        help="filter data with JMESPath. See https://jmespath.org/ for more information and examples.",
    ),
]

_general_options = [click.option("-v", "--verbose", count=True)]


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


@click.group()
def cli():
    pass


@cli.command()
@add_options(_login_options)
@add_options(_general_options)
@click.option(
    "--status",
    is_flag=True,
    help="Get server status"
)
@click.option(
    "--ips",
    is_flag=True,
    help="Use to see number of licensed IPs, active IPs and left IPs",
)
@click.option(
    "--version",
    is_flag=True,
    help="Get server version"
)

def server(
    address,
    port,
    username,
    password,
    insecure,
    format,
    filter,
    status,
    ips,
    version,
    verbose,
):
    """get Nessus server info"""

    for one_address in address:
        one_password = password_check(one_address, username, password, verbose)

        try:
            tnscon = TnsApi(one_address, port, insecure)
            tnscon.login(username, one_password)
        except ConnectionError as e:
            print(
                "Can't reach Nessus API via {} Please check your connection.".format(
                    one_address
                )
            )
            sys.exit(1)

        except CustomOAuth2Error as e:
            print(
                "Can't login to Nessus API with supplied credentials. Please make sure they are correct."
            )
            sys.exit(1)

        if status:
            server_status = tnscon.server_status_get()
            print(one_address, server_status)
        if ips:
            server_properties = tnscon.server_properties_get()
            licensed_ips = server_properties["license"]["ips"]
            active_ips = server_properties["used_ip_count"]
            left_ips = int(licensed_ips) - int(active_ips)
            left_ips_percentage = str(
                int(100 - 100 * int(active_ips) / int(licensed_ips))
            )
            print(
                one_address
                + " "
                + "{0:}".format(int(licensed_ips))
                + " - "
                + "{0:}".format(int(active_ips))
                + " = "
                + "{0:}".format(left_ips)
                + " ("
                + left_ips_percentage
                + "%) remaining IPs"
            )

        if version:
            nessus_type = tnscon.server_properties_get()["nessus_type"]
            server_version = tnscon.server_properties_get()["server_version"]
            print(one_address, nessus_type, server_version)

        tnscon.logout()


@cli.command()
@add_options(_login_options)
@add_options(_general_options)
@click.option(
    "--list",
    is_flag=True,
    help="Get user list"
)

def user(address, port, username, password, insecure, format, filter, list, verbose):
    """get Nessus user info"""

    for one_address in address:
        one_password = password_check(one_address, username, password, verbose)

        try:
            tnscon = TnsApi(one_address, port, insecure)
            tnscon.login(username, one_password)
        except ConnectionError as e:
            print(
                "Can't reach Nessus API via {} Please check your connection.".format(
                    one_address
                )
            )
            sys.exit(1)

        except CustomOAuth2Error as e:
            print(
                "Can't login to Nessus API with supplied credentials. Please make sure they are correct."
            )
            sys.exit(1)

        if list:
            print(one_address)
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


@cli.command()
@add_options(_login_options)
@add_options(_general_options)
@click.option(
    "--list",
    is_flag=True,
    help="Get scan policy list"
)
@click.option(
    "--delete",
    is_flag=True,
    help="Delete scan policy"
)

def policy(
    address, port, username, password, insecure, format, filter, list, delete, verbose
):
    """get Nessus policy info"""

    for one_address in address:
        one_password = password_check(one_address, username, password, verbose)

        try:
            tnscon = TnsApi(one_address, port, insecure)
            tnscon.login(username, one_password)
        except ConnectionError as e:
            print(
                "Can't reach Nessus API via {}. Please check your connection.".format(
                    one_address
                )
            )
            sys.exit(1)

        except CustomOAuth2Error as e:
            print(
                "Can't login to Nessus API with supplied credentials. Please make sure they are correct."
            )
            sys.exit(1)

        if list:
            print(one_address)
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
            print(one_address)
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

        tnscon.logout()


@cli.command()
@add_options(_login_options)
@add_options(_general_options)
@click.option(
    "--list", is_flag=True,
    help="Get scan list"
)
@click.option(
    "--delete",
    is_flag=True,
    help="Delete scan with whole history"
)

def scan(
    address, port, username, password, insecure, format, filter, list, delete, verbose
):
    """get Nessus scan details info"""

    for one_address in address:
        one_password = password_check(one_address, username, password, verbose)

        try:
            tnscon = TnsApi(one_address, port, insecure)
            tnscon.login(username, one_password)
        except ConnectionError as e:
            print(
                "Can't reach Nessus API via {}. Please check your connection.".format(
                    one_address
                )
            )
            sys.exit(1)

        except CustomOAuth2Error as e:
            print(
                "Can't login to Nessus API with supplied credentials. Please make sure they are correct."
            )
            sys.exit(1)

        if list:
            print(one_address)
            scans_on_nessus = tnscon.scans_get()
            # print(scans_on_nessus)
            if scans_on_nessus is None:
                print("No items!")
                sys.exit(1)

            for scan_on_nessus in scans_on_nessus:
                if "creation_date" in scan_on_nessus:
                    scan_on_nessus.update(
                        {
                            "creation_date": str(
                                datetime.datetime.fromtimestamp(
                                    int(scan_on_nessus["creation_date"])
                                )
                            )
                        }
                    )
                if "last_modification_date" in scan_on_nessus:
                    scan_on_nessus.update(
                        {
                            "last_modification_date": str(
                                datetime.datetime.fromtimestamp(
                                    int(scan_on_nessus["last_modification_date"])
                                )
                            )
                        }
                    )

            default_filter = (
                "[].{"
                "folder_id: folder_id, "
                "id: id, "
                "name: name, "
                "owner: owner, "
                "creation_date: creation_date, "
                "last_modification_date: last_modification_date, "
                "status: status}"
            )

            if filter:
                expression = jmespath.compile(filter)
            else:
                expression = jmespath.compile(default_filter)

            scans_on_nessus = expression.search(scans_on_nessus)

            if format == "table":
                print(dataframe_table(scans_on_nessus))
            elif format == "csv":
                print(dataframe_table(scans_on_nessus).to_csv(index=False), "\n")
            else:
                print(scans_on_nessus)

        if delete:
            print(one_address)
            scans_on_nessus = tnscon.scans_get()
            print(scans_on_nessus)
            if scans_on_nessus is None:
                print("No items!")
                sys.exit(1)

            for scan_on_nessus in scans_on_nessus:
                if "creation_date" in scan_on_nessus:
                    scan_on_nessus.update(
                        {
                            "creation_date": str(
                                datetime.datetime.fromtimestamp(
                                    int(scan_on_nessus["creation_date"])
                                )
                            )
                        }
                    )
                if "last_modification_date" in scan_on_nessus:
                    scan_on_nessus.update(
                        {
                            "last_modification_date": str(
                                datetime.datetime.fromtimestamp(
                                    int(scan_on_nessus["last_modification_date"])
                                )
                            )
                        }
                    )

            default_filter = (
                "[].{"
                "folder_id: folder_id, "
                "id: id, "
                "name: name, "
                "owner: owner, "
                "creation_date: creation_date, "
                "last_modification_date: last_modification_date, "
                "status: status}"
            )

            if filter:
                expression = jmespath.compile(filter)
            else:
                expression = jmespath.compile(default_filter)

            scans_on_nessus = expression.search(scans_on_nessus)

            if scans_on_nessus is not None:
                if format == "table":
                    print(dataframe_table(scans_on_nessus))
                elif format == "csv":
                    print(dataframe_table(scans_on_nessus).to_csv(index=False), "\n")
                else:
                    print(scans_on_nessus)

                if len(scans_on_nessus) == 1:
                    item_or_items = "scan"
                else:
                    item_or_items = "scans"

                if "id" not in scans_on_nessus[0]:
                    print(
                        "\nYou can't delete SCAN without SCAN ID. Use ID in your filter!"
                    )
                    sys.exit(0)

                if click.confirm(
                    "\nDo you want to delete {} {} listed above with whole history?".format(
                        len(scans_on_nessus), item_or_items
                    )
                ):
                    for scan_on_nessus in scans_on_nessus:
                        scan_on_nessus_id = scan_on_nessus["id"]
                        print("Deleting scan id {}".format(scan_on_nessus_id))
                        tnscon.scan_delete(scan_on_nessus_id)
                else:
                    print("Nothing will be deleted")


@cli.command()
@add_options(_login_options)
@add_options(_general_options)
@click.option(
    "--family-list",
    is_flag=True,
    help="Get plugins families list"
)

def plugin(
    address, port, username, password, insecure, format, filter, family_list, verbose
):
    """get Nessus plugin info"""

    for one_address in address:
        one_password = password_check(one_address, username, password, verbose)

        try:
            tnscon = TnsApi(one_address, port, insecure)
            tnscon.login(username, one_password)
        except ConnectionError as e:
            print(
                "Can't reach Nessus API via {}. Please check your connection.".format(
                    one_address
                )
            )
            sys.exit(1)

        except CustomOAuth2Error as e:
            print(
                "Can't login to Nessus API with supplied credentials. Please make sure they are correct."
            )
            sys.exit(1)

        if family_list:
            print(one_address)
            plugins_families_on_nessus = tnscon.plugins_families_get()

            default_filter = (
                "[].{"
                "id: id, "
                "name: name, "
                "count: count}"
            )

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

        else:
            print("No option given!")

        tnscon.logout()


@cli.command()
@add_options(_login_options)
@add_options(_general_options)
@click.option(
    "--list",
    is_flag=True,
    help="Get settings list"
)

def settings(
    address, port, username, password, insecure, format, filter, list, verbose
):
    """get Nessus settings info"""

    for one_address in address:
        one_password = password_check(one_address, username, password, verbose)

        try:
            tnscon = TnsApi(one_address, port, insecure)
            tnscon.login(username, one_password)
        except ConnectionError as e:
            print(
                "Can't reach Nessus API via {}. Please check your connection.".format(
                    one_address
                )
            )
            sys.exit(1)

        except CustomOAuth2Error as e:
            print(
                "Can't login to Nessus API with supplied credentials. Please make sure they are correct."
            )
            sys.exit(1)

        if list:
            print(one_address)
            advanced_settings_on_nessus = tnscon.settings_advanced_get()

            default_filter = (
                "[].{" 
                "id: id, " 
                "name: name, " 
                "value: value}"
            )

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

        else:
            print("No option given!")

        tnscon.logout()


def main():

    print("tnscm v.{}".format(__version__))
    cli()


if __name__ == "__main__":
    main()
