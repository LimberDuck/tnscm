import requests
import json
import certstore
import urllib3
import sys
import datetime


class TnsApi:

    def __init__(self, host="127.0.0.1", port=443, insecure=None):
        """
        :param host: address to Nessus API `127.0.0.1`
        :param port: port to Nessus API `443`
        :param insecure: if True perform insecure SSL connections and transfers
        """
        self.host = host
        self.port = port
        self.verify = certstore.ca_bundle

        if not insecure:
            self.verify = certstore.ca_bundle
        else:
            self.verify = False
            urllib3.disable_warnings()

        self._token = ""

    def build_url(self, resource):
        url = "{}://{}:{}".format("https", self.host, self.port)
        return "{}{}".format(url, resource)

    def connect(self, method, resource, data=None):

        headers = {
            "X-Cookie": "token={0}".format(self._token),
            "content-type": "application/json",
        }

        data = json.dumps(data)

        if method == "POST":
            r = requests.post(
                self.build_url(resource), data=data, headers=headers, verify=self.verify
            )
        elif method == "PUT":
            r = requests.put(
                self.build_url(resource), data=data, headers=headers, verify=self.verify
            )
        elif method == "DELETE":
            r = requests.delete(
                self.build_url(resource), data=data, headers=headers, verify=self.verify
            )
        else:
            r = requests.get(
                self.build_url(resource), data=data, headers=headers, verify=self.verify
            )

        if r.status_code == 401:
            print("Response code: {}".format(r.status_code))
            print("Unauthorized.")
            sys.exit()
        if r.status_code == 500:
            print("Response code: {}".format(r.status_code))
            print("Internal Server Error.")
            sys.exit()
        if r.status_code == 503:
            print("Response code: {}".format(r.status_code))
            print("Service Unavailable.")
            sys.exit()

        if method == "POST":
            return r.json()
        elif method == "PUT":
            if r is None:
                return None
        elif method == "DELETE":
            return r
        else:
            if "download" in resource:
                return r.content
            else:
                return r.json()

    def login(self, usr, pwd):
        """
        Login to Nessus.
        """

        login = {"username": usr, "password": pwd}
        data = self.connect("POST", "/session", data=login)
        self._token = data["token"]
        return self._token

    def logout(self):
        """
        Logout of Nessus.
        """
        self.connect("DELETE", "/session")

    def session_get(self):
        data = self.connect("GET", "/session")
        return data

    def server_status_get(self):
        data = self.connect("GET", "/server/status")["status"]
        return data

    def server_properties_get(self):
        data = self.connect("GET", "/server/properties")
        return data

    def policies_get(self):
        data = self.connect("GET", "/policies")["policies"]
        return data

    def policies_delete(self, id):
        data = self.connect("DELETE", "/policies/{0}".format(id))
        return data

    def users_get(self):
        data = self.connect("GET", "/users")["users"]
        return data

    def folders_get(self):
        data = self.connect("GET", "/folders")
        return data

    def scans_get(self):
        data = self.connect("GET", "/scans")["scans"]
        return data

    def scan_delete(self, id):
        data = self.connect("DELETE", "/scans/{0}".format(id))
        return data

    def plugins_families_get(self):
        data = self.connect("GET", "/plugins/families")["families"]
        return data

    def settings_advanced_get(self):
        data = self.connect("GET", "/settings/advanced")["preferences"]
        return data
