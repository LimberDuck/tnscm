import os
import re
import requests
import certstore
import urllib3
import time


class TnsApiError(Exception):
    """Nessus API returned an error response."""

    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code


class TnsApiConnectionError(TnsApiError):
    """Nessus API can't be reached (network, SSL or timeout problem)."""


class TnsApi:

    # (connect, read) timeouts in seconds
    timeout = (10, 300)
    # Nessus answers 503 while it is starting or loading plugins
    retries_on_503 = 3
    retry_wait_seconds = 5
    download_chunk_size = 1024 * 1024

    def __init__(self, host="127.0.0.1", port=443, insecure=None, ca_cert=None):
        """
        :param host: address to Nessus API `127.0.0.1`
        :param port: port to Nessus API `443`
        :param insecure: if True perform insecure SSL connections and transfers
        :param ca_cert: path to CA certificate (PEM) used to verify the server
        """
        self.host = host
        self.port = port

        if insecure:
            self.verify = False
            urllib3.disable_warnings()
        elif ca_cert:
            self.verify = ca_cert
        else:
            self.verify = certstore.ca_bundle

        self.session = requests.Session()
        self.session.verify = self.verify
        self.session.headers.update({"Accept": "application/json"})

    def build_url(self, resource):
        url = "{}://{}:{}".format("https", self.host, self.port)
        return "{}{}".format(url, resource)

    def _request(
        self, method, resource, data=None, params=None, stream=False, files=None
    ):
        """
        Send request and return response, raise TnsApiError on any failure.
        :param files: multipart files for upload, sent instead of JSON data
        """
        url = self.build_url(resource)

        for attempt in range(self.retries_on_503 + 1):
            try:
                r = self.session.request(
                    method,
                    url,
                    json=None if files else data,
                    params=params,
                    files=files,
                    timeout=self.timeout,
                    stream=stream,
                )
            except requests.exceptions.SSLError as e:
                reason = re.search(r"certificate verify failed: (.*?)\s*\(_ssl", str(e))
                raise TnsApiConnectionError(
                    "SSL certificate of {} can't be verified: {}. "
                    "Use --ca-cert to trust the server CA or -k to skip verification.".format(
                        self.host, reason.group(1).rstrip(".") if reason else e
                    )
                )
            except requests.exceptions.Timeout:
                raise TnsApiConnectionError(
                    "Nessus API via {}:{} did not respond in time.".format(
                        self.host, self.port
                    )
                )
            except requests.exceptions.ConnectionError:
                raise TnsApiConnectionError(
                    "Can't reach Nessus API via {}:{}. Please check your connection.".format(
                        self.host, self.port
                    )
                )

            if r.status_code == 503 and attempt < self.retries_on_503:
                r.close()
                time.sleep(self.retry_wait_seconds)
                continue
            break

        if not r.ok:
            raise TnsApiError(self._error_message(method, resource, r), r.status_code)
        return r

    def _error_message(self, method, resource, r):
        try:
            detail = r.json().get("error")
        except ValueError:
            detail = None
        detail = detail or r.text.strip()[:200] or r.reason

        message = "{} {} on {} returned {}: {}".format(
            method, resource, self.host, r.status_code, detail
        )
        if r.status_code == 401 and resource == "/session":
            message += ". Please make sure your credentials are correct."
        if r.status_code == 412:
            message += ". This action is not available via API in this Nessus edition."
        return message

    def connect(self, method, resource, data=None, params=None):
        """
        Call Nessus API and return decoded JSON response, or None if there is no body.
        """
        r = self._request(method, resource, data=data, params=params)
        if r.content and "json" in r.headers.get("content-type", ""):
            return r.json()
        return None

    def download(self, resource, out_path, params=None):
        """
        Stream file from Nessus API to out_path.
        """
        with self._request("GET", resource, params=params, stream=True) as r:
            with open(out_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=self.download_chunk_size):
                    f.write(chunk)

    def login(self, usr, pwd):
        """
        Login to Nessus.
        """

        login = {"username": usr, "password": pwd}
        data = self.connect("POST", "/session", data=login)
        token = data["token"]
        self.session.headers["X-Cookie"] = "token={0}".format(token)
        return token

    def logout(self):
        """
        Logout of Nessus.
        """
        self.connect("DELETE", "/session")
        self.session.headers.pop("X-Cookie", None)
        self.session.close()

    def session_get(self):
        data = self.connect("GET", "/session")
        return data

    def server_status_get(self):
        data = self.connect("GET", "/server/status")["status"]
        return data

    def server_properties_get(self):
        data = self.connect("GET", "/server/properties")
        return data

    def server_health_alerts_get(self):
        data = self.connect("GET", "/settings/health/alerts")
        return data

    def server_health_stats_get(self):
        data = self.connect("GET", "/settings/health/stats")
        return data

    def policies_get(self):
        data = self.connect("GET", "/policies")["policies"]
        return data

    def policy_details_get(self, id):
        data = self.connect("GET", "/policies/{0}".format(id))
        return data

    def policy_editor_get(self, id):
        data = self.connect("GET", "/editor/policy/{0}".format(id))
        return data

    def policy_export(self, id, out_path):
        self.download("/policies/{0}/export".format(id), out_path)

    def file_upload(self, path):
        """
        Upload file to Nessus and return its name on the server.
        """
        with open(path, "rb") as f:
            # read once, so the same content is sent again when request is retried
            files = {"Filedata": (os.path.basename(path), f.read())}
        r = self._request("POST", "/file/upload", files=files)
        return r.json()["fileuploaded"]

    def policy_import(self, path):
        """
        Import policy from .nessus file and return the new policy.
        """
        uploaded = self.file_upload(path)
        data = self.connect("POST", "/policies/import", data={"file": uploaded})
        return data

    def policies_delete(self, id):
        data = self.connect("DELETE", "/policies/{0}".format(id))
        return data

    def users_get(self):
        data = self.connect("GET", "/users")["users"]
        return data

    def folders_get(self):
        data = self.connect("GET", "/folders")["folders"]
        return data

    def scans_get(self, folder_id=None):
        params = {"folder_id": folder_id} if folder_id is not None else None
        data = self.connect("GET", "/scans", params=params)["scans"]
        return data

    def scans_details_get(self, id, history_id=None):
        params = {"history_id": history_id} if history_id is not None else None
        data = self.connect("GET", "/scans/{0}".format(id), params=params)
        return data

    def scan_host_details_get(self, scan_id, host_id, history_id=None):
        params = {"history_id": history_id} if history_id is not None else None
        data = self.connect(
            "GET", "/scans/{0}/hosts/{1}".format(scan_id, host_id), params=params
        )
        return data

    def scans_history_get(self, id):
        data = self.connect("GET", "/scans/{0}".format(id))["history"]
        return data

    def scan_export_request(self, id, history_id=None, file_format="nessus"):
        data_format = {"format": file_format}
        params = {"history_id": history_id} if history_id is not None else None
        data = self.connect(
            "POST", "/scans/{0}/export".format(id), data=data_format, params=params
        )
        return data

    def scan_export_status(self, scan_id, file_id):
        data = self.connect(
            "GET", "/scans/{0}/export/{1}/status".format(scan_id, file_id)
        )
        return data

    def scan_export_download(self, scan_id, file_id, out_path):
        self.download(
            "/scans/{0}/export/{1}/download".format(scan_id, file_id), out_path
        )

    def plugin_details_get(self, id):
        data = self.connect("GET", "/plugins/plugin/{0}".format(id))
        return data

    def plugin_family_details_get(self, id):
        data = self.connect("GET", "/plugins/families/{0}".format(id))
        return data

    def policy_templates_get(self):
        data = self.connect("GET", "/editor/policy/templates")["templates"]
        return data

    def plugins_search(self, filter_name, value, quality="eq", max_count=None):
        """
        Find plugins with the policy editor plugin filter, e.g. fname eq scan_info.nasl
        or dependency eq scan_info.nasl (plugins which depend on given file).
        Return (list of dicts with keys id, name and family_name, number of plugins found).
        When more than max_count plugins are found, the list is empty.
        """
        if not getattr(self, "_plugins_search_resource", None):
            templates = self.policy_templates_get()
            uuid = next(t["uuid"] for t in templates if t["name"] == "advanced")
            self._plugins_search_resource = (
                "/editor/policy/templates/{0}/families".format(uuid)
            )
        resource = self._plugins_search_resource
        params = {
            "filter.search_type": "and",
            "filter.0.filter": filter_name,
            "filter.0.quality": quality,
            "filter.0.value": value,
        }
        families = self.connect("GET", resource, params=params)["families"] or {}
        count = sum(family["count"] for family in families.values())
        if max_count is not None and count > max_count:
            return [], count
        found = []
        for family_name, family in families.items():
            family_resource = "{0}/{1}".format(resource, family["id"])
            plugins = self.connect("GET", family_resource, params=params)["plugins"]
            for plugin in plugins or []:
                found.append(
                    {
                        "id": plugin["id"],
                        "name": plugin["name"],
                        "family_name": family_name,
                    }
                )
        return found, count

    def plugins_families_get(self):
        data = self.connect("GET", "/plugins/families")["families"]
        return data

    def settings_advanced_get(self):
        data = self.connect("GET", "/settings/advanced")["preferences"]
        return data

    def settings_advanced_modify(self, changes):
        """
        :param changes: list of dicts with keys action (add, edit, remove), name, value and id
        """
        payload = {}
        for index, change in enumerate(changes):
            for key, value in change.items():
                if value is not None:
                    payload["setting.{}.{}".format(index, key)] = value
        data = self.connect("PUT", "/settings/advanced", data=payload)
        return data
