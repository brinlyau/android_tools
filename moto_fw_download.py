#!/usr/bin/env python3
"""
Motorola Firmware Downloader
Replicates the LMSA (Software Fix) firmware lookup and download flow.
Queries Lenovo's servers with device parameters to find and download
the correct stock firmware for a connected Motorola device.

Authentication: Requires a Lenovo ID account. The script will open a
browser for you to log in, then uses the resulting token for API access.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import uuid
import webbrowser
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import requests

BASE_URL = "https://lsa.lenovo.com/Interface"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36"
)
CLIENT_VERSION = "7.4.3.4"
TOKEN_CACHE_FILE = os.path.join(
    os.path.expanduser("~"), ".cache", "moto_fw_download", "auth.json"
)


class LMSAClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json",
            "Cache-Control": "no-store,no-cache",
            "Pragma": "no-cache",
            "Request-Tag": "lmsa",
            "Connection": "Close",
        })
        self.guid = str(uuid.uuid4())
        self.jwt_token = None
        self._last_match_content = "unset"  # sentinel to distinguish None response

    def _wrap_request(self, dparams):
        return {
            "client": {"version": CLIENT_VERSION},
            "dparams": dparams,
            "language": "en",
            "windowsInfo": "Windows 10, 64bit",
        }

    def _post(self, endpoint, dparams, retries=3, add_auth=True):
        url = BASE_URL + endpoint
        body = self._wrap_request(dparams)
        headers = {"guid": self.guid}
        if add_auth and self.jwt_token:
            headers["Authorization"] = f"Bearer {self.jwt_token}"

        for attempt in range(retries):
            try:
                resp = self.session.post(url, json=body, headers=headers, timeout=30)
                # Capture JWT from response header before checking status
                auth = resp.headers.get("Authorization")
                resp_guid = resp.headers.get("Guid")
                if resp_guid == self.guid and auth:
                    self.jwt_token = auth
                if resp.status_code == 403:
                    print(f"  403 Forbidden - auth token may be expired")
                    return None
                if resp.status_code >= 400:
                    print(f"  HTTP {resp.status_code} for {endpoint}")
                    return None
                data = resp.json()
                return data
            except requests.exceptions.ConnectionError as e:
                print(f"  Connection error (attempt {attempt+1}/{retries}): {e}")
                if attempt == retries - 1:
                    return None
            except Exception as e:
                print(f"  Request failed (attempt {attempt+1}/{retries}): {e}")
                if attempt == retries - 1:
                    return None
        return None

    def get_login_url(self):
        """Fetch the dynamic Lenovo ID login URL from the server."""
        print("[*] Fetching login URL...")
        resp = self._post(
            "/dictionary/getApiInfo.jhtml",
            {"key": "TIP_URL"},
            add_auth=False,
        )
        if resp and resp.get("code") == "0000" and resp.get("content"):
            content = resp["content"]
            if isinstance(content, str):
                content = json.loads(content)
            login_url = content.get("login_url")
            token_url = content.get("token_url")
            if login_url:
                login_url += "&lenovoid.lang=en_US"
                return login_url, token_url
        print(f"[-] Failed to get login URL: {resp}")
        return None, None

    def lenovo_id_login(self, wust):
        """Exchange a WUST token for a JWT via the Lenovo ID login callback."""
        print("[*] Exchanging WUST token for JWT...")
        resp = self._post(
            "/user/lenovoIdLogin.jhtml",
            {"wust": wust, "guid": self.guid},
            add_auth=False,  # This call creates the auth, doesn't send it
        )
        if self.jwt_token:
            print("[+] JWT token acquired successfully")
            return True
        if resp and resp.get("code") == "0000":
            print("[+] Login response OK but no JWT in headers")
            return True
        print(f"[-] Login failed: {resp}")
        return False

    def login_interactive(self):
        """Interactive Lenovo ID login via browser."""
        login_url, _ = self.get_login_url()
        if not login_url:
            # Fallback to known URL format
            login_url = (
                "https://passport.lenovo.com/glbwebauthnv6/preLogin"
                "?lenovoid.action=uilogin"
                "&lenovoid.realm=lmsaclient"
                "&lenovoid.cb=https://lsa.lenovo.com/Tips/lenovoIdSuccess.html"
                "&lenovoid.lang=en_US"
            )

        print("\n" + "=" * 60)
        print("LENOVO ID LOGIN")
        print("=" * 60)
        print("1. A browser will open the Lenovo login page.")
        print("2. Log in with your Lenovo ID.")
        print("3. After login, you'll be redirected to a page that")
        print("   may say 'success' or show an error (either is fine).")
        print("4. Copy the FULL URL from your browser's address bar")
        print("   and paste it below.")
        print("=" * 60)
        print()

        webbrowser.open(login_url)

        while True:
            url_or_token = input("Paste the redirect URL (or just the WUST token): ").strip()
            if not url_or_token:
                continue

            # Extract WUST from full URL
            wust = None
            if "lenovoid.wust=" in url_or_token:
                m = re.search(r"lenovoid\.wust=(.*?)(?=&lenovoid\.|&|$)", url_or_token)
                if m:
                    wust = m.group(1)
            elif url_or_token.startswith("http"):
                # Try query string parsing
                parsed = urlparse(url_or_token)
                qs = parse_qs(parsed.query)
                if "lenovoid.wust" in qs:
                    wust = qs["lenovoid.wust"][0]
            else:
                # Assume it's the raw WUST token
                wust = url_or_token

            if not wust:
                print("[-] Could not extract WUST token from input. Try again.")
                continue

            print(f"[*] WUST token: {wust[:20]}...")
            return self.lenovo_id_login(wust)

    def login(self, wust=None, token=None):
        """Authenticate with the server.

        Args:
            wust: WUST token from Lenovo ID login redirect
            token: Previously saved JWT token
        """
        # Use a previously saved JWT directly
        if token:
            self.jwt_token = token
            print("[*] Using saved JWT token, verifying...")
            # Test with a lightweight API call that requires auth
            try:
                resp = self._post(
                    "/rescueDevice/getRomMatchParams.jhtml",
                    {"modelName": "XT1771"},
                )
            except Exception:
                resp = None
            if resp and resp.get("code") == "0000":
                print("[+] Saved token is valid")
                return True
            else:
                print("[-] Saved token expired or invalid")
                self.jwt_token = None

        # Use provided WUST token
        if wust:
            return self.lenovo_id_login(wust)

        # Interactive browser login
        return self.login_interactive()

    def save_token(self):
        """Save JWT token to cache file for reuse."""
        if not self.jwt_token:
            return
        os.makedirs(os.path.dirname(TOKEN_CACHE_FILE), exist_ok=True)
        data = {"jwt": self.jwt_token, "guid": self.guid}
        with open(TOKEN_CACHE_FILE, "w") as f:
            json.dump(data, f)
        print(f"[*] Token saved to {TOKEN_CACHE_FILE}")

    @staticmethod
    def load_token():
        """Load cached JWT token if available."""
        if not os.path.exists(TOKEN_CACHE_FILE):
            return None, None
        try:
            with open(TOKEN_CACHE_FILE) as f:
                data = json.load(f)
            return data.get("jwt"), data.get("guid")
        except (json.JSONDecodeError, IOError):
            return None, None

    def search_models(self, query):
        """Search available models by name or model number."""
        print(f"[*] Fetching model list...")
        resp = self._post(
            "/rescueDevice/getModelNames.jhtml",
            {"country": "", "category": "phone"},
        )
        if not resp or resp.get("code") != "0000" or not resp.get("content"):
            print(f"[-] Failed to get model list")
            return []
        content = resp["content"]
        if isinstance(content, str):
            content = json.loads(content)
        models = content.get("models", [])
        q = query.lower()
        matches = [
            m for m in models
            if q in m.get("modelName", "").lower()
            or q in m.get("marketName", "").lower()
        ]
        return matches

    def get_match_params(self, model_name):
        print(f"[*] Getting match parameters for model: {model_name}")
        resp = self._post(
            "/rescueDevice/getRomMatchParams.jhtml",
            {"modelName": model_name},
        )
        if resp and resp.get("code") == "0000":
            content = resp.get("content")
            self._last_match_content = content
            if content:
                if isinstance(content, str):
                    content = json.loads(content)
                params = content.get("params", [])
                if params:
                    print(f"[+] Server requires parameters: {params}")
                    return params
            return None
        print(f"[-] Match params response: {resp}")
        return None

    def get_firmware(self, match_params):
        print("[*] Querying server for matching firmware...")
        resp = self._post(
            "/rescueDevice/getNewResource.jhtml",
            match_params,
        )
        if not resp:
            return None

        code = resp.get("code")
        content = resp.get("content")

        if code == "0000" and content:
            if isinstance(content, str):
                content = json.loads(content)
            if isinstance(content, list) and len(content) > 0:
                return content
            return [content] if isinstance(content, dict) else None
        elif code == "3010":
            print("[-] No matching firmware found for this device configuration")
        elif code == "3030":
            print("[-] Partial match - manual selection may be required")
            if content:
                return content if isinstance(content, list) else [content]
        elif code == "3040":
            print("[!] Device already on latest firmware")
            if content:
                return content if isinstance(content, list) else [content]
        else:
            print(f"[-] Server returned code: {code}, desc: {resp.get('desc')}")

        return None

    def get_firmware_by_imei(self, imei):
        print(f"[*] Looking up firmware by IMEI: {imei}")
        resp = self._post(
            "/rescueDevice/getNewResourceByImei.jhtml",
            {"imei": imei},
        )
        if resp and resp.get("code") == "0000" and resp.get("content"):
            content = resp["content"]
            if isinstance(content, str):
                content = json.loads(content)
            return content if isinstance(content, list) else [content]
        print(f"[-] IMEI lookup response code: {resp.get('code') if resp else 'None'}")
        return None

    def get_firmware_by_sn(self, sn):
        print(f"[*] Looking up firmware by SN: {sn}")
        resp = self._post(
            "/rescueDevice/getNewResourceBySN.jhtml",
            {"sn": sn},
        )
        if resp and resp.get("code") == "0000" and resp.get("content"):
            content = resp["content"]
            if isinstance(content, str):
                content = json.loads(content)
            return content if isinstance(content, list) else [content]
        print(f"[-] SN lookup response code: {resp.get('code') if resp else 'None'}")
        return None

    def get_warranty_info(self, imei_or_sn):
        """Look up warranty/sales country info via Lenovo's proxy APIs.

        Tries two sources:
        1. WARRANTY_URL (Lenovo Support API) - returns warranty dates + countries
        2. POI_V1_URL (SDE/iBase) - returns warranty dates + countryName
        """
        if not imei_or_sn:
            return None

        # Try Support API first
        print(f"[*] Looking up warranty info...")
        resp = self._post(
            "/dictionary/getApiInfo.jhtml",
            {"key": "WARRANTY_URL", "param": imei_or_sn},
        )
        if resp and resp.get("code") == "0000" and resp.get("content"):
            content = resp["content"]
            if isinstance(content, str):
                try:
                    content = json.loads(content)
                except (json.JSONDecodeError, TypeError):
                    content = None
            if content and isinstance(content, dict):
                result = {}
                # Parse Support API response
                warranties = content.get("Warranties", [])
                if warranties:
                    # Take the latest warranty by end date
                    latest = sorted(warranties, key=lambda w: w.get("End", ""), reverse=True)[0]
                    result["warranty_start"] = latest.get("Start", "")
                    result["warranty_end"] = latest.get("End", "")
                countries = content.get("Countries", [])
                if countries:
                    result["ship_country"] = ", ".join(
                        c.get("Name", "") for c in countries if c.get("Name")
                    )
                result["serial"] = content.get("Serial", "")
                if result.get("ship_country") or result.get("warranty_start"):
                    return result

        # Fallback: SDE/POI API
        prefix = "IMEI" if len(imei_or_sn) > 10 else ""
        resp = self._post(
            "/dictionary/getApiInfo.jhtml",
            {"key": "POI_V1_URL", "param": prefix + imei_or_sn},
        )
        if resp and resp.get("code") == "0000" and resp.get("content"):
            content = resp["content"]
            if isinstance(content, str):
                try:
                    content = json.loads(content)
                except (json.JSONDecodeError, TypeError):
                    content = None
            if content and isinstance(content, dict):
                svc = None
                svc_list = content.get("serviceInfoList", [])
                if svc_list:
                    svc = svc_list[0]
                result = {}
                if svc:
                    result["ship_country"] = svc.get("countryName", "")
                    result["warranty_start"] = svc.get("warrantyStartDate", "")
                    result["warranty_end"] = svc.get("warrantyEndDate", "")
                machine = content.get("machineInfo", {})
                if machine:
                    result["product_name"] = machine.get("productName", "")
                    result["serial"] = machine.get("serialNumber", "")
                if result.get("ship_country") or result.get("warranty_start"):
                    return result

        return None


def run_cmd(cmd, timeout=10):
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def detect_device_adb():
    """Read device properties via ADB."""
    print("[*] Detecting device via ADB...")
    devices = run_cmd(["adb", "devices"])
    if not devices or "device" not in devices.split("\n", 1)[-1]:
        return None

    def getprop(prop):
        val = run_cmd(["adb", "shell", "getprop", prop])
        return val if val else None

    model = getprop("ro.boot.hardware.sku") or getprop("ro.product.model")
    if not model:
        return None

    fingerprint = getprop("ro.build.fingerprint")
    carrier = getprop("ro.carrier")
    blur_ver = getprop("ro.build.version.full")
    sw_ver = getprop("ro.build.display.id")
    sn = getprop("ro.serialno") or run_cmd(["adb", "get-serialno"])

    # IMEI - try multiple methods
    imei = getprop("persist.radio.imei") or getprop("ro.boot.imei")
    if not imei:
        # Try service call - works on most Android versions including 16
        raw = run_cmd([
            "adb", "shell", "service", "call", "iphonesubinfo", "1",
            "s16", "com.android.shell",
        ], timeout=5)
        if raw:
            # Parse Parcel response: extract chars between quotes
            # Example: Result: Parcel(
            #   0x00000000: 00000000 0000000f 00350035 00340035 '........ 55.54.'
            #   0x00000010: 00330037 00350034 00370033 00320035 '73.45.37.52.'
            #   0x00000020: 00310037 00000000                   '71..    ')
            parts = re.findall(r"'(.*?)'", raw)
            if parts:
                digits = "".join(parts).replace(".", "").replace(" ", "")
                if len(digits) >= 14 and digits.isdigit():
                    imei = digits
    if not imei:
        # Fallback: dumpsys (may require root or debug build)
        dumpsys = run_cmd(
            ["adb", "shell", "dumpsys", "iphonesubinfo"], timeout=5
        )
        if dumpsys:
            for line in dumpsys.splitlines():
                m = re.search(r"Device ID\s*=\s*(\d{14,15})", line)
                if m:
                    imei = m.group(1)
                    break
    sim_config = getprop("persist.radio.multisim.config")
    hw_code = getprop("ro.boot.hwcode") or ""
    android_ver = getprop("ro.build.version.release") or ""

    # FSG version - try multiple properties (order matches FlashBusiness.cs)
    fsg = getprop("ril.baseband.config.version")
    if not fsg:
        fsg = getprop("gsm.version.baseband")
        if fsg:
            parts = fsg.split()
            if len(parts) == 2:
                fsg = parts[1]
            else:
                # Android 15+ may need vendor property instead
                try:
                    av = int(android_ver) if android_ver else 0
                except ValueError:
                    av = 0
                if av >= 15:
                    fsg = getprop("vendor.ril.baseband.config.version") or fsg
    if not fsg:
        fsg = getprop("vendor.ril.baseband.config.version")

    # Determine SIM count
    if sim_config and sim_config.lower() not in ("ss", "ssss", ""):
        sim_count = "Dual"
    else:
        sim_count = "Single"

    ram = getprop("ro.vendor.hw.ram") or getprop("ro.boot.ram") or ""
    country = getprop("ro.boot.country") or ""

    info = {
        "modelName": model,
        "fingerPrint": fingerprint or "",
        "roCarrier": carrier or "",
        "blurVersion": blur_ver or "",
        "softwareVersion": sw_ver or "",
        "fsgVersion": fsg or "",
        "simCount": sim_count,
        "hwCode": hw_code,
        "memory": ram,
        "country": country,
        "imei": imei or "",
        "sn": sn or "",
        "brand": "Motorola",
        "category": "phone",
        "connect_type": "adb",
        "android_version": android_ver,
    }
    return info


def detect_device_fastboot():
    """Read device properties via fastboot.

    Replicates LMSA's ReadPropertiesInFastboot class:
    1. Runs 'fastboot getvar all' to read all properties at once
    2. Runs 'fastboot oem hw dualsim' for SIM config
    3. Converts composite values (fingerprint -> softwareVersion + androidVer,
       version-baseband cleanup, ram/emmc size extraction)
    """
    print("[*] Detecting device via fastboot...")
    devices = run_cmd(["fastboot", "devices"])
    if not devices:
        return None

    # --- Step 1: 'fastboot getvar all' (matches ReadAll()) ---
    props = {}
    try:
        result = subprocess.run(
            ["fastboot", "getvar", "all"],
            capture_output=True, text=True, timeout=15,
        )
        # fastboot outputs variable listing to stderr
        output = result.stderr + "\n" + result.stdout
        # Parse "(bootloader) key: value" or "key: value" lines
        for line in output.splitlines():
            # LMSA regex: (?<bootloader>\(bootloader\)\s+)(?<key>.+):\s+(?<value>.*)
            m = re.match(r"(?:\(bootloader\)\s+)?(.+?):\s+(.*)", line)
            if m:
                key = m.group(1).strip()
                val = m.group(2).strip()
                if key and key not in props and key not in ("Finished", "FAILED", "OKAY", "completed"):
                    props[key] = val
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None

    if not props:
        return None

    # Helper: get property, handling split values like "ro.build.fingerprint[0]", "[1]", etc.
    def convert(element):
        if element in props:
            return props[element]
        # Reassemble split values: key[0], key[1], ...
        val = ""
        i = 0
        while f"{element}[{i}]" in props:
            val += props[f"{element}[{i}]"]
            i += 1
        return val.strip() if val else ""

    # --- Step 2: ConvertFingerPrint() ---
    # Extracts softwareVersion and androidVer from fingerprint
    fingerprint = convert("ro.build.fingerprint")
    android_ver = ""
    sw_ver = ""
    if fingerprint:
        fp_parts = fingerprint.split("/")
        # softwareVersion = 4th segment (e.g. "W1UXS36H.72-45-10-2")
        if len(fp_parts) > 3:
            sw_ver = fp_parts[3].strip()
            props["softwareVersion"] = sw_ver
        # androidVer = from 3rd segment after ':' (e.g. "arcfox:16" -> "16")
        if len(fp_parts) > 2:
            av_parts = fp_parts[2].split(":")
            if len(av_parts) > 1:
                android_ver = av_parts[1].strip()
                props["androidVer"] = android_ver

    # --- Step 3: ConvertFsgVersion() ---
    fsg = convert("version-baseband")
    if fsg and "not found" in fsg.lower():
        fsg = ""
    elif fsg:
        parts = fsg.split(" ")
        if len(parts) == 1:
            fsg = parts[0].strip()
        elif len(parts) > 1:
            fsg = parts[1].strip()
    props["version-baseband"] = fsg

    # --- Step 4: ConvertBlurVersion() ---
    blur_ver = convert("ro.build.version.full")

    # --- Step 5: ConvertFlashSize() ---
    emmc = convert("emmc")
    if emmc:
        props["emmc"] = emmc.split(" ")[0]

    # --- Step 6: ConvertRamSize() ---
    ram = convert("ram")
    if ram:
        ram = ram.split(" ")[0]
        props["ram"] = ram

    # --- Step 7: ReadSimConfig() via 'fastboot oem hw dualsim' ---
    sim_count = "Single"
    try:
        result = subprocess.run(
            ["fastboot", "oem", "hw", "dualsim"],
            capture_output=True, text=True, timeout=20,
        )
        sim_output = result.stderr + "\n" + result.stdout
        for line in sim_output.splitlines():
            if "dualsim" in line:
                parts = line.split(":")
                if len(parts) > 1 and parts[1].strip().lower() == "true":
                    sim_count = "Dual"
                    break
        else:
            # Fallback: check 'dualsim' property from getvar all
            ds = props.get("dualsim", "")
            if ds.lower() == "true":
                sim_count = "Dual"
    except (subprocess.TimeoutExpired, FileNotFoundError):
        ds = props.get("dualsim", "")
        if ds.lower() == "true":
            sim_count = "Dual"

    # --- Build device info (matches ConvertFastbootDeviceInfo) ---
    model = props.get("sku") or props.get("ro.boot.hardware.sku") or ""
    if not model:
        return None

    info = {
        "modelName": model,
        "fingerPrint": fingerprint,
        "roCarrier": props.get("ro.carrier", ""),
        "blurVersion": blur_ver,
        "softwareVersion": sw_ver or props.get("softwareVersion", ""),
        "fsgVersion": fsg,
        "simCount": sim_count,
        "hwCode": "",
        "memory": ram,
        "country": "",
        "imei": props.get("imei", ""),
        "sn": props.get("serialno", ""),
        "brand": "Motorola",
        "category": "phone",
        "connect_type": "fastboot",
        "android_version": android_ver,
        # Extra fastboot-only fields
        "fdr_allowed": props.get("fdr-allowed", ""),
        "securestate": props.get("securestate", ""),
        "cid": props.get("cid", ""),
        "channelId": props.get("channelid", ""),
        "trackId": props.get("trackId", ""),
        "erase_personal_data": props.get("erase_personal_data", ""),
    }
    return info


def build_match_request(device_info, required_params):
    """Build the request payload matching LMSA's GetAutoMatchParams format."""
    params = {}
    for p in required_params:
        if p == "modelName":
            params[p] = device_info.get("modelName", "-1")
        elif p == "fingerPrint":
            params[p] = device_info.get("fingerPrint", "-1")
        elif p == "roCarrier":
            params[p] = device_info.get("roCarrier", "-1")
        elif p == "blurVersion":
            # Skip blurVersion for Android >= 10
            android_ver = device_info.get("android_version", "")
            try:
                if int(android_ver) >= 10:
                    continue
            except (ValueError, TypeError):
                pass
            params[p] = device_info.get("blurVersion", "-1")
        elif p in ("fsgVersion.qcom", "fsgVersion.mtk", "fsgVersion.samsung"):
            params[p] = device_info.get("fsgVersion", "-1")
        elif p == "simCount":
            val = device_info.get("simCount", "")
            params[p] = val if val else "Lack"
        elif p == "softwareVersion":
            params[p] = device_info.get("softwareVersion", "-1")
        elif p == "hwCode":
            params[p] = device_info.get("hwCode", "-1")
        elif p == "memory":
            params[p] = device_info.get("memory", "-1")
        elif p == "country":
            params[p] = device_info.get("country", "-1")
        else:
            params[p] = "-1"

        if not params.get(p):
            params[p] = "Lack" if p == "simCount" else "-1"

    params["category"] = device_info.get("category", "phone")

    request = {
        "modelName": device_info["modelName"],
        "params": params,
        "imei": device_info.get("imei", ""),
        "imei2": device_info.get("imei2", ""),
        "sn": device_info.get("sn", ""),
        "matchType": 0 if device_info.get("connect_type") == "fastboot" else 1,
    }

    channel_id = device_info.get("channelId")
    if channel_id:
        request["channelId"] = channel_id

    return request


def _android_ver_from_fingerprint(fp):
    """Extract Android version from a build fingerprint string."""
    if not fp:
        return None
    parts = fp.split("/")
    if len(parts) > 2:
        av = parts[2].split(":")
        if len(av) > 1:
            return av[1].strip()
    return None


def print_firmware_info(fw):
    """Display firmware details."""
    print("\n" + "=" * 60)
    print("FIRMWARE FOUND")
    print("=" * 60)
    print(f"  Model:        {fw.get('modelName', 'N/A')}")
    print(f"  Real Model:   {fw.get('realModelName', 'N/A')}")
    print(f"  Market Name:  {fw.get('marketName', 'N/A')}")
    print(f"  Sales Model:  {fw.get('saleModel', 'N/A')}")
    print(f"  Platform:     {fw.get('platform', 'N/A')}")
    android_ver = _android_ver_from_fingerprint(fw.get("fingerprint"))
    if android_ver:
        print(f"  Android:      {android_ver}")
    print(f"  Fastboot:     {fw.get('fastboot', 'N/A')}")
    latest = fw.get("latest", "N/A")
    print(f"  Latest:       {latest}")
    if fw.get("latestDesc"):
        print(f"  Latest Desc:  {fw['latestDesc']}")
    print(f"  Fingerprint:  {fw.get('fingerprint', 'N/A')}")
    if fw.get("comments"):
        print(f"  Comments:     {fw['comments']}")

    rom = fw.get("romResource")
    if rom:
        print(f"\n  ROM File:     {rom.get('name', 'N/A')}")
        print(f"  ROM URL:      {rom.get('uri', 'N/A')}")
        print(f"  ROM MD5:      {rom.get('md5', 'N/A')}")
        print(f"  ROM Type:     {rom.get('type', 'N/A')}")
        print(f"  Unzip:        {rom.get('unZip', 'N/A')}")
        if rom.get("description"):
            print(f"  ROM Desc:     {rom['description']}")

    tool = fw.get("toolResource")
    if tool:
        print(f"\n  Tool:         {tool.get('name', 'N/A')}")
        print(f"  Tool URL:     {tool.get('uri', 'N/A')}")
        if tool.get("md5"):
            print(f"  Tool MD5:     {tool['md5']}")

    cc = fw.get("countryCodeResource")
    if cc and cc.get("uri"):
        print(f"\n  Country Code: {cc.get('name', 'N/A')}")
        print(f"  CC URL:       {cc['uri']}")
        if cc.get("md5"):
            print(f"  CC MD5:       {cc['md5']}")

    recipe = fw.get("flashFlow")
    if recipe:
        print(f"\n  Recipe URL:   {recipe}")

    print("=" * 60)


def pick_firmware(results):
    """Let user pick from multiple firmware results."""
    print(f"\n[*] {len(results)} firmware options available.\n")
    print(f"  {'#':<4} {'Model':<12} {'Android':<9} {'Latest':<7} {'Fingerprint / ROM'}")
    print(f"  {'-'*3} {'-'*11} {'-'*8} {'-'*6} {'-'*40}")
    for i, fw in enumerate(results):
        rom = fw.get("romResource") or {}
        av = _android_ver_from_fingerprint(fw.get("fingerprint")) or "?"
        latest = "Yes" if fw.get("latest") else "No"
        fp = fw.get("fingerprint", "N/A")
        # Shorten fingerprint for display
        fp_short = fp.split("/")[-1] if "/" in fp else fp
        print(
            f"  [{i}] {fw.get('modelName', '?'):<12} "
            f"{av:<9} {latest:<7} "
            f"{fp_short}  ({rom.get('name', 'N/A')})"
        )
    print()
    try:
        choice = int(input("Select firmware [0]: ") or "0")
    except (ValueError, EOFError):
        choice = 0
    return results[min(choice, len(results) - 1)]


def download_firmware(fw, output_dir, download_recipe=False):
    """Download all resources for a firmware entry."""
    out_dir = os.path.join(output_dir, fw.get("modelName", "unknown"))
    print(f"\n[*] Download directory: {os.path.abspath(out_dir)}")

    rom = fw.get("romResource")
    if rom and rom.get("uri"):
        download_file(rom["uri"], out_dir, rom.get("md5"))

    cc = fw.get("countryCodeResource")
    if cc and cc.get("uri"):
        download_file(cc["uri"], out_dir, cc.get("md5"))

    if download_recipe and fw.get("flashFlow"):
        download_file(fw["flashFlow"], out_dir)

    print("\n[+] Done!")


def md5_check(filepath, expected_md5):
    """Verify file MD5."""
    h = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest().lower() == expected_md5.lower()


def download_file(url, dest_dir, expected_md5=None):
    """Download a file with progress display and optional MD5 check."""
    filename = urlparse(url).path.split("/")[-1]
    if "?" in filename:
        filename = filename.split("?")[0]
    filepath = os.path.join(dest_dir, filename)
    tmp_path = filepath + ".tmp"

    # Check if already downloaded
    if os.path.exists(filepath):
        if expected_md5 and md5_check(filepath, expected_md5):
            print(f"[+] Already downloaded and verified: {filename}")
            return filepath
        elif not expected_md5:
            print(f"[+] Already downloaded: {filename}")
            return filepath

    os.makedirs(dest_dir, exist_ok=True)

    # Resume support
    downloaded = 0
    if os.path.exists(tmp_path):
        downloaded = os.path.getsize(tmp_path)

    headers = {"User-Agent": USER_AGENT}
    if downloaded > 0:
        headers["Range"] = f"bytes={downloaded}-"
        print(f"[*] Resuming download of {filename} from {downloaded} bytes...")
    else:
        print(f"[*] Downloading {filename}...")

    resp = requests.get(url, headers=headers, stream=True, timeout=30)

    total = int(resp.headers.get("content-length", 0)) + downloaded
    mode = "ab" if downloaded > 0 else "wb"

    with open(tmp_path, mode) as f:
        current = downloaded
        for chunk in resp.iter_content(chunk_size=65536):
            if chunk:
                f.write(chunk)
                current += len(chunk)
                if total > 0:
                    pct = current / total * 100
                    bar = "#" * int(pct // 2) + "-" * (50 - int(pct // 2))
                    size_mb = current / 1024 / 1024
                    total_mb = total / 1024 / 1024
                    print(
                        f"\r  [{bar}] {pct:.1f}% ({size_mb:.1f}/{total_mb:.1f} MB)",
                        end="",
                        flush=True,
                    )

    print()

    # MD5 check
    if expected_md5:
        print(f"[*] Verifying MD5: {expected_md5}")
        if md5_check(tmp_path, expected_md5):
            print("[+] MD5 verified OK")
        else:
            print("[-] MD5 MISMATCH - file may be corrupt")
            os.remove(tmp_path)
            return None

    os.rename(tmp_path, filepath)
    print(f"[+] Saved: {filepath}")
    return filepath


def main():
    parser = argparse.ArgumentParser(
        description="Download Motorola stock firmware via Lenovo's LMSA servers"
    )
    parser.add_argument(
        "--model", "-m",
        help="Device model name / SKU (e.g. 'berlin', 'raven'). "
             "Auto-detected from USB device if not provided.",
    )
    parser.add_argument(
        "--imei",
        help="Look up firmware by IMEI instead of device properties",
    )
    parser.add_argument(
        "--sn",
        help="Look up firmware by serial number",
    )
    parser.add_argument(
        "--carrier", help="Override carrier (ro.carrier value)",
    )
    parser.add_argument(
        "--output", "-o", default="download",
        help="Output directory for downloaded firmware (default: ./download)",
    )
    parser.add_argument(
        "--info-only", "-i", action="store_true",
        help="Only show firmware info, don't download",
    )
    parser.add_argument(
        "--download-recipe", action="store_true",
        help="Also download the flash recipe XML",
    )
    parser.add_argument(
        "--json", "-j", action="store_true",
        help="Output firmware info as JSON",
    )
    parser.add_argument(
        "--wust",
        help="WUST token from Lenovo ID login (skips browser login)",
    )
    parser.add_argument(
        "--token",
        help="JWT token for direct authentication (skips login entirely)",
    )
    parser.add_argument(
        "--no-cache", action="store_true",
        help="Don't use cached auth token",
    )
    parser.add_argument(
        "--login-only", action="store_true",
        help="Only perform login and cache the token, then exit",
    )
    parser.add_argument(
        "--search", "-s",
        help="Search available models by name (e.g. 'razr 50', 'edge 60', 'XT2451')",
    )
    parser.add_argument(
        "--warranty", "-w", action="store_true",
        help="Look up warranty and sales country info (requires IMEI or SN)",
    )

    args = parser.parse_args()

    client = LMSAClient()

    # Try to load cached token first
    cached_jwt, cached_guid = None, None
    if not args.no_cache and not args.wust and not args.token:
        cached_jwt, cached_guid = LMSAClient.load_token()
        if cached_jwt:
            if cached_guid:
                client.guid = cached_guid
            print("[*] Found cached auth token")

    # Authenticate
    token_to_use = args.token or cached_jwt
    if not client.login(wust=args.wust, token=token_to_use):
        print("[-] Authentication failed. Cannot access firmware endpoints.")
        sys.exit(1)

    # Save token for future use
    client.save_token()

    if args.login_only:
        print("[+] Login successful, token cached.")
        sys.exit(0)

    # Search models
    if args.search:
        matches = client.search_models(args.search)
        if not matches:
            print(f"[-] No models matching '{args.search}'")
            sys.exit(1)
        print(f"\n[+] Found {len(matches)} model(s) matching '{args.search}':\n")
        print(f"  {'#':<4} {'Model':<16} {'Market Name':<40} {'Platform':<8} {'Brand'}")
        print(f"  {'-'*3} {'-'*15} {'-'*39} {'-'*7} {'-'*10}")
        for i, m in enumerate(matches):
            print(
                f"  [{i}] {m.get('modelName', '?'):<16} "
                f"{m.get('marketName', '?'):<40} "
                f"{m.get('platform', '?'):<8} "
                f"{m.get('brand', '?')}"
            )
        if args.info_only:
            sys.exit(0)
        print()
        try:
            choice = input("Select a model to look up firmware (number, or Enter to quit): ").strip()
        except (EOFError, KeyboardInterrupt):
            sys.exit(0)
        if not choice:
            sys.exit(0)
        try:
            idx = int(choice)
        except ValueError:
            print("[-] Invalid selection")
            sys.exit(1)
        if idx < 0 or idx >= len(matches):
            print("[-] Out of range")
            sys.exit(1)
        selected = matches[idx]
        model_name = selected["modelName"]
        print(f"\n[*] Selected: {model_name} ({selected.get('marketName', '')})")

        # Try IMEI first (most reliable)
        results = None
        if args.imei:
            print("[*] Looking up firmware by IMEI...")
            results = client.get_firmware_by_imei(args.imei)

        # Try auto-match for the selected model
        if not results:
            required_params = client.get_match_params(model_name)
            if required_params:
                missing = []
                match = {}
                for p in required_params:
                    if p == "simCount":
                        match[p] = "Dual"
                    elif p == "roCarrier":
                        if args.carrier:
                            match[p] = args.carrier
                        else:
                            missing.append(p)
                    elif p == "fingerPrint":
                        missing.append(p)
                    else:
                        missing.append(p)
                if missing:
                    print(f"[!] Server requires: {', '.join(required_params)}")
                    print(f"    Missing values for: {', '.join(missing)}")
                    for p in missing:
                        val = input(f"    Enter {p} (or press Enter to skip): ").strip()
                        match[p] = val if val else "-1"
                match["category"] = selected.get("category", "phone").lower()
                req = {
                    "modelName": model_name,
                    "params": match,
                    "imei": args.imei or "", "imei2": "", "sn": args.sn or "",
                    "matchType": 1,
                }
                results = client.get_firmware(req)

        # Last resort: ask for IMEI interactively
        if not results:
            print("[-] Auto-match failed (server requires real device fingerprint)")
            print("[*] IMEI lookup is the most reliable method.")
            print("    Find your IMEI: dial *#06# or check Settings > About Phone")
            try:
                imei_input = input("    Enter IMEI (or press Enter to quit): ").strip()
            except (EOFError, KeyboardInterrupt):
                sys.exit(0)
            if not imei_input:
                sys.exit(0)
            results = client.get_firmware_by_imei(imei_input)

        if not results:
            print("[-] No firmware found")
            sys.exit(1)

        print(f"\n[+] Found {len(results)} firmware(s):\n")
        for fw in results:
            print_firmware_info(fw)
        if args.json:
            print(json.dumps(results, indent=2))
        fw = results[0] if len(results) == 1 else pick_firmware(results)
        download_firmware(fw, args.output, args.download_recipe)
        sys.exit(0)

    # IMEI/SN direct lookup (no device detection needed)
    if args.imei and not args.model:
        results = client.get_firmware_by_imei(args.imei)
        if not results:
            print("[-] No firmware found for that IMEI")
            sys.exit(1)
        print(f"\n[+] Found {len(results)} firmware(s) for IMEI {args.imei}:\n")
        for i, fw in enumerate(results):
            print_firmware_info(fw)
        if args.json:
            print(json.dumps(results, indent=2))
        if args.info_only:
            sys.exit(0)
        fw = results[0] if len(results) == 1 else pick_firmware(results)
        download_firmware(fw, args.output, args.download_recipe)
        sys.exit(0)

    if args.sn and not args.model:
        results = client.get_firmware_by_sn(args.sn)
        if not results:
            print("[-] No firmware found for that serial number")
            sys.exit(1)
        print(f"\n[+] Found {len(results)} firmware(s) for SN {args.sn}:\n")
        for i, fw in enumerate(results):
            print_firmware_info(fw)
        if args.json:
            print(json.dumps(results, indent=2))
        if args.info_only:
            sys.exit(0)
        fw = results[0] if len(results) == 1 else pick_firmware(results)
        download_firmware(fw, args.output, args.download_recipe)
        sys.exit(0)

    # Detect device
    device_info = detect_device_fastboot()
    if not device_info:
        device_info = detect_device_adb()

    if not device_info and not args.model:
        print("[-] No device detected and no --model specified")
        sys.exit(1)

    if args.model:
        if not device_info:
            device_info = {
                "modelName": args.model,
                "brand": "Motorola",
                "category": "phone",
                "connect_type": "manual",
            }
        else:
            device_info["modelName"] = args.model

    if args.carrier:
        device_info["roCarrier"] = args.carrier
    if args.imei:
        device_info["imei"] = args.imei

    print(f"\n[+] Device: {device_info['modelName']}")
    print(f"    Connection: {device_info.get('connect_type', 'unknown')}")
    if device_info.get("fingerPrint"):
        print(f"    Fingerprint: {device_info['fingerPrint']}")
    if device_info.get("roCarrier"):
        print(f"    Carrier: {device_info['roCarrier']}")
    if device_info.get("softwareVersion"):
        print(f"    Software: {device_info['softwareVersion']}")
    if device_info.get("imei"):
        print(f"    IMEI: {device_info['imei']}")

    # Warranty / sales country lookup
    if args.warranty:
        lookup_key = device_info.get("imei") or device_info.get("sn")
        if lookup_key:
            warranty = client.get_warranty_info(lookup_key)
            if warranty:
                if warranty.get("ship_country"):
                    print(f"    Country:    {warranty['ship_country']}")
                if warranty.get("warranty_start"):
                    print(f"    Warranty:   {warranty['warranty_start']} to {warranty.get('warranty_end', '?')}")
                if warranty.get("product_name"):
                    print(f"    Product:    {warranty['product_name']}")
                if warranty.get("serial"):
                    print(f"    MSN:        {warranty['serial']}")
            else:
                print("    Warranty:   Not found")
        else:
            print("    Warranty:   Need IMEI or SN to look up")
    print()

    results = None

    # Strategy 1: IMEI-based lookup (preferred - this is what LMSA uses)
    if device_info.get("imei"):
        print("[*] Trying IMEI-based lookup (primary method)...")
        results = client.get_firmware_by_imei(device_info["imei"])

    # Strategy 2: Auto-match via model params
    if not results:
        required_params = client.get_match_params(device_info["modelName"])
        if required_params:
            match_request = build_match_request(device_info, required_params)
            print(f"[*] Match request params: {json.dumps(match_request.get('params', {}), indent=2)}")
            results = client.get_firmware(match_request)
        else:
            content = client._last_match_content
            if content is None:
                print("[-] Server has no match parameters for this model")
                print("    Note: the server uses XT model numbers (e.g. XT2451-3),")
                print("    not codenames (e.g. arcfox). Check ro.boot.hardware.sku")

    # Strategy 3: SN-based lookup
    if not results and device_info.get("sn"):
        print("[*] Trying SN-based lookup...")
        results = client.get_firmware_by_sn(device_info["sn"])

    if not results:
        print("[-] No firmware found for this device")
        sys.exit(1)

    # Show all results
    print(f"\n[+] Found {len(results)} firmware(s):\n")
    for fw in results:
        print_firmware_info(fw)

    if args.json:
        print(json.dumps(results, indent=2))

    if args.info_only:
        sys.exit(0)

    fw = results[0] if len(results) == 1 else pick_firmware(results)
    download_firmware(fw, args.output, args.download_recipe)


if __name__ == "__main__":
    main()
