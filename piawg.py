#!/usr/bin/env python3

# piawg
# Setup Wireguard for PIA
# https://www.privateinternetaccess.com/

import argparse
from string import Template
import subprocess
import time
import os
import sys
import datetime
import json
import base64
from enum import Enum
from typing import Any, Dict, Optional, Union, Tuple
import logging
import ssl
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import HTTPError
from urllib.parse import urlencode
from dataclasses import dataclass

logging.basicConfig(
    format="%(levelname)s:pia:%(name)s:%(message)s",
    level=logging.getLevelName(os.environ.get("LOG_LEVEL", "INFO")),
)

logger = logging.getLogger("piavpn")

GET_TOKEN_URL = "https://www.privateinternetaccess.com/api/client/v2/token"
FULL_SERVER_LIST_URL = "https://serverlist.piaservers.net/vpninfo/servers/v4"
CA_CERT_PATH = Path("ca.rsa.4096.crt")
PORT_PATH = Path("/var/run/pia-forwarded-port")
WG_CONFIG_PATH = Path("/etc/wireguard/pia.conf")
SCRIPT_NAME = os.path.basename(sys.argv[0])


class Color(Enum):
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def colored(message: str, color: Color = Color.OKGREEN) -> str:
    if not sys.stdout.isatty():
        return message
    return color.value + message + Color.ENDC.value


@dataclass
class ApiResponse:
    status: str


@dataclass
class ApiErrorResponse(ApiResponse):
    message: str


@dataclass
class GetSignatureResponse(ApiResponse):
    payload: str
    signature: str


@dataclass
class GetSignaturePayload:
    token: str
    expires_at: datetime.datetime
    port: int


@dataclass
class Server:
    ip: str
    cn: str


class ScriptError(Exception):
    message: str
    exit_code: int
    output = None

    def __init__(self, message: str, exit_code: int = 1, output=None):
        super().__init__(message)
        self.message = message
        self.exit_code = exit_code
        self.output = output


class PiaApi:
    username: str
    password: str
    server: Server
    ca_cert_path: Path
    token_path: Path
    context: ssl.SSLContext
    logger: logging.Logger

    def __init__(
        self,
        username: str,
        password: str,
        server: Server,
        ca_cert_path: Path,
        token_path: Path,
    ):
        self.username = username
        self.password = password
        self.server = server
        self.token_path = token_path
        self.ca_cert_path = ca_cert_path
        self.context = self._get_context()
        self.logger = logging.getLogger("api")
        pass

    def _get_context(self) -> ssl.SSLContext:
        cname = self.server.cn

        class WrapSSLContext(ssl.SSLContext):
            def wrap_socket(self, *args, **kwargs):
                kwargs["server_hostname"] = cname
                return super().wrap_socket(*args, **kwargs)

        context = WrapSSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(self.ca_cert_path)
        return context

    def _fetch(self, port: int, path: str, params: Dict[str, str] = {}):
        query = urlencode(params)
        req = Request(
            url=f"https://{self.server.ip}:{port}/{path}?{query}",
        )
        try:
            with urlopen(req, context=self.context) as f:
                return json.load(f)

        except HTTPError as e:
            raise ScriptError(f"Failed to call API: {e}")

    def _get_token(self) -> str:
        """
        Get a token. Check the cache for an existing, unexpired token before requesting a new one.
        """
        if self.token_path.is_file():
            token, expiry_str = self.token_path.read_text().split("\n")
            expiry = datetime.datetime.fromisoformat(expiry_str)
            # Check if expired (with buffer of 2 minutes)
            if expiry - datetime.timedelta(minutes=2) > datetime.datetime.now():
                self.logger.debug("Retrieved token from cache")
                return token

        req = Request(
            GET_TOKEN_URL,
            data=urlencode(
                {"username": self.username, "password": self.password}
            ).encode(),
        )
        #  For some reason PIA doesn't like the default urllib user agent
        req.add_header("User-Agent", "Python")
        self.logger.info("Fetching new token")
        try:
            with urlopen(req) as f:
                res = json.load(f)
                token = res["token"]
        except HTTPError as e:
            raise ScriptError(message=f"Failed to get token: {e}")

        self.token_path.parent.mkdir(exist_ok=True)
        with open(self.token_path, "w") as f:
            expiry = datetime.datetime.now() + datetime.timedelta(hours=24)
            f.write(f"{res['token']}\n{expiry.isoformat()}")
        return token

    def add_key(self, public_key: str):
        return self._fetch(
            1337, "addKey", {"pt": self._get_token(), "pubkey": public_key}
        )

    def get_port_signature(
        self,
    ) -> Union[Tuple[GetSignatureResponse, GetSignaturePayload], ApiErrorResponse]:
        res = self._fetch(19999, "getSignature", {"token": self._get_token()})
        self.logger.debug(res)
        if res["status"] != "OK":
            return ApiErrorResponse(**res)

        payload = json.loads(base64.b64decode(res["payload"]).decode("utf8"))
        payload["expires_at"] = datetime.datetime.fromisoformat(payload["expires_at"])
        return GetSignatureResponse(**res), GetSignaturePayload(**payload)

    def bind_port(self, payload: str, signature: str):
        return self._fetch(
            19999,
            "bindPort",
            {
                "payload": payload,
                "signature": signature,
            },
        )


def build_wg_config(conf_entries: Dict[str, Dict[str, Any]]) -> str:
    conf = ""
    for section, items in conf_entries.items():
        conf += f"[{section}]\n"
        for k, v in items.items():
            if isinstance(v, list):
                for list_item in v:
                    conf += f"{k} = {list_item}\n"
            else:
                conf += f"{k} = {v}\n"
    return conf


def set_network_namespace(namespace: str):
    import ctypes
    import ctypes.util
    import errno

    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    with (Path("/run/netns") / namespace).open() as f:
        ns_fileno = f.fileno()
        ret = libc.setns(ns_fileno, 0)
        if ret != 0:
            last_err = ctypes.get_errno()
            raise ScriptError(f"Call to setns failed: {errno.errorcode[last_err]}")


def start_wireguard(
    pia_api: PiaApi,
    template: Optional[Template] = None,
    network_namespace: Optional[str] = None,
):
    logger = logging.getLogger("wireguard")
    private_key = subprocess.check_output(["wg", "genkey"]).decode().strip()
    public_key = (
        subprocess.check_output(["wg", "pubkey"], input=(f"{private_key}\n").encode())
        .decode()
        .strip()
    )
    logger.debug(f"Wireguard public key: {public_key}")
    res = pia_api.add_key(public_key)
    logger.debug(f"Add key response: {res}")
    logger.info("Disabling old Wireguard connection ...")
    subprocess.run(["wg-quick", "down", "pia"])

    if template is not None:
        template_args = {
            "peer_ip": res["peer_ip"],
            "private_key": str(private_key),
            "server_key": res["server_key"],
            "server_ip": res["server_ip"],
            "server_port": res["server_port"],
            "endpoint": f"{res['server_ip']}:{res['server_port']}",
        }
        conf = template.substitute(template_args)
        with open(WG_CONFIG_PATH, "w") as f:
            f.write(conf)
    else:
        conf_entries = {}
        conf_entries["Interface"] = {
            "Address": res["peer_ip"],
            "PrivateKey": str(private_key),
        }
        if network_namespace is not None:
            conf_entries["Interface"]["Table"] = "off"
            conf_entries["Interface"]["PostUp"] = [
                f"ip link set pia netns {network_namespace}",
                f"ip -n {network_namespace} link set pia up",
                f"ip -n {network_namespace} addr add {res['peer_ip']}/32 dev pia",
                f"ip -n {network_namespace} route add default dev pia",
            ]
        conf_entries["Peer"] = {
            "PersistentKeepalive": "25",
            "PublicKey": res["server_key"],
            "AllowedIPs": "0.0.0.0/0",
            "Endpoint": f"{res['server_ip']}:{res['server_port']}",
        }
        conf = build_wg_config(conf_entries)

        logger.debug("Writing Wireguard config to /etc/wireguard/pia.conf")

    with open(WG_CONFIG_PATH, "w") as f:
        f.write(conf)

    logger.info("Starting Wireguard")
    result = subprocess.run(["wg-quick", "up", "pia"], check=True, capture_output=True)
    for line in result.stderr.decode().strip().splitlines():
        logger.debug(line)
    print(colored(f"Connected to {res['server_ip']}!", Color.OKGREEN))
    if network_namespace:
        down_cmd = f"ip netns exec {network_namespace} wg-quick down pia"
    else:
        down_cmd = "wg-quick down pia"
    print(colored(f"To disconnect from the VPN, run: {down_cmd}", Color.OKGREEN))


def get_full_server_list(with_port_forwarding=False):
    try:
        with urlopen(FULL_SERVER_LIST_URL) as f:
            server_list = json.loads(f.read().decode().split("\n")[0])
    except HTTPError as e:
        raise ScriptError(f"Failed to fetch server list: {e}")
    if with_port_forwarding:
        server_list["regions"] = [
            r for r in server_list["regions"] if r["port_forward"]
        ]
    return server_list


def do_portforwarding(pia_api: PiaApi, port_path: Path):
    """
    Start port forwarding and renew the port every 15 minutes. Once the port expires
    fetch a new port.
    """
    logger = logging.getLogger("portforwarding")

    def _get_port_signature() -> Tuple[GetSignatureResponse, GetSignaturePayload]:
        """
        Get a lease on a new port
        """
        logger.info("Getting new signature")
        res = pia_api.get_port_signature()
        if isinstance(res, ApiErrorResponse):
            raise ScriptError(f"portforwarding: failed to getSignature: {res.message}")
        signature_res, payload = res
        print(colored(f"Forwarded port {payload.port}"))
        logger.info(f"Writing port to {port_path}")
        with open(port_path, "w") as f:
            f.write(f"{payload.port}")
        logger.info(f"Expires at {payload.expires_at}")
        logger.info(f"Will bind port {payload.port} every 15 minutes")
        return signature_res, payload

    signature_res, payload = _get_port_signature()
    # Rebind our port every 15 minutes.
    running = True
    while running:
        expires_in = payload.expires_at - datetime.datetime.now(
            tz=datetime.timezone.utc
        )
        # if the port expires within the next hour fetch a new port lease
        if expires_in < datetime.timedelta(hours=1):
            logger.info(
                f"Port {payload.port} is expiring in less than 1 hour, acquiring a new one"
            )
            signature_res, payload = _get_port_signature()
        res = pia_api.bind_port(
            payload=signature_res.payload, signature=signature_res.signature
        )
        if res["status"] != "OK":
            raise ScriptError("portforwarding: failed to bindPort")
        else:
            logger.info(f"Refreshed port {payload.port} on {datetime.datetime.now()}")
        try:
            time.sleep(15 * 60)  # wait 15 minutes
        except KeyboardInterrupt:
            PORT_PATH.unlink()
            running = False


def parse_args():
    parser = argparse.ArgumentParser(description="PIA Wireguard client")
    required_args = ["username", "password", "region"]
    parser.add_argument(
        "--username",
        type=str,
        help="Username",
        default=os.environ.get("PIA_USER", None),
    )
    parser.add_argument(
        "--password",
        type=str,
        help="Password",
        default=os.environ.get("PIA_PASS", None),
    )
    parser.add_argument(
        "--region",
        type=str,
        help="PIA region",
        default=os.environ.get("PIA_REGION", None),
    )
    parser.add_argument(
        "--token-path",
        type=Path,
        help="Path to store PIA token",
        default=Path(os.environ.get("PIA_TOKEN_PATH", "/tmp/pia-token")),
    )
    parser.add_argument(
        "--port-path",
        type=Path,
        help="Path to store PIA port",
        default=Path(os.environ.get("PIA_PORT_PATH", PORT_PATH)),
    )
    parser.add_argument(
        "--enable-port-forwarding",
        action="store_true",
        help="Enable port forwarding",
        default=os.environ.get("PIA_ENABLE_PORT_FORWARDING", "0").lower()
        not in {"0", "false"},
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify connection by checking public IP",
        default=os.environ.get("PIA_VERIFY", "0").lower() not in {"0", "false"},
    )
    parser.add_argument(
        "--network-namespace",
        type=str,
        help="Move PIA interface to the provided network namespace. The namespace must"
        " already exist (i.e there is a file handle in /run/netns)",
        default=os.environ.get("PIA_NETWORK_NAMESPACE", None),
    )
    parser.add_argument(
        "--ca-file",
        type=Path,
        help="Certificate authority file for PIA",
        default=os.environ.get("PIA_CA_FILE", CA_CERT_PATH),
    )
    parser.add_argument(
        "--config-template",
        help="Wireguard config template",
        type=Path,
        default=os.environ.get("PIA_CONFIG_TEMPLATE", None),
    )
    args = parser.parse_args()
    missing_args = []
    for arg_name in required_args:
        if getattr(args, arg_name) is None:
            missing_args.append(arg_name)
    if len(missing_args) > 0:
        raise ScriptError(f"Missing required argument(s): {', '.join(missing_args)}")

    if args.config_template is not None:
        if not args.config_template.exists():
            raise ScriptError("--config-template must point to a valid file")
        args.config_template = Template(args.config_template.read_text())
    return args


def main():
    args = parse_args()

    if os.getuid() != 0:
        raise ScriptError(f"This script must be run as root i.e: sudo ./{SCRIPT_NAME}")

    servers = get_full_server_list(with_port_forwarding=args.enable_port_forwarding)
    region = next(
        (region for region in servers["regions"] if region["id"] == args.region), {}
    )
    if not region:
        raise ScriptError(f"Invalid region: {args.region}")
    logger.debug(f"Region: {region}")
    if not region["port_forward"] and args.enable_port_forwarding:
        raise ScriptError("Region does not support port forwarding")

    servers = [Server(**s) for s in region["servers"]["wg"]]
    if len(servers) == 0:
        raise ScriptError(f"Region {args.region} has no wireguard servers")

    pia_api = PiaApi(
        username=args.username,
        password=args.password,
        server=servers[0],
        ca_cert_path=args.ca_file,
        token_path=args.token_path,
    )

    start_wireguard(pia_api, args.config_template, args.network_namespace)

    if args.enable_port_forwarding:
        # If a network namespace was provided set it so forwarding happens inside of
        # that namespace
        if args.network_namespace:
            set_network_namespace(args.network_namespace)
        do_portforwarding(pia_api, port_path=args.port_path)

    else:
        print(colored("portforwarding is disabled. Exiting", Color.OKBLUE))


if __name__ == "__main__":
    try:
        main()
    except ScriptError as e:
        print(colored(e.message, Color.FAIL))
        sys.exit(e.exit_code)
    except subprocess.CalledProcessError as e:
        print(colored(str(e), Color.FAIL))
        if e.stderr:
            print(colored(e.stderr.decode(), Color.FAIL))
        sys.exit(1)
    except Exception:
        import traceback

        print(colored(traceback.format_exc(), Color.FAIL))
