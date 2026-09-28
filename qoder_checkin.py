#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Qoder 每日自动领取「专属活动权益」脚本（单文件版）
==================================================

背景
----
Qoder 客户端（国际版 Qoder / 国内版 Qoder CN）会下发「专属活动权益」活动页，
其中典型活动是 **每天领 100 Credits**（实测活动窗口为每天 10:00→次日 09:59，UTC+8，
即每天北京时间 10:00 刷新）。客户端只负责弹出活动页，点「领取」是活动页里的请求，
本脚本把这步搬到命令行，可无人值守执行。

原理
----
1) 活动接口（逆向自客户端 app.asar 的 campaignMainService 与活动页 activity-iframe.js）：

       GET  {base}/sash/api/v1/me/campaigns?clientType=10
       POST {base}/sash/api/v1/me/campaigns/{campaignId}/claim

   只领 actionType == "CLAIM_BENEFIT" 且 claimStatus == "CLAIMABLE" 的活动；
   claimStatus == "CLAIMED" 表示今天已领，直接跳过（幂等）。

2) 鉴权头与客户端 createAuthorizedHeaders() 一致：

       Authorization: Bearer <token>
       Cosy-ClientType: 10
       Cosy-Version / Cosy-MachineOS / Cosy-MachineId / Cosy-MachineHostname
       Cosy-MachineToken / Cosy-MachineCode / Cosy-MachineType   ← 设备风控身份

   国际版服务端按设备风控身份限领（每台设备每天一次），因此带上风控身份更稳。

3) token 从本机客户端读取（Electron safeStorage，无需扫码 / 无需浏览器）：

       macOS   ~/Library/Application Support/com.qoder[cn].app.stable/auth.v1.dat
               "v10" + AES-128-CBC；密钥 = PBKDF2-SHA1(钥匙串 "<App> Safe Storage" 口令,
               "saltysalt", 1003, 16)，IV = 16 个空格
       Windows %APPDATA%\\com.qoder[cn].app.stable\\auth.v1.dat
               "v10" + AES-256-GCM；密钥 = DPAPI 解开 Local State 的 os_crypt.encrypted_key
       Linux   ~/.config/com.qoder[cn].app.stable/auth.v1.dat
               "v10" + AES-128-CBC，密钥 = PBKDF2('peanuts','saltysalt',1)
               （v11 依赖系统密钥环，本脚本不支持）

4) 设备风控身份由客户端自带的 umid 组件生成：

       macOS   /Applications/Qoder CN.app/Contents/Resources/umid/runtime-info
       调用    runtime-info <env> --account-stdin   （stdin 传 {"account": <uid>}）
       输出    首行 JSON，取 machineToken / machineCode / machineType
       env     国内版 0，国际版 3

特点
----
- 复用本机客户端登录态，不操控 UI、不新建窗口，纯读取 + 纯 HTTP 调用
- 幂等安全：先查状态，已领直接跳过，绝不重复领
- 支持 --dry-run 预览、--json 机器可读输出，适合 cron / launchd 定时运行
- 客户端关闭时也能领取（只读磁盘上的登录态文件）

用法示例
--------
    python3 qoder_checkin.py                      # 国内版 + 国际版都领（已领自动跳过）
    python3 qoder_checkin.py --site cn            # 只领国内版
    python3 qoder_checkin.py --dry-run            # 只看今日状态，不领取
    python3 qoder_checkin.py --json               # 仅输出机器可读 JSON

常用参数
--------
    --site cn|intl|both   选择目标站点（默认 both）
    --dry-run             只查询状态，不领取
    --json / --quiet      机器可读输出 / 静默
    --token / --token-file
                          跳过客户端登录态，直接传入 access token（单站点）
    --keychain-service    macOS 指定钥匙串项名（默认自动尝试并记住可用项）
    --no-risk             不生成设备风控身份（国际版可能因此领不到）
    --data-dir / --resources-dir
                          客户端路径非标准位置时手动指定
    --timeout / --retries HTTP 超时（秒）/ 网络重试次数（默认 3）

定时建议
--------
    活动每天 10:00（北京时间）刷新，建议 10:05 之后运行：
    5 10 * * * /usr/bin/python3 /path/to/qoder_checkin.py --quiet

退出码
------
    0  成功（含「今日已领取」）
    1  配置 / 登录态错误
    2  网络 / 接口错误
    3  未知异常

前置条件
--------
    本机已安装并登录过 Qoder 客户端；依赖 pycryptodome（与 traecode/trae_work 脚本一致）。
"""

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

try:
    from Crypto.Cipher import AES  # pycryptodome
except ImportError:  # pragma: no cover - 环境缺依赖时给出可执行提示
    AES = None

# ----------------------------- 配置 -----------------------------
# 站点定义：base 为官方 OpenAPI 域名，risk_env 为 runtime-info 的环境编号
SITES = {
    "cn": {
        "label": "Qoder 国内版",
        "base": "https://openapi.qoder.com.cn",
        "app_id": "com.qodercn.app.stable",
        "install_name": "Qoder CN",
        "keychain": ["Qoder CN App Safe Storage", "Qoder App Safe Storage",
                     "Qoder CN Safe Storage"],
        "risk_env": 0,
    },
    "intl": {
        "label": "Qoder 国际版",
        "base": "https://openapi.qoder.sh",
        "app_id": "com.qoder.app.stable",
        "install_name": "Qoder",
        "keychain": ["Qoder App Safe Storage", "Qoder Safe Storage"],
        "risk_env": 3,
    },
}
SITE_ALIASES = {
    "cn": "cn", "domestic": "cn", "国内": "cn", "国内版": "cn",
    "intl": "intl", "international": "intl", "国际": "intl", "国际版": "intl",
}

# 活动接口（clientType=10 与官方客户端一致）
CAMPAIGNS_PATH = "/sash/api/v1/me/campaigns?clientType=10"
CAMPAIGN_CLAIM_PATH = "/sash/api/v1/me/campaigns/{campaign_id}/claim"
CAMPAIGN_CLIENT_TYPE = "10"

# 默认客户端版本（读不到 build-manifest.json 时兜底）
DEFAULT_CLIENT_VERSION = "0.4.3"

# 登录态文件名 / 机器 ID 文件名
AUTH_FILE = "auth.v1.dat"
MACHINE_ID_FILE = "auth.machine-id"

# 本地缓存目录（机器 ID 兜底持久化用，与 tabbit 脚本的缓存约定一致）
CACHE_DIR = "~/.qoder_checkin"

# 失败重试：仅对网络层失败与 5xx 生效（4xx / 登录态错误不重试）
DEFAULT_RETRIES = 3
RETRY_BACKOFF_SECONDS = (1.0, 3.0, 5.0)

# runtime-info 超时（客户端自身约 25s）
RISK_TIMEOUT_SECONDS = 25

# 读取 macOS 钥匙串的超时：首次读取会弹授权框，需要留给用户点击的时间
KEYCHAIN_TIMEOUT_SECONDS = 60

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.I)


# ----------------------------- 错误类型 -----------------------------
class CheckinError(RuntimeError):
    """脚本内可预期的错误基类，携带退出码与修复建议。"""

    exit_code = 2

    def __init__(self, message, hint=None):
        super().__init__(message)
        self.hint = hint


class AuthError(CheckinError):
    """登录态 / 凭证读取失败，属环境错误。"""

    exit_code = 1


class ApiError(CheckinError):
    """接口返回业务错误 / 非预期响应。"""

    exit_code = 2


class NetworkError(CheckinError):
    """网络层失败（重试耗尽后）。"""

    exit_code = 2


# ----------------------------- 日志 -----------------------------
class Log:
    """日志一律写 stderr；json 模式下更严格，保证 stdout 只承载结果数据。"""

    def __init__(self, quiet=False, json_mode=False):
        self.quiet = quiet
        self.json_mode = json_mode

    def _stream(self):
        # 非 json 模式保持 INFO 走 stdout（便于人工阅读 / 管道分类）
        # json 模式强制走 stderr，避免污染机器可读输出
        return sys.stderr if self.json_mode else sys.stdout

    def info(self, msg):
        if not self.quiet:
            print(f"[INFO] {msg}", file=self._stream())

    def warn(self, msg):
        if not self.quiet:
            print(f"[WARN] {msg}", file=sys.stderr)

    def err(self, msg):
        print(f"[ERROR] {msg}", file=sys.stderr)


# ----------------------------- 工具 -----------------------------
def _pretty(path):
    """把绝对路径里的 $HOME 折叠成 ~，让日志更短。"""
    home = os.path.expanduser("~")
    return path.replace(home, "~", 1) if path.startswith(home) else path


def safe_exists(path):
    try:
        return os.path.exists(path)
    except OSError:
        return False


def machine_os():
    """与客户端一致的 Cosy-MachineOS 格式：aarch64_darwin / x86_64_win32 …"""
    machine = platform.machine().lower()
    arch = {"arm64": "aarch64", "aarch64": "aarch64",
            "x86_64": "x86_64", "amd64": "x86_64"}.get(machine, machine or "unknown")
    plat = {"darwin": "darwin", "win32": "win32"}.get(sys.platform, "linux")
    return f"{arch}_{plat}"


def machine_hostname(raw=None):
    """与客户端一致的主机名清洗：仅可打印 ASCII，超长截断并附 8 位哈希。"""
    raw = raw if raw is not None else platform.node()
    text = str(raw or "").strip()
    if not text:
        return None

    def clip(value):
        if len(value) <= 96:
            return value
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
        head = re.sub(r"[-\s]+$", "", value[:96 - 8 - 1])
        return f"{head}-{digest}" if head else f"unknown-{digest}"

    if re.fullmatch(r"[\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?", text):
        return clip(text)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]
    cleaned = re.sub(r"-{2,}", "-", re.sub(r"[^\x21-\x7e]+", "-", text)).strip("-")
    return clip(f"{cleaned}-{digest}" if cleaned else f"unknown-{digest}")


def read_text_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except OSError:
        return None


def build_manifest_version(resources_dir):
    """读取客户端版本号（build-manifest.json 的 productVersion），用于 Cosy-Version。"""
    if not resources_dir:
        return None
    raw = read_text_file(os.path.join(resources_dir, "build-manifest.json"))
    if not raw:
        return None
    try:
        meta = json.loads(raw)
    except json.JSONDecodeError:
        return None
    version = meta.get("productVersion")
    return version.strip() if isinstance(version, str) and version.strip() else None


# ----------------------------- 客户端路径 -----------------------------
def user_data_dir(site, override=None):
    """客户端数据目录（含 auth.v1.dat / auth.machine-id）。"""
    if override:
        return os.path.expanduser(override)
    name = site["app_id"]
    home = os.path.expanduser("~")
    if sys.platform == "darwin":
        return os.path.join(home, "Library", "Application Support", name)
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or os.path.join(home, "AppData", "Roaming")
        return os.path.join(base, name)
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")
    return os.path.join(base, name)


def candidate_resources_dirs(site):
    """客户端 Resources 目录候选（umid/runtime-info 与 build-manifest.json 所在处）。"""
    home = os.path.expanduser("~")
    install = site["install_name"]
    if sys.platform == "darwin":
        return [f"/Applications/{install}.app/Contents/Resources",
                os.path.join(home, "Applications", f"{install}.app",
                             "Contents", "Resources")]
    if sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA") or os.path.join(home, "AppData", "Local")
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        return [os.path.join(local, "Programs", install, "resources"),
                os.path.join(pf, install, "resources")]
    slug = install.lower().replace(" ", "-")
    return [f"/opt/{install}/resources", f"/opt/{slug}/resources",
            f"/usr/lib/{slug}/resources"]


def find_resources_dir(site, override=None):
    if override:
        path = os.path.expanduser(override)
        return path if safe_exists(path) else None
    for path in candidate_resources_dirs(site):
        if safe_exists(path):
            return path
    return None


# ----------------------------- 凭证解密（Electron safeStorage） -----------------------------
def _pkcs7_unpad(data):
    if not data:
        return data
    pad = data[-1]
    if 1 <= pad <= 16 and data[-pad:] == bytes([pad]) * pad:
        return data[:-pad]
    return data


def _require_aes():
    if AES is None:
        raise AuthError(
            "缺少 AES 依赖，无法解密客户端登录态",
            hint="请先安装：pip3 install pycryptodome",
        )


def mac_keychain_password(service, log: Log, timeout=KEYCHAIN_TIMEOUT_SECONDS):
    """从 macOS 钥匙串读取 safeStorage 口令。

    客户端自己创建的钥匙串项默认只信任客户端本身，其他进程读取时 macOS 会弹一次
    授权框（点「始终允许」后即可长期无人值守）。因此这里超时给得比较宽松。
    """
    try:
        proc = subprocess.run(
            ["security", "find-generic-password", "-w", "-s", service],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired:
        log.warn(f"读取钥匙串「{service}」超时（{timeout}s）——"
                 "若屏幕上有钥匙串授权框，请点击「始终允许」后重跑；"
                 "也可用 --keychain-service 指定正确的项。")
        return None
    except (OSError, subprocess.SubprocessError) as e:
        log.warn(f"读取钥匙串失败（{service}）：{e}")
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.decode("utf-8", "replace").strip() or None


def load_known_service(site):
    """读取上次成功使用的钥匙串项名（缓存，避免每次都在候选里盲试）。"""
    raw = read_text_file(os.path.expanduser(os.path.join(CACHE_DIR, "keychain.json")))
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    value = data.get(site["app_id"]) if isinstance(data, dict) else None
    return value if isinstance(value, str) and value else None


def save_known_service(site, service):
    path = os.path.expanduser(os.path.join(CACHE_DIR, "keychain.json"))
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        data = {}
        raw = read_text_file(path)
        if raw:
            loaded = json.loads(raw)
            if isinstance(loaded, dict):
                data = loaded
        data[site["app_id"]] = service
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except (OSError, json.JSONDecodeError):
        pass


def dpapi_unprotect(blob):
    """Windows：用 DPAPI 解开 Local State 里的 os_crypt.encrypted_key。"""
    script = ("Add-Type -AssemblyName System.Security;"
              "$b=[Convert]::FromBase64String([Console]::In.ReadToEnd());"
              "[Convert]::ToBase64String("
              "[System.Security.Cryptography.ProtectedData]::Unprotect($b,$null,'CurrentUser'))")
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive",
             "-EncodedCommand", encoded],
            input=base64.b64encode(blob), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=20)
    except (OSError, subprocess.SubprocessError) as e:
        raise AuthError(f"DPAPI 解密失败：{e}") from e
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", "replace").strip()
        raise AuthError(f"DPAPI 解密失败：{stderr[:200] or 'powershell 返回非零退出码'}")
    return base64.b64decode(proc.stdout.decode("ascii").strip())


def ordered_keychain_services(site, override=None):
    """钥匙串项尝试顺序：命令行指定 → 上次成功记录 → 站点内置候选（去重）。"""
    services = []
    for candidate in (override, load_known_service(site)):
        if candidate and candidate not in services:
            services.append(candidate)
    for candidate in site["keychain"]:
        if candidate not in services:
            services.append(candidate)
    return services


def make_decryptors(site, data_dir, log: Log, keychain_service=None):
    """返回候选解密器 [(解密函数, 描述, 钥匙串项名或 None)]。

    macOS 上不同客户端用不同的钥匙串项（国内版 / 国际版各一个），因此这里为每个
    可读到的口令各生成一个候选，由 read_auth 用真实密文逐个试。
    """
    if sys.platform == "win32":
        local_state = read_text_file(os.path.join(data_dir, "Local State"))
        if not local_state:
            raise AuthError("客户端目录下没有 Local State，无法取得解密密钥")
        try:
            meta = json.loads(local_state)
        except json.JSONDecodeError as e:
            raise AuthError(f"Local State 解析失败：{e}") from e
        raw_key = (meta.get("os_crypt") or {}).get("encrypted_key") or ""
        blob = base64.b64decode(raw_key) if raw_key else b""
        if blob[:5] != b"DPAPI":
            raise AuthError("Local State 中没有 DPAPI 密钥，无法解密登录态")
        key = dpapi_unprotect(blob[5:])

        def decrypt_win(data, _key=key):
            if data[:3] != b"v10":
                raise AuthError("未知的登录态加密格式（期望 v10）")
            cipher = AES.new(_key, AES.MODE_GCM, nonce=data[3:15])
            return cipher.decrypt_and_verify(data[15:-16], data[-16:]).decode("utf-8")

        return [(decrypt_win, "DPAPI + AES-256-GCM", None)]

    if sys.platform == "darwin":
        out = []
        for service in ordered_keychain_services(site, keychain_service):
            password = mac_keychain_password(service, log)
            if not password:
                continue
            key = hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"),
                                      b"saltysalt", 1003, 16)

            def decrypt_mac(data, _key=key):
                if data[:3] != b"v10":
                    raise AuthError("未知的登录态加密格式（期望 v10）")
                plain = AES.new(_key, AES.MODE_CBC, b" " * 16).decrypt(data[3:])
                return _pkcs7_unpad(plain).decode("utf-8")

            out.append((decrypt_mac, f"钥匙串「{service}」+ AES-128-CBC", service))
        if not out:
            raise AuthError(
                "无法从钥匙串读取 Qoder 的 Safe Storage 口令",
                hint=("请在「钥匙串访问」里确认存在 "
                      + " / ".join(site["keychain"])
                      + "；首次运行若弹出授权框请选「始终允许」，"
                        "或改用 --token 传入。"),
            )
        return out

    # Linux：v10 用固定口令 peanuts（v11 依赖系统密钥环，本脚本不支持）
    key = hashlib.pbkdf2_hmac("sha1", b"peanuts", b"saltysalt", 1, 16)

    def decrypt_linux(data):
        if data[:3] == b"v11":
            raise AuthError(
                "该登录态使用 v11 加密（依赖系统密钥环），本脚本暂不支持",
                hint="请在已登录 Qoder 客户端的机器上运行，或改用 --token 传入。",
            )
        if data[:3] != b"v10":
            raise AuthError("未知的登录态加密格式（期望 v10）")
        plain = AES.new(key, AES.MODE_CBC, b" " * 16).decrypt(data[3:])
        return _pkcs7_unpad(plain).decode("utf-8")

    return [(decrypt_linux, "peanuts + AES-128-CBC", None)]


def read_auth(site, args, log: Log):
    """读取并解密客户端登录态，返回 {token, uid, user, expiresAt, file, how, data_dir}。"""
    data_dir = user_data_dir(site, args.data_dir)
    auth_path = os.path.join(data_dir, AUTH_FILE)
    if not safe_exists(auth_path):
        raise AuthError(
            f"未找到登录态文件 {_pretty(auth_path)}",
            hint=f"请先安装并登录「{site['install_name']}」客户端，或用 --token 直接传入。",
        )
    _require_aes()
    try:
        with open(auth_path, "rb") as f:
            blob = f.read()
    except OSError as e:
        raise AuthError(f"无法读取登录态文件 {_pretty(auth_path)}：{e}") from e

    reasons = []
    for decrypt, how, service in make_decryptors(site, data_dir, log,
                                                 args.keychain_service):
        try:
            payload = json.loads(decrypt(blob))
        except CheckinError as e:
            reasons.append(f"{how} → {e}")
            continue
        except (ValueError, UnicodeDecodeError) as e:
            reasons.append(f"{how} → 解密结果无法解析（{e}）")
            continue
        if not isinstance(payload, dict):
            reasons.append(f"{how} → 解密结果不是 JSON 对象")
            continue
        token = payload.get("token")
        if not isinstance(token, str) or not token.strip():
            reasons.append(f"{how} → 登录态里没有 token")
            continue
        if service:
            save_known_service(site, service)
        user = payload.get("user") if isinstance(payload.get("user"), dict) else {}
        expires = payload.get("expiresAt")
        return {
            "token": token.strip(),
            "uid": user.get("id") if isinstance(user.get("id"), str) else None,
            "user": user,
            "expiresAt": expires if isinstance(expires, str) else None,
            "file": auth_path,
            "how": how,
            "data_dir": data_dir,
        }

    raise AuthError(
        "登录态文件解密失败：" + "；".join(reasons[:3] or ["未知原因"]),
        hint="请确认客户端已登录且未升级加密方式，或改用 --token 传入。",
    )


# ----------------------------- 设备身份（机器 ID / 风控） -----------------------------
def machine_id(site, data_dir, override=None):
    """机器 ID：优先复用客户端的 auth.machine-id，否则本地持久化一个并复用。"""
    if override:
        return override.strip()
    for path in (os.path.join(data_dir, MACHINE_ID_FILE),
                 os.path.expanduser(os.path.join(CACHE_DIR, "machine-id"))):
        value = (read_text_file(path) or "").strip()
        if UUID_RE.fullmatch(value):
            return value
    value = _random_uuid()
    try:
        cache_dir = os.path.expanduser(CACHE_DIR)
        os.makedirs(cache_dir, exist_ok=True)
        tmp = os.path.join(cache_dir, "machine-id.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(value)
        os.chmod(tmp, 0o600)
        os.replace(tmp, os.path.join(cache_dir, "machine-id"))
    except OSError:
        pass
    return value


def _random_uuid():
    return str(uuid.uuid4())


def find_runtime_info(resources_dir):
    """客户端自带的 umid 组件路径（生成设备风控身份用）。"""
    if not resources_dir:
        return None
    exe = "runtime-info.exe" if sys.platform == "win32" else "runtime-info"
    path = os.path.join(resources_dir, "umid", exe)
    return path if safe_exists(path) else None


def get_risk_identity(site, uid, runtime_info, timeout=RISK_TIMEOUT_SECONDS):
    """调用 umid/runtime-info 生成设备风控身份。

    macOS / Windows：runtime-info <env> --account-stdin，stdin 传 {"account": uid}
    Linux（qodercli 提取的组件）：runtime-info <env>
    返回 {machineToken, machineCode, machineType}，失败返回 None（不阻断领取）。
    """
    if not runtime_info or not uid:
        return None
    with_stdin = sys.platform in ("darwin", "win32")
    argv = [runtime_info, str(site["risk_env"])] + (["--account-stdin"] if with_stdin else [])
    try:
        proc = subprocess.run(
            argv,
            input=(json.dumps({"account": uid}) + "\n").encode("utf-8") if with_stdin else None,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    line = proc.stdout.decode("utf-8", "replace").splitlines()
    if not line:
        return None
    try:
        payload = json.loads(line[0])
    except json.JSONDecodeError:
        return None
    picked = {}
    for key in ("machineToken", "machineCode", "machineType"):
        value = payload.get(key)
        if not isinstance(value, str) or not value.strip() or len(value) > 4096:
            return None
        picked[key] = value.strip()
    return picked


RISK_CACHE = {}


def resolve_risk_identity(site, uid, args, log: Log):
    """带进程内缓存的设备风控身份获取；--no-risk 或缺组件时返回 (None, 原因)。"""
    if args.no_risk:
        return None, "已通过 --no-risk 关闭"
    key = f"{site['app_id']}:{uid}"
    if key in RISK_CACHE:
        return RISK_CACHE[key], None
    resources = find_resources_dir(site, args.resources_dir)
    runtime_info = find_runtime_info(resources)
    if not runtime_info:
        reason = (f"未找到客户端 umid 组件（{site['install_name']}）"
                  if resources else f"未安装「{site['install_name']}」客户端")
        RISK_CACHE[key] = None
        return None, reason
    risk = get_risk_identity(site, uid, runtime_info)
    if not risk:
        RISK_CACHE[key] = None
        return None, "umid/runtime-info 执行失败"
    log.info(f"已取得设备风控身份（umid · env={site['risk_env']}）")
    RISK_CACHE[key] = risk
    return risk, None


# ----------------------------- HTTP -----------------------------
def _sleep_before_retry(attempt, log: Log, reason):
    delay = RETRY_BACKOFF_SECONDS[min(attempt, len(RETRY_BACKOFF_SECONDS) - 1)]
    log.warn(f"{reason}；{delay:g}s 后重试（第 {attempt + 1} 次）")
    time.sleep(delay)


def http_request(url, headers, timeout, log: Log, method="GET",
                 body=None, retries=DEFAULT_RETRIES):
    """发送请求，返回 (http_code, 原始响应体)。

    - 401/403 → 立即抛 AuthError（登录态问题，重试无意义）
    - 网络失败 / 5xx → 指数退避重试，最多 retries 次
    - 其余 4xx → 原样返回，交给业务层判断
    """
    last_reason = None
    for attempt in range(max(retries, 0) + 1):
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.getcode(), resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            code = e.code
            try:
                raw = e.read().decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                raw = ""
            if code in (401, 403):
                raise AuthError(
                    f"登录态已失效（HTTP {code}）",
                    hint="请打开 Qoder 客户端确认已登录（让客户端刷新凭据）后重跑本脚本。",
                ) from e
            if code >= 500 and attempt < retries:
                last_reason = f"服务端返回 HTTP {code}"
                _sleep_before_retry(attempt, log, last_reason)
                continue
            return code, raw
        except urllib.error.URLError as e:
            last_reason = f"网络请求失败: {e.reason}"
            if attempt < retries:
                _sleep_before_retry(attempt, log, last_reason)
                continue
            raise NetworkError(last_reason, hint="请检查本机网络 / 代理设置。") from e
        except (TimeoutError, OSError) as e:
            last_reason = f"请求超时或连接异常: {e}"
            if attempt < retries:
                _sleep_before_retry(attempt, log, last_reason)
                continue
            raise NetworkError(last_reason) from e
        except Exception as e:  # noqa: BLE001
            raise NetworkError(f"请求异常: {e}") from e
    raise NetworkError(last_reason or "网络请求失败", hint="已重试全部次数仍失败。")


def parse_body(raw):
    if not raw:
        return {}
    try:
        body = json.loads(raw)
    except json.JSONDecodeError:
        return {"_raw": " ".join(raw.split())[:200]}
    return body if isinstance(body, dict) else {"_data": body}


# ----------------------------- 主流程 -----------------------------
def parse_sites(value):
    if value in (None, "both", "all"):
        return ["cn", "intl"]
    keys = []
    for part in str(value).replace(",", " ").split():
        key = SITE_ALIASES.get(part.lower()) or SITE_ALIASES.get(part)
        if not key:
            raise argparse.ArgumentTypeError(
                f"未知站点：{part}（可选 cn / intl / both）")
        if key not in keys:
            keys.append(key)
    return keys or ["cn", "intl"]


def resolve_token(args, site, log: Log):
    """登录态来源：--token / --token-file / 本机客户端 auth.v1.dat。"""
    explicit = args.token or os.environ.get("QODER_TOKEN")
    if explicit:
        return {"token": explicit.strip(), "uid": args.uid, "user": {},
                "expiresAt": None, "file": None, "how": "命令行 / 环境变量",
                "data_dir": user_data_dir(site, args.data_dir)}
    if args.token_file:
        path = os.path.expanduser(args.token_file)
        raw = read_text_file(path)
        if raw is None:
            raise AuthError(f"无法读取 token 文件：{_pretty(path)}")
        token = raw.strip().splitlines()[0].strip() if raw.strip() else ""
        if not token:
            raise AuthError("token 文件内容为空")
        return {"token": token, "uid": args.uid, "user": {}, "expiresAt": None,
                "file": path, "how": "token 文件",
                "data_dir": user_data_dir(site, args.data_dir)}
    return read_auth(site, args, log)


def _campaign_line(campaign):
    """把活动对象压成一行便于阅读的摘要。"""
    benefit = campaign.get("benefit") if isinstance(campaign.get("benefit"), dict) else {}
    amount = benefit.get("amount")
    parts = [str(campaign.get("campaignKey") or campaign.get("campaignId") or "?")]
    if campaign.get("actionType"):
        parts.append(str(campaign["actionType"]))
    if campaign.get("claimStatus"):
        parts.append(str(campaign["claimStatus"]))
    if amount is not None:
        parts.append(f"{benefit.get('kind') or 'BENEFIT'}/{amount}")
    return " ".join(parts)


# ----------------------------- 接口 -----------------------------
def build_headers(token, site, uid, data_dir, resources_dir, risk, client_version=None):
    """构造与客户端一致的鉴权头（含设备风控身份）。"""
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
        "Cosy-ClientType": CAMPAIGN_CLIENT_TYPE,
        "Cosy-Version": (client_version
                         or build_manifest_version(resources_dir)
                         or DEFAULT_CLIENT_VERSION),
        "Cosy-MachineOS": machine_os(),
        "Cosy-MachineId": machine_id(site, data_dir),
        "User-Agent": "Qoder",
    }
    host = machine_hostname()
    if host:
        headers["Cosy-MachineHostname"] = host
    if risk:
        headers["Cosy-MachineToken"] = risk["machineToken"]
        headers["Cosy-MachineCode"] = risk["machineCode"]
        headers["Cosy-MachineType"] = risk["machineType"]
    return headers


def fetch_campaigns(base, headers, args, log: Log):
    """拉取活动列表，返回服务端原始 payload。"""
    code, raw = http_request(base + CAMPAIGNS_PATH, headers, args.timeout, log,
                             retries=args.retries)
    body = parse_body(raw)
    if code != 200:
        raise ApiError(f"活动列表查询失败: HTTP {code} "
                       f"{json.dumps(body, ensure_ascii=False)[:200]}")
    return body


def claim_campaign(base, campaign_id, headers, args, log: Log):
    """领取单个活动。返回 (ok, 说明/金额信息)。"""
    url = base + CAMPAIGN_CLAIM_PATH.format(campaign_id=urllib.parse.quote(campaign_id))
    # 与客户端一致：POST 空体（显式声明 Content-Length，避免网关判非法请求）
    post_headers = dict(headers)
    post_headers["Content-Length"] = "0"
    code, raw = http_request(url, post_headers, args.timeout, log, method="POST",
                             body=b"", retries=args.retries)
    body = parse_body(raw)
    if code == 200:
        return True, body
    return False, f"HTTP {code} {json.dumps(body, ensure_ascii=False)[:180]}"


def checkin_site(key, args, log: Log):
    """对单个站点执行「查询 + 领取」，返回结果条目。"""
    site = SITES[key]
    entry = {"site": key, "label": site["label"], "base": site["base"]}
    auth = resolve_token(args, site, log)
    entry["uid"] = auth.get("uid")
    entry["account"] = (auth.get("user") or {}).get("name")
    if auth.get("how"):
        entry["credential"] = auth["how"]

    resources = find_resources_dir(site, args.resources_dir)
    data_dir = auth["data_dir"]

    # 1) 设备风控身份（国际版按设备限领，靠它识别；国内版可选）
    risk, risk_reason = None, None
    if auth.get("uid"):
        risk, risk_reason = resolve_risk_identity(site, auth["uid"], args, log)
    entry["risk_identity"] = bool(risk)

    headers = build_headers(auth["token"], site, auth.get("uid"), data_dir,
                            resources, risk)
    payload = fetch_campaigns(site["base"], headers, args, log)

    # 2) token 由外部传入时 uid 未知：拿到 uid 后带风控身份再查一次
    if not auth.get("uid") and isinstance(payload.get("uid"), str):
        auth["uid"] = payload["uid"]
        entry["uid"] = payload["uid"]
        risk, risk_reason = resolve_risk_identity(site, auth["uid"], args, log)
        entry["risk_identity"] = bool(risk)
        if risk:
            headers = build_headers(auth["token"], site, auth["uid"], data_dir,
                                    resources, risk)
            payload = fetch_campaigns(site["base"], headers, args, log)

    campaigns = payload.get("campaigns")
    campaigns = campaigns if isinstance(campaigns, list) else []
    credit = [c for c in campaigns
              if isinstance(c, dict) and c.get("actionType") == "CLAIM_BENEFIT"]
    claimable = [c for c in credit if c.get("claimStatus") == "CLAIMABLE"]
    entry["show_campaign"] = bool(payload.get("showCampaign"))
    entry["campaigns"] = [_campaign_line(c) for c in campaigns if isinstance(c, dict)]

    if not args.json:
        log.info(f"[{key}] {site['label']}：活动 {len(campaigns)} 个，"
                 f"可领取 {len(claimable)} 个")
        if risk_reason:
            log.info(f"[{key}] 未使用设备风控身份：{risk_reason}")

    if args.dry_run:
        entry["action"] = "dry_run"
        entry["claimable"] = len(claimable)
        return entry

    # 3) 幂等：没有可领的积分活动 → 区分「今日已领」与「暂无可领活动」
    if not claimable:
        if credit:
            entry["action"] = "skip_already_claimed"
            if not args.json:
                log.info(f"[{key}] 今日已领取，跳过。✅")
        else:
            entry["action"] = "no_activity"
            hint = "当前窗口暂无可领活动"
            if key == "intl" and not risk:
                hint += f"（国际版需要设备风控身份：{risk_reason}）"
            entry["message"] = hint
            if not args.json:
                log.info(f"[{key}] {hint}。")
        return entry
    return _claim_all(key, site, entry, claimable, headers, args, log)


def _claim_all(key, site, entry, claimable, headers, args, log: Log):
    """逐个领取可领活动，结果写入 entry。"""
    claimed, errors = [], []
    total = 0
    for campaign in claimable:
        campaign_id = campaign.get("campaignId")
        if not isinstance(campaign_id, str) or not campaign_id:
            errors.append("活动缺少 campaignId")
            continue
        if not args.json:
            log.info(f"[{key}] 领取 {_campaign_line(campaign)} ……")
        ok, result = claim_campaign(site["base"], campaign_id, headers, args, log)
        benefit = campaign.get("benefit") if isinstance(campaign.get("benefit"), dict) else {}
        if ok:
            amount = benefit.get("amount")
            if isinstance(result, dict) and isinstance(result.get("benefit"), dict):
                resp_amount = result["benefit"].get("amount")
                if resp_amount is not None:
                    amount = resp_amount
            total += amount if isinstance(amount, (int, float)) else 0
            claimed.append({"campaignId": campaign_id,
                            "campaignKey": campaign.get("campaignKey"),
                            "amount": amount})
            if not args.json:
                log.info(f"[{key}] 领取成功：{campaign.get('campaignKey')} "
                         f"+{amount if amount is not None else '?'} Credits ✅")
        else:
            errors.append(f"{campaign.get('campaignKey')}: {result}")
            log.err(f"[{key}] 领取失败：{campaign.get('campaignKey')} → {result}")

    entry["claimed"] = claimed
    entry["claimed_amount"] = total
    if claimed:
        entry["action"] = "checked_in"
    else:
        entry["action"] = "error"
        entry["msg"] = "；".join(errors) or "未知原因"
    return entry


# ----------------------------- 入口 -----------------------------
def build_parser():
    parser = argparse.ArgumentParser(
        description="Qoder 每日自动领取「专属活动权益」脚本（单文件版）")
    parser.add_argument("--site", default="both",
                        help="目标站点：cn（国内版）/ intl（国际版）/ both（默认）")
    parser.add_argument("--token", help="直接传入 access token（仅单站点有效）")
    parser.add_argument("--token-file", help="从文件读取 access token（取第一行）")
    parser.add_argument("--uid", help="账号 uid（配合 --token 时用于生成设备风控身份）")
    parser.add_argument("--data-dir", help="客户端数据目录（默认自动探测）")
    parser.add_argument("--resources-dir", help="客户端 Resources 目录（默认自动探测）")
    parser.add_argument("--keychain-service",
                        help="macOS 钥匙串项名（默认按候选自动尝试并记住可用项）")
    parser.add_argument("--no-risk", action="store_true",
                        help="不生成设备风控身份（国际版可能因此领不到）")
    parser.add_argument("--dry-run", action="store_true",
                        help="只查询今日状态，不执行领取")
    parser.add_argument("--json", action="store_true", help="仅输出机器可读 JSON")
    parser.add_argument("--quiet", "-q", action="store_true", help="静默模式")
    parser.add_argument("--timeout", type=int, default=20, help="HTTP 超时（秒）")
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES,
                        help=f"网络异常 / 5xx 自动重试次数（默认 {DEFAULT_RETRIES}，0 关闭）")
    return parser


def _report_hint(log: Log, error):
    hint = getattr(error, "hint", None)
    if hint:
        log.err(f"提示：{hint}")


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    # --json 时 stdout 必须只输出 JSON：INFO 一律静音，WARN/ERROR 仍走 stderr
    log = Log(quiet=args.quiet or args.json, json_mode=args.json)

    def emit(payload):
        if args.json:
            print(json.dumps(payload, ensure_ascii=False))

    if args.token and args.token_file:
        log.err("--token 与 --token-file 不能同时使用。")
        return 1
    try:
        site_keys = parse_sites(args.site)
    except argparse.ArgumentTypeError as e:
        log.err(str(e))
        return 1
    if (args.token or args.token_file) and len(site_keys) > 1:
        log.err("--token / --token-file 只能配合单个站点使用（--site cn 或 --site intl）。")
        return 1

    results, errors = [], []
    for key in site_keys:
        try:
            entry = checkin_site(key, args, log)
        except AuthError as e:
            log.err(f"[{key}] {e}")
            _report_hint(log, e)
            errors.append({"site": key, "auth": True, "msg": str(e)})
            results.append({"site": key, "action": "error", "msg": str(e)})
            continue
        except CheckinError as e:
            log.err(f"[{key}] {e}")
            _report_hint(log, e)
            errors.append({"site": key, "auth": False, "msg": str(e)})
            results.append({"site": key, "action": "error", "msg": str(e)})
            continue
        except Exception as e:  # noqa: BLE001
            log.err(f"[{key}] 未知异常: {e}")
            errors.append({"site": key, "auth": False, "msg": f"未知异常: {e}"})
            results.append({"site": key, "action": "error", "msg": f"未知异常: {e}"})
            continue
        results.append(entry)
        if entry.get("action") == "error":
            errors.append({"site": key, "auth": False, "msg": entry.get("msg")})

    if args.json:
        emit({"status": "error" if errors else "ok",
              "dry_run": args.dry_run,
              "results": results})
    else:
        if not errors:
            if args.dry_run:
                log.info("查询完成（dry-run，未做任何领取）。")
            else:
                claimed_total = sum(e.get("claimed_amount") or 0 for e in results)
                if claimed_total:
                    log.info(f"完成：本次共领取 {claimed_total} Credits ✅")
                else:
                    log.info("完成：暂无可领取的权益。")
        snapshot = ", ".join(
            f"{e.get('label', e.get('site'))}={e.get('action')}" for e in results)
        log.info(f"结果：{snapshot}")

    if not results:
        log.err("没有可执行的站点。")
        return 1
    if errors:
        # 全部是登录态问题 → 1；否则按接口 / 网络错误 → 2
        return 1 if all(e.get("auth") for e in errors) else 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
