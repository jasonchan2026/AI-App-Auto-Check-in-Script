#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WorkBuddy 每日自动签到脚本（单文件版）
=====================================

通过读取本机 WorkBuddy 登录态中的 accessToken，调用官方接口完成每日签到领积分。
- 仅用 Python 标准库，无任何第三方依赖。
- 单次运行：命令行直接执行即可，适合用 cron / 计划任务 / launchd 定时调用。
- 幂等安全：先查询今日是否已签到，已签则跳过，绝不重复签。
- 失败重试：网络抖动 / 5xx 自动指数退避重试；401/403 登录态失效立即明确报错，不重试。
- 输出干净：--json 时 stdout 只有一行 JSON，所有日志一律走 stderr，可安全 `| jq`。
- 跨平台自动定位登录态文件；也支持环境变量 / 命令行参数传入 token。

登录态说明
----------
WorkBuddy 桌面端把 `auth.accessToken` 存为「加密信封」形式：

    {"$wbEncrypted": 1, "envelope": "<base64>"}

envelope 内是 AES-256-GCM 密文，密钥存放在客户端进程内
（`process._linkedBinding('electron_browser_workbuddy_storage').loggerGet()`
返回的 atRestSecretKey）。本脚本因此会**短暂起一个 WorkBuddy 客户端子进程**
（ELECTRON_RUN_AS_NODE=1）完成解密：密钥与明文 token 都只存在于该子进程的内存中，
不落盘、不缓存、不打印，原地清零后随进程退出。

凭据助手的 JS 与加解密约定参考了 MIT 协议项目 88lin/workbuddy-auto-signin。

用法示例
--------
    python workbuddy_checkin.py                # 签到 + 成长中心（默认全跑，推荐）
    python workbuddy_checkin.py --json         # 同上，仅输出机器可读 JSON（stdout）
    python workbuddy_checkin.py --no-growth    # 只签到，不碰成长中心
    python workbuddy_checkin.py --growth-only  # 只跑成长中心，不签到
    python workbuddy_checkin.py --dry-run      # 只查询状态，什么都不领（含成长中心）
    python workbuddy_checkin.py --gift         # （可选）额外领「今日礼包」
    python workbuddy_checkin.py --doctor       # 离线体检：只验凭据格式与解密能力，不联网
    python workbuddy_checkin.py --retries 0    # 关闭重试（排障用）
    WORKBUDDY_ACCESS_TOKEN=xxx python workbuddy_checkin.py

注意：所有参数用**英文半角**减号 `--`，写成中文破折号 `—` 会被 argparse 拒绝。

环境变量
--------
    WORKBUDDY_ACCESS_TOKEN    直接指定明文 accessToken（跳过解密）
    WORKBUDDY_AUTH_FILE       手动指定凭据文件路径
    WORKBUDDY_EXE             指定与加密凭据对应的客户端可执行文件
    WORKBUDDY_BUDGET_SECONDS  单次运行的网络请求时间预算（默认 240，范围 30–420）

成长中心
--------
默认就会跑 /v2/activity/growth 的 7 个模块，顺序固定：Buddy 旅行（领礼物 +
派出发）→ 任务（接单 + 领奖）→ 补登卡 → 连登兑换 → 盲盒 → Buddy 盲盒 →
展示值。顺序有讲究：任务领奖排在抽奖前（任务送的抽奖机会马上能用），补登
排在连登兑换前（补登会改变连登天数，先补才知道档位解锁）。

每个模块都是「先查状态再决定是否写」，重复运行不会重复领取。一整轮最坏要打
十几个接口，因此内置时间预算：预算耗尽就主动收尾并如实记录已领到的部分。
不需要时用 --no-growth 关掉。

退出码
------
    0  成功（含「今日已签到」跳过 / 活动未开启 / 成长中心无可领取项）
    1  参数 / 环境 / 登录态错误（找不到凭据、token 已失效等）
    2  网络 / 接口错误
    3  未知异常
"""

import argparse
import base64
import json
import math
import os
import plistlib
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid

# ----------------------------- 配置 -----------------------------
# 官方客户端实际打的就是这个 endpoint（可被凭据里的 auth.endpoint 覆盖）
DEFAULT_ENDPOINT = "https://copilot.tencent.com"
STATUS_PATH = "/v2/billing/meter/checkin-activity-status"
CHECKIN_PATH = "/v2/billing/meter/daily-checkin"
GIFT_PATH = "/billing/meter/claim-gift"  # 注意：无 /v2 前缀

# 客户端 UA：官方桌面端就是这个值，保持一致最稳
USER_AGENT = "WorkBuddy"

# 失败重试：仅对网络层失败与 5xx 生效（4xx / 登录态错误不重试）
DEFAULT_RETRIES = 3
RETRY_BACKOFF_SECONDS = (5.0, 15.0, 30.0)

# 登录态文件候选路径（跨平台）
AUTH_REL_BASENAME = os.path.join("CodeBuddyExtension", "Data", "Public", "auth",
                                 "workbuddy-desktop.info")

# 凭据助手（解密）相关限额
AUTH_HELPER_TIMEOUT = 15.0     # 客户端子进程最长执行时间
AUTH_INPUT_LIMIT = 65536       # stdin 输入上限
AUTH_OUTPUT_LIMIT = 65536      # stdout 输出上限
TOKEN_LIMIT = 32768

AUTH_REASONS = {
    "INVALID_FORMAT": "登录凭据格式无效，请检查凭据来源和客户端版本",
    "UNSUPPORTED_ENVELOPE": "加密凭据格式尚不支持，请更新脚本；重新登录不会改变加密格式",
    "RUNTIME_NOT_FOUND": "未找到 WorkBuddy 客户端，请用 WORKBUDDY_EXE 指定其可执行文件",
    "INVALID_RUNTIME_PATH": "WORKBUDDY_EXE 不是可用的可执行文件，请核对路径",
    "RUNTIME_UNAVAILABLE": "客户端运行时不支持所需的原生存储接口，请检查客户端和脚本版本",
    "KEY_MISMATCH": "凭据与所选客户端的密钥不匹配，请用 WORKBUDDY_EXE 指定对应客户端",
    "DECRYPT_FAILED": "加密凭据认证失败，请检查客户端版本及凭据是否完整",
    "HELPER_TIMEOUT": "凭据解密超时，已停止子进程，请稍后重试",
    "HELPER_PROTOCOL": "客户端凭据助手返回无效结果，请检查客户端和脚本版本",
}

# ------------------------- 成长中心（/v2/activity/growth） -------------------------
GROWTH_PATH = "/v2/activity/growth"

# 每轮最多用掉几张补登卡。卡是稀缺资源（上限 4 张），而这条写路径还没有被真实
# 响应验证过（实测 makeup_dates 一直是空），一轮只花一张：猜错形状也只错一次。
MAKEUP_MAX_PER_RUN = 1

# 连登兑换三档：(tier 标识, /redeem/summary 的状态字段前缀, 展示名, 天数)
# tier 的口径是**档位标识字符串**（"7d"/"14d"/"28d"），权威来源是 GET /streak 的
# redemption_status.tiers[].tier。天数只用于兜底重试时退回旧写法。
REDEEM_TIERS = (
    ("7d", "starter", "入门", 7),
    ("14d", "advanced", "进阶", 14),
    ("28d", "legendary", "巅峰", 28),
)

# 各档奖励的官方文案（2026-09 活动版本）。兑换成功的汇报优先用服务端返回的实际
# 明细，挖不到字段时才回落到这里——活动改版时以响应为准。
REDEEM_REWARDS = {
    "7d": "+2 能量 +1 补登卡 +1 次抽奖",
    "14d": "+50 积分 +3 能量 +1 补登卡 +1 次抽奖",
    "28d": "+150 积分 +5 能量 +1 补登卡 +1 次抽奖",
}


# 凭据助手 JS：只有固定的代码文本进 argv，加密信封走 stdin。
# 构建材料（密钥）永不离开该子进程。
AUTH_HELPER_JS = r"""
'use strict';
const crypto = require('crypto');
const inputLimit = 65536;
const failure = reason => { throw {reason}; };
const object = x => x !== null && typeof x === 'object' && !Array.isArray(x);
function base64(value, length) {
  if (typeof value !== 'string' || value.length > inputLimit) failure('INVALID_FORMAT');
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value || (length !== undefined && bytes.length !== length))
    failure('INVALID_FORMAT');
  return bytes;
}
function utf8(bytes) {
  const text = bytes.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(bytes)) failure('INVALID_FORMAT');
  return text;
}
function decode(value) {
  if (!object(value) || Object.keys(value).sort().join(',') !== '$wbEncrypted,envelope' || value.$wbEncrypted !== 1)
    failure('UNSUPPORTED_ENVELOPE');
  let envelope;
  try { envelope = JSON.parse(utf8(base64(value.envelope))); }
  catch (e) { failure(e.reason || 'INVALID_FORMAT'); }
  if (!object(envelope) || !Number.isInteger(envelope.suite)) failure('INVALID_FORMAT');
  if (envelope.suite !== 1) failure('UNSUPPORTED_ENVELOPE');
  if (Object.keys(envelope).sort().join(',') !== 'authTag,ciphertext,keyId,nonce,suite' ||
      typeof envelope.keyId !== 'string' || !/^[0-9a-f]{16}$/.test(envelope.keyId)) failure('INVALID_FORMAT');
  return {keyId: envelope.keyId, nonce: base64(envelope.nonce, 12),
    tag: base64(envelope.authTag, 16), ciphertext: base64(envelope.ciphertext)};
}
function nativeStorage() {
  try {
    const storage = process._linkedBinding('electron_browser_workbuddy_storage');
    if (typeof storage.loggerGet !== 'function') failure('RUNTIME_UNAVAILABLE');
    return storage;
  } catch (_) { failure('RUNTIME_UNAVAILABLE'); }
}
function decrypt(envelope) {
  let payload;
  try { payload = JSON.parse(nativeStorage().loggerGet()); }
  catch (_) { failure('RUNTIME_UNAVAILABLE'); }
  let key;
  let plaintext;
  try {
    if (!object(payload) || payload.version !== 1) failure('RUNTIME_UNAVAILABLE');
    let secret;
    try { secret = base64(payload.atRestSecretKey, 32); }
    catch (_) { failure('RUNTIME_UNAVAILABLE'); }
    const empty = secret.every(b => b === 0);
    secret.fill(0);
    if (empty) failure('RUNTIME_UNAVAILABLE');
    key = crypto.createHash('sha256').update(payload.atRestSecretKey, 'utf8').digest();
    payload = null;
    if (crypto.createHash('sha256').update(key).digest('hex').slice(0, 16) !== envelope.keyId)
      failure('KEY_MISMATCH');
    const lp = s => {
      const bytes = Buffer.from(s, 'utf8');
      const length = Buffer.alloc(4); length.writeUInt32BE(bytes.length);
      return Buffer.concat([length, bytes]);
    };
    const aad = Buffer.concat([Buffer.from('WB-AAD\0', 'ascii'), Buffer.from([1]),
      lp('WBEV1'), lp('sym-v1'), Buffer.from([0, 0, 0, 1]), lp(envelope.keyId), Buffer.from([2, 0, 0])]);
    try {
      const cipher = crypto.createDecipheriv('aes-256-gcm', key, envelope.nonce, {authTagLength: 16});
      cipher.setAAD(aad); cipher.setAuthTag(envelope.tag);
      plaintext = Buffer.concat([cipher.update(envelope.ciphertext), cipher.final()]);
    } catch (_) { failure('DECRYPT_FAILED'); }
    const token = utf8(plaintext);
    if (!token.length || token.length > 32768 || !/^[A-Za-z0-9._~+\/-]+=*$/.test(token))
      failure('INVALID_FORMAT');
    return token;
  } finally {
    if (key) key.fill(0);
    if (plaintext) plaintext.fill(0);
  }
}
let chunks = [], size = 0;
function reply(value) {
  process.stdout.write(JSON.stringify({version: 1, ...value}), () => process.exit(value.ok ? 0 : 1));
}
process.stdin.on('data', chunk => {
  size += chunk.length;
  if (size > inputLimit) reply({ok: false, reason: 'INVALID_FORMAT'});
  else chunks.push(chunk);
});
process.stdin.on('error', () => reply({ok: false, reason: 'HELPER_PROTOCOL'}));
process.stdin.on('end', () => {
  try {
    const request = JSON.parse(utf8(Buffer.concat(chunks))); chunks = [];
    if (!object(request) || request.version !== 1) failure('HELPER_PROTOCOL');
    if (request.operation === 'probe') {
      nativeStorage();
      if (!crypto.getCiphers().includes('aes-256-gcm')) failure('RUNTIME_UNAVAILABLE');
      reply({ok: true, electron: process.versions.electron || 'unknown'});
    } else if (request.operation === 'decrypt') {
      reply({ok: true, accessToken: decrypt(decode(request.value))});
    } else failure('HELPER_PROTOCOL');
  } catch (e) {
    const reasons = ['INVALID_FORMAT','UNSUPPORTED_ENVELOPE','RUNTIME_UNAVAILABLE',
      'KEY_MISMATCH','DECRYPT_FAILED','HELPER_PROTOCOL'];
    reply({ok: false, reason: reasons.includes(e.reason) ? e.reason : 'HELPER_PROTOCOL'});
  }
});
"""


# ----------------------------- 错误类型 -----------------------------
class CheckinError(RuntimeError):
    """脚本内可预期的错误基类，携带退出码与修复建议。"""

    exit_code = 2

    def __init__(self, message, hint=None):
        super().__init__(message)
        self.hint = hint


class AuthError(CheckinError):
    """登录态无效 / 不可用（凭据相关），属环境错误。"""

    exit_code = 1

    def __init__(self, message, hint=None, reason=None):
        super().__init__(message, hint)
        self.reason = reason

    @classmethod
    def from_reason(cls, reason):
        """按凭据助手的固定 reason 码构造，绝不把子进程原始输出带进消息。"""
        return cls(AUTH_REASONS.get(reason, "登录凭据不可用"),
                   hint="请先登录 WorkBuddy 桌面端；如已登录仍失败，用 WORKBUDDY_EXE "
                        "指定与该凭据匹配的客户端。",
                   reason=reason)


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
    """把 $HOME 前缀折叠成 ~，日志更短。"""
    home = os.path.expanduser("~")
    return "~" + path[len(home):] if path.startswith(home) else path


def dig(obj, key):
    """在可能被 data/result 包裹的响应里找字段，兼容信封结构。"""
    if isinstance(obj, dict):
        if key in obj and obj[key] is not None:
            return obj[key]
        for k in ("data", "result", "resp", "response"):
            if k in obj and isinstance(obj[k], dict):
                r = dig(obj[k], key)
                if r is not None:
                    return r
    return None


def _valid_token(token):
    """accessToken 形态校验：只允许 JWT/base64url 那类字符集。"""
    return (isinstance(token, str) and 0 < len(token) <= TOKEN_LIMIT
            and re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", token) is not None)


def _sleep_before_retry(attempt, log: Log, reason):
    delay = RETRY_BACKOFF_SECONDS[min(attempt, len(RETRY_BACKOFF_SECONDS) - 1)]
    log.warn(f"{reason}；{delay:g}s 后重试（第 {attempt + 1} 次）")
    time.sleep(delay)


# ------------------------- 客户端运行时定位 -------------------------
def _mac_runtime(bundle):
    """从 .app 的 Info.plist 读 CFBundleExecutable，避免硬编码 Electron 字样。"""
    try:
        with open(os.path.join(bundle, "Contents", "Info.plist"), "rb") as f:
            name = plistlib.load(f).get("CFBundleExecutable")
        if (not isinstance(name, str) or not name or name in (".", "..")
                or "/" in name or "\\" in name):
            return None
        return os.path.join(bundle, "Contents", "MacOS", name)
    except (OSError, ValueError, TypeError, AttributeError):
        return None


def find_runtime():
    """定位 WorkBuddy 客户端可执行文件（解密密钥只存在于这个运行时里）。

    顺序：WORKBUDDY_EXE 覆盖 → 平台默认安装位置。macOS 读 Info.plist 拿真实
    可执行文件名（客户端升级改名过，猜 Electron 会失效）。
    """
    override = os.environ.get("WORKBUDDY_EXE")
    if override:
        path = os.path.abspath(os.path.expanduser(override))
        if not os.path.isfile(path) or (os.name != "nt" and not os.access(path, os.X_OK)):
            raise AuthError.from_reason("INVALID_RUNTIME_PATH")
        return path

    home = os.path.expanduser("~")
    candidates = []
    if sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA") or os.path.join(home, "AppData", "Local")
        candidates.append(os.path.join(local, "Programs", "WorkBuddy", "WorkBuddy.exe"))
        for name in ("ProgramFiles", "ProgramFiles(x86)"):
            if os.environ.get(name):
                candidates.append(os.path.join(os.environ[name], "WorkBuddy", "WorkBuddy.exe"))
    elif sys.platform == "darwin":
        candidates = [_mac_runtime(os.path.join(root, "WorkBuddy.app"))
                      for root in ("/Applications", os.path.join(home, "Applications"))]
    for path in candidates:
        if path and os.path.isfile(path) and (os.name == "nt" or os.access(path, os.X_OK)):
            return os.path.abspath(path)
    raise AuthError.from_reason("RUNTIME_NOT_FOUND")


def run_auth_helper(request, log: Log):
    """起一个短命的客户端子进程执行解密 / 探测。

    管道与时限全部设上限；异常消息里绝不含子进程输出或 token。
    ELECTRON_RUN_AS_NODE=1 让 Electron 以纯 Node 模式启动，不拉起 GUI。
    """
    payload = json.dumps(dict(request, version=1), ensure_ascii=True).encode("ascii")
    if len(payload) > AUTH_INPUT_LIMIT:
        raise AuthError.from_reason("INVALID_FORMAT")

    env = {k: v for k, v in os.environ.items()
           if not k.upper().startswith(("NODE_", "ELECTRON_", "WORKBUDDY_"))}
    env["ELECTRON_RUN_AS_NODE"] = "1"
    exe = find_runtime()
    log.info(f"启动凭据助手：{_pretty(exe)}（{request['operation']}）")
    try:
        proc = subprocess.Popen(
            [exe, "-e", AUTH_HELPER_JS],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, shell=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except OSError:
        raise AuthError.from_reason("RUNTIME_UNAVAILABLE") from None

    output = {}
    failed = threading.Event()

    def read_pipe(name, pipe, limit):
        # 读满 limit+1 即视为超限：助手不该产生这么大的输出，超了直接杀掉
        try:
            captured = pipe.read(limit + 1)
            if len(captured) > limit:
                failed.set()
                proc.kill()
            else:
                output[name] = captured
        except OSError:
            failed.set()

    def write_pipe():
        try:
            proc.stdin.write(payload)
            proc.stdin.close()
        except OSError:
            failed.set()

    workers = [
        threading.Thread(target=read_pipe, args=("stdout", proc.stdout, AUTH_OUTPUT_LIMIT), daemon=True),
        threading.Thread(target=read_pipe, args=("stderr", proc.stderr, 8192), daemon=True),
        threading.Thread(target=write_pipe, daemon=True),
    ]
    deadline = time.monotonic() + AUTH_HELPER_TIMEOUT
    try:
        for w in workers:
            w.start()
        try:
            proc.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise AuthError.from_reason("HELPER_TIMEOUT") from None
        for w in workers:
            w.join(max(0.0, deadline - time.monotonic()))
        if any(w.is_alive() for w in workers) or failed.is_set():
            raise AuthError.from_reason("HELPER_PROTOCOL")
        try:
            reply = json.loads(output.get("stdout", b"").decode("utf-8"))
        except (ValueError, UnicodeError):
            raise AuthError.from_reason("HELPER_PROTOCOL") from None
        if not isinstance(reply, dict) or reply.get("version") != 1:
            raise AuthError.from_reason("HELPER_PROTOCOL")
        if reply.get("ok") is False and proc.returncode == 1:
            reason = reply.get("reason")
            raise AuthError.from_reason(reason if reason in AUTH_REASONS else "HELPER_PROTOCOL")
        if reply.get("ok") is not True or proc.returncode != 0:
            raise AuthError.from_reason("HELPER_PROTOCOL")
        if request["operation"] == "decrypt":
            if set(reply) != {"version", "ok", "accessToken"} or not _valid_token(reply.get("accessToken")):
                raise AuthError.from_reason("HELPER_PROTOCOL")
        elif set(reply) != {"version", "ok", "electron"} or not isinstance(reply.get("electron"), str):
            raise AuthError.from_reason("HELPER_PROTOCOL")
        return reply
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        for w in workers:
            if w.ident is not None:
                w.join(1)
        if not any(w.is_alive() for w in workers):
            for pipe in (proc.stdin, proc.stdout, proc.stderr):
                try:
                    pipe.close()
                except OSError:
                    pass


def _envelope_kind(value):
    """判断 accessToken 是明文还是加密信封；只做格式校验，不解密。"""
    if isinstance(value, str):
        if not _valid_token(value):
            raise AuthError.from_reason("INVALID_FORMAT")
        return "plaintext"
    if not isinstance(value, dict):
        raise AuthError.from_reason("INVALID_FORMAT")
    if set(value) != {"$wbEncrypted", "envelope"} or value.get("$wbEncrypted") != 1:
        raise AuthError.from_reason("UNSUPPORTED_ENVELOPE")
    try:
        encoded = value["envelope"]
        if not isinstance(encoded, str) or not 0 < len(encoded) <= AUTH_INPUT_LIMIT - 1024:
            raise ValueError()
        raw = base64.b64decode(encoded, validate=True)
        if base64.b64encode(raw).decode("ascii") != encoded:
            raise ValueError()
        envelope = json.loads(raw.decode("utf-8"))
        if not isinstance(envelope, dict) or envelope.get("suite") != 1:
            raise ValueError()
        if set(envelope) != {"suite", "keyId", "nonce", "authTag", "ciphertext"}:
            raise ValueError()
        if not isinstance(envelope["keyId"], str) or not re.fullmatch(r"[0-9a-f]{16}", envelope["keyId"]):
            raise ValueError()
        for field, length in (("nonce", 12), ("authTag", 16), ("ciphertext", None)):
            data = envelope[field]
            if not isinstance(data, str):
                raise ValueError()
            decoded = base64.b64decode(data, validate=True)
            if (base64.b64encode(decoded).decode("ascii") != data
                    or (length is not None and len(decoded) != length)):
                raise ValueError()
        return "sym-v1"
    except AuthError:
        raise
    except (ValueError, TypeError, KeyError):
        raise AuthError.from_reason("INVALID_FORMAT") from None


def find_auth_file(args, log: Log):
    """按优先级定位凭据文件：--auth-file > WORKBUDDY_AUTH_FILE > 平台候选路径。

    返回 (path, looked_in)；looked_in 是实际检查过的路径，NO_AUTH 时用于提示。
    """
    if getattr(args, "auth_file", None):
        p = os.path.abspath(os.path.expanduser(args.auth_file))
        return (p if os.path.isfile(p) else None), [p]
    override = os.environ.get("WORKBUDDY_AUTH_FILE")
    if override:
        p = os.path.abspath(os.path.expanduser(override))
        return (p if os.path.isfile(p) else None), [p]

    home = os.path.expanduser("~")
    local = os.environ.get("LOCALAPPDATA") or os.path.join(home, "AppData", "Local")
    xdg_data = os.environ.get("XDG_DATA_HOME") or os.path.join(home, ".local", "share")
    candidates = [
        os.path.join(local, AUTH_REL_BASENAME),                                    # Windows 桌面端
        os.path.join(home, "Library", "Application Support", AUTH_REL_BASENAME),  # macOS 桌面端
        os.path.join(xdg_data, "CodeBuddyExtension", "Data", "Public", "auth",
                     "Tencent-Cloud.coding-copilot.info"),                       # Linux CodeBuddy CLI
        os.path.join(home, ".config", AUTH_REL_BASENAME),
        os.path.join(home, ".workbuddy", "auth", "workbuddy-desktop.info"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c, candidates
    return None, candidates


def load_session(path, log: Log, attempts=3, delay=2.0):
    """读取并解析凭据 JSON；对 PermissionError 重试。

    客户端刷新 token 时会短暂独占该文件，定时任务极易撞上这个窗口——
    锁是瞬时的，等两秒再读即可，不必因此判定当天失败。
    """
    last = None
    for i in range(attempts):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except PermissionError as e:
            last = e
            if i < attempts - 1:
                # 客户端刷新 token 时会短暂独占该文件，锁是瞬时的，等一下再读
                log.warn(f"凭据文件被占用（客户端正在刷新 token），{delay:g}s 后重试"
                         f"（第 {i + 1} 次）")
                time.sleep(delay)
    raise last


def validate_session(session):
    """校验会话结构；缺失字段一律报 NO_SESSION 类错误，不静默继续。"""
    if not isinstance(session, dict):
        raise AuthError.from_reason("INVALID_FORMAT")
    for field in ("auth", "account"):
        if not isinstance(session.get(field), dict):
            raise AuthError.from_reason("INVALID_FORMAT")
    auth = session["auth"]
    if auth.get("accessToken") in (None, "") or session["account"].get("uid") in (None, ""):
        raise AuthError(
            "登录态缺少必要字段（accessToken / uid）",
            hint="请先在本机登录 WorkBuddy 桌面端，让客户端重建凭据文件后再重跑。",
            reason="NO_SESSION",
        )
    return auth, session["account"]


def resolve_session(session, log: Log):
    """返回可用的 (auth, account)，accessToken 已是明文。"""
    auth, account = validate_session(session)
    raw = auth["accessToken"]
    if _envelope_kind(raw) == "plaintext":
        return auth, account
    log.info("accessToken 为加密信封，正在通过 WorkBuddy 客户端解密……")
    token = run_auth_helper({"operation": "decrypt", "value": raw}, log)["accessToken"]
    return dict(auth, accessToken=token), account


def build_headers(auth, account):
    """构造请求头：与官方桌面端保持一致。"""
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {auth['accessToken']}",
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
    }
    uid = account.get("uid")
    if isinstance(uid, str) and uid:
        headers["X-User-Id"] = uid
    ent = account.get("enterpriseId")
    if isinstance(ent, str) and ent:
        headers["X-Enterprise-Id"] = ent
        headers["X-Tenant-Id"] = ent
    domain = auth.get("domain")
    if isinstance(domain, str) and domain:
        headers["X-Domain"] = domain
    return headers


def resolve_endpoint(session, args, log: Log):
    """endpoint 优先级：--base-url > 凭据里的 auth.endpoint > 默认值。"""
    if args.base_url:
        return args.base_url.rstrip("/")
    ep = (session.get("auth") or {}).get("endpoint")
    if isinstance(ep, str) and ep.startswith("https://"):
        return ep.rstrip("/")
    return DEFAULT_ENDPOINT


def _parse_body(raw, http_code, url):
    """解析响应体；非 JSON / 结构异常时抛出带原文片段的 ApiError。"""
    if not raw:
        return {}
    try:
        body = json.loads(raw)
    except json.JSONDecodeError:
        snippet = " ".join(raw.split())[:200]
        raise ApiError(
            f"接口返回非 JSON 响应（HTTP {http_code}，{url}）: {snippet}",
            hint="若为 401/403 或 HTML 页面，通常是登录态失效或域名被网关拦截。",
        ) from None
    if not isinstance(body, dict):
        raise ApiError(f"接口响应结构异常（HTTP {http_code}，顶层 {type(body).__name__}）")
    return body


def http_post(base_url, path, headers, timeout, log: Log, retries=DEFAULT_RETRIES):
    """发送 POST 请求，返回 (http_code, body_dict)。

    - 401 → 立即抛 AuthError（登录态问题，重试无意义）
    - 403 → 单独提示：多为权限 / 活动条件不满足，不能一概当成登录过期
    - 网络失败 / 5xx → 指数退避重试，最多 retries 次
    - 其余 4xx → 原样返回响应体，交给业务层判断（例如「已签到」是 HTTP 400）
    """
    url = base_url.rstrip("/") + path
    last_reason = None

    for attempt in range(max(retries, 0) + 1):
        req = urllib.request.Request(url, data=b"{}", headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                http_code = resp.getcode()
                raw = resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            http_code = e.code
            try:
                raw = e.read().decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                raw = ""
            if http_code == 401:
                raise AuthError(
                    f"服务端拒绝认证（HTTP 401）：{url}",
                    hint="请打开 WorkBuddy 客户端确认已登录，让客户端刷新 token 后重跑本脚本。",
                ) from e
            if http_code == 403:
                raise AuthError(
                    f"服务端拒绝此操作（HTTP 403）：{url}",
                    hint="这通常不是登录过期，而是账号权限或活动条件不满足"
                         "（如连登兑换「进阶」档位未解锁）。",
                ) from e
            if http_code >= 500 and attempt < retries:
                last_reason = f"服务端返回 HTTP {http_code}"
                _sleep_before_retry(attempt, log, last_reason)
                continue
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

        return http_code, _parse_body(raw, http_code, url)

    raise NetworkError(last_reason or "网络请求失败", hint="已重试全部次数仍失败。")


def _status_data(base_url, headers, timeout, log: Log, retries):
    """查询今日签到状态，返回 (body, data)；data 兼容信封结构。"""
    http_code, body = http_post(base_url, STATUS_PATH, headers, timeout, log, retries)
    if not 200 <= http_code < 300:
        raise ApiError(
            f"状态查询失败: HTTP {http_code} code={body.get('code')} msg={body.get('msg')}"
        )
    data = body.get("data")
    if not isinstance(data, dict):
        data = body  # 字段直接摊在顶层的形态
    return body, data


def _pick_points(body):
    """积分字段名历史上不稳定（顶层 credit / data.today_credit …），按优先级取值。"""
    for key in ("credit", "today_credit", "daily_credit", "points", "add_credit"):
        val = dig(body, key)
        if isinstance(val, (int, float)) and val != 0:
            return val
    return None


def _is_already_signed(body):
    """领取接口返回是否表示「今日已签」。兼容 null 与 400 + code 10001。"""
    if body is None:
        return True
    if isinstance(body, dict):
        if body.get("code") == 10001 or "已签" in (body.get("msg") or ""):
            return True
    return False


def do_checkin(base_url, headers, timeout, log: Log, retries):
    """执行签到，返回结果字典。领取接口幂等：今日重复领取只会返回「已签」。"""
    http_code, body = http_post(base_url, CHECKIN_PATH, headers, timeout, log, retries)
    if _is_already_signed(body):
        return {"action": "already_signed", "ok": True, "points": None,
                "msg": (body or {}).get("msg") or "今天已签到"}
    credit = _pick_points(body)
    if credit is not None or 200 <= http_code < 300:
        return {"action": "checked_in", "ok": True, "points": credit,
                "msg": (body or {}).get("msg") or "OK"}
    raise ApiError(f"签到失败: HTTP {http_code} code={body.get('code')} msg={body.get('msg')}")


def do_claim_gift(base_url, headers, timeout, log: Log, retries):
    """（可选）领取今日礼包。已领取视为成功，不影响主流程退出码。"""
    http_code, body = http_post(base_url, GIFT_PATH, headers, timeout, log, retries)
    msg = body.get("msg", "") or ""
    if 200 <= http_code < 300:
        return {"ok": True, "points": _pick_points(body), "msg": msg or "OK"}
    # 幂等：已领取不算失败。按语义关键字判断，不复用签到接口的 10001。
    if "已领" in msg or "领过" in msg or body.get("code") == 10001:
        return {"ok": True, "points": None, "msg": msg or "今日礼包已领取"}
    return {"ok": False, "points": None,
            "msg": f"HTTP {http_code} code={body.get('code')} msg={msg}"}


# ------------------------- 成长中心：基础工具 -------------------------
# 伪 HTTP 码：区分「没拿到响应」的两种原因
CODE_NO_NETWORK = -1   # 连不上 / 超时
CODE_BUDGET_OUT = -2   # 本次运行的时间预算已耗尽，主动放弃后续请求

# 本次运行的网络请求时间预算。签到 + 成长中心一整轮最坏要打十几个接口，
# 退避重试又会把单次请求拉长到几十秒，没有预算就会被系统强杀（Windows 计划任务
# 有 ExecutionTimeLimit；macOS launchd 没有，但预算仍是唯一的兜底），
# 结果是最后的输出根本没写出来。
DEFAULT_BUDGET_SECONDS = 240.0
MIN_BUDGET_SECONDS = 30.0
MAX_BUDGET_SECONDS = 420.0

_budget_started_at = None
_budget_seconds = DEFAULT_BUDGET_SECONDS


def parse_budget():
    """解析 WORKBUDDY_BUDGET_SECONDS；非法值一律夹到安全区间，绝不在这里抛异常。

    这段逻辑必须留在函数内：写成模块级的话，环境变量配错会让进程在 main() 的
    try/except 生效之前就崩掉，失败当天连错误信息都看不到。
    """
    raw = os.environ.get("WORKBUDDY_BUDGET_SECONDS")
    if not raw:
        return DEFAULT_BUDGET_SECONDS, None
    try:
        val = float(raw)
    except (TypeError, ValueError):
        return DEFAULT_BUDGET_SECONDS, (
            f"WORKBUDDY_BUDGET_SECONDS={raw!r} 不是数字，已回落 "
            f"{int(DEFAULT_BUDGET_SECONDS)} 秒")
    if val <= 0:
        # "0" 是非空字符串，用 `or` 兜不住；且 0 会让每个请求都直接放弃，脚本永久失效
        return DEFAULT_BUDGET_SECONDS, (
            f"WORKBUDDY_BUDGET_SECONDS={raw} 必须为正数，已回落 "
            f"{int(DEFAULT_BUDGET_SECONDS)} 秒")
    if val < MIN_BUDGET_SECONDS:
        return MIN_BUDGET_SECONDS, (
            f"WORKBUDDY_BUDGET_SECONDS={raw} 过小，已夹到 {int(MIN_BUDGET_SECONDS)} 秒")
    if val > MAX_BUDGET_SECONDS:
        return MAX_BUDGET_SECONDS, (
            f"WORKBUDDY_BUDGET_SECONDS={raw} 超过上限，已夹到 "
            f"{int(MAX_BUDGET_SECONDS)} 秒")
    return val, None


def start_budget():
    """启动预算时钟；配置非法时返回告警文案，由调用方带进输出。"""
    global _budget_started_at, _budget_seconds
    _budget_seconds, warning = parse_budget()
    _budget_started_at = time.monotonic()
    return warning


def budget_left():
    """本次运行还剩多少秒可用于网络请求。"""
    if _budget_started_at is None:
        return _budget_seconds
    return _budget_seconds - (time.monotonic() - _budget_started_at)


def _as_int(value, default=0):
    """把可能为字符串的数字安全地转成 int。

    OverflowError 必须一并捕获：json.loads 默认接受 Infinity，服务端返回该字面量时
    value 已经是 float('inf')，int() 抛的是 OverflowError 而非 ValueError。
    """
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        pass
    try:
        return int(float(value))  # 兼容 "1.5"/"1e3"，宁可截断也不把真实数值丢成 0
    except (TypeError, ValueError, OverflowError):
        return default


def _fmt_credit(value):
    """积分展示用：能转 int 就转，否则原样返回。"""
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return value


def _client_token(prefix="u"):
    """活动接口（抽奖 / 连登兑换 / 补登）要求的防重放 token。

    官方前端用 crypto.randomUUID() 拼成 "u-<uuid>"，服务端只做幂等去重、不校验
    格式；缺了它 /lottery/draw 会直接 400（实测过）。
    """
    return f"{prefix}-{uuid.uuid4()}"


def _fmt_eta(arrive_at, server_now):
    """把服务端时间戳换算成「还有多久回来」。

    任何时间戳缺失 / 非法就返回空串——这纯是展示信息，绝不能因为它让整轮执行失败。
    """
    try:
        left = float(arrive_at) - float(server_now)
    except (TypeError, ValueError, OverflowError):
        return ""
    if not math.isfinite(left):
        return ""
    if left <= 0:
        return "，已到达待领取"
    # 先算分钟再决定量纲：直接按 left < 3600 分档会让 3599s 显示成「约 60 分钟」
    minutes = int(round(left / 60.0))
    if minutes < 60:
        return f"，约 {max(1, minutes)} 分钟后回"
    return f"，约 {left / 3600.0:.1f} 小时后回"


# 退避节奏（秒）。定时任务最容易撞上的失败是「刚开机/刚唤醒」：WiFi 重连、DHCP
# 续租、VPN 拨通往往要几十秒，早期那种「5 秒后再试一次」几乎撞在同一堵墙上。
NETWORK_RETRY_DELAYS = (5, 15, 30)
# 5xx 是服务端抖动，不是本机网络没就绪，短促重试即可——干等几分钟既救不了它，
# 还会把预算耗光，让后面的模块一个都跑不成。
SERVER_RETRY_DELAYS = (3, 10)
GROWTH_TIMEOUT = 15


def _growth_request(url, headers, method="GET", payload=None, log: Log = None):
    """成长中心用的单次请求，返回 (code, body)；网络失败返回 CODE_NO_NETWORK。

    不抛异常：成长中心要逐段判断「该不该继续」，异常会让整个流程崩掉。
    """
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=GROWTH_TIMEOUT) as resp:
            raw = resp.read().decode("utf-8", "replace")
            return resp.getcode(), _safe_json(raw)
    except urllib.error.HTTPError as e:
        try:
            raw = e.read().decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            raw = ""
        return e.code, _safe_json(raw)
    except urllib.error.URLError as e:
        return CODE_NO_NETWORK, {"error": str(e.reason)}
    except Exception as e:  # noqa: BLE001
        return CODE_NO_NETWORK, {"error": str(e)}


def _safe_json(raw):
    """解析响应体；非 JSON 时返回带原文片段的 dict，绝不抛异常。"""
    if not raw:
        return {}
    try:
        body = json.loads(raw)
    except json.JSONDecodeError:
        return {"raw": " ".join(raw.split())[:200]}
    return body if isinstance(body, dict) else {"raw": str(body)[:200]}


def _retry_delays(code):
    """该失败码对应的退避节奏；空元组表示「重试也没用」，立刻如实返回。"""
    if code == CODE_NO_NETWORK:
        return NETWORK_RETRY_DELAYS
    if code >= 500:
        return SERVER_RETRY_DELAYS
    return ()


def growth_get(url, headers, log: Log = None, retry=True):
    """带预算的 GET。返回 CODE_BUDGET_OUT 表示「没发出去，因为再发就要超时了」。"""
    if budget_left() <= 1:
        return CODE_BUDGET_OUT, {"error": "已达本次运行时间预算，跳过剩余请求"}
    code, body = _growth_request(url, headers, "GET", None, log)
    if not retry:
        return code, body

    # 退避进度按「失败类型」分桶，而不是一个全局计数：失败类型会在重试途中变化，
    # 典型的是冷启动——前几次网络不可达，之后转成 500（代理还没就绪）。全局计数
    # 会让这种 5xx 撞上已用光的计数，一次都重试不到。
    attempts = {}
    while True:
        delays = _retry_delays(code)
        if not delays:
            return code, body
        used = attempts.get(delays, 0)
        if used >= len(delays):
            return code, body
        delay = delays[used]
        attempts[delays] = used + 1
        # 一轮重试最坏要占掉 delay + 一整个超时，预算不够就别开始：宁可现在如实
        # 返回失败，也不能跑穿时限——那样连日志都写不出来。
        if budget_left() <= delay + GROWTH_TIMEOUT:
            return code, body
        time.sleep(delay)
        code, body = _growth_request(url, headers, "GET", None, log)


def growth_post(url, headers, payload=None, log: Log = None, retry=False):
    """带预算的 POST。默认**不重试**：抽奖/领奖等写操作若在服务端处理完成后才超时，
    重试会重复提交。只有调用方明确知道接口幂等时才传 retry=True。"""
    if budget_left() <= 1:
        return CODE_BUDGET_OUT, {"error": "已达本次运行时间预算，跳过剩余请求"}
    code, body = _growth_request(url, headers, "POST", payload, log)
    if not retry:
        return code, body
    delays = _retry_delays(code)
    for delay in delays:
        if budget_left() <= delay + GROWTH_TIMEOUT:
            break
        time.sleep(delay)
        code, body = _growth_request(url, headers, "POST", payload, log)
        if not _retry_delays(code):
            break
    return code, body


def _is_hard_failure(code):
    """是否属于「需要人关注」的失败。

    5xx 与「没拿到响应」算硬失败；4xx 绝大多数是业务规则（如派 Buddy 已达每日
    上限、活动已结束、兑换档位未解锁），属于每天的正常状态，若计入退出码会让
    计划任务天天报红。
    """
    return code >= 500 or code in (CODE_NO_NETWORK, CODE_BUDGET_OUT)


def _http_label(code):
    """把伪 HTTP 码翻译成人话；-1/-2 是脚本自定义的「没拿到响应」标记。"""
    if code == CODE_NO_NETWORK:
        return "网络不可达"
    if code == CODE_BUDGET_OUT:
        return "时间预算耗尽"
    return f"HTTP {code}"


def _is_no_chance(msg):
    """抽奖失败是否只是「没有次数」——这是常态，不是故障。

    服务端对「次数为 0」返回 400 + `insufficient lottery chance balance`，和真正的
    参数错误（`invalid request`）同为 400，只看状态码会把两者混为一谈。
    """
    m = str(msg or "").lower()
    if not m:
        return False
    if "insufficient" in m or "not enough" in m:
        return "chance" in m or "balance" in m
    return "no chance" in m


def _is_unknown_tier(code, body):
    """连登兑换是否因为「tier 这个值本身不认识」被拒——用于判断要不要换写法重试。

    这类 400 发生在参数校验阶段，服务端没兑换任何东西，重试不会重复领取；
    `invalid request` 这类业务拒绝不在此列，不能重试。
    """
    if code != 400:
        return False
    m = str(dig(body, "msg") or "").lower()
    return "tier" in m and ("unknown" in m or "unsupported" in m or "invalid" in m)


def _is_tier_locked(code, body):
    """未解锁档位：403 + 「连续登录天数不足」——这是常态，不是故障。

    不加这条的话，未解锁档位会被计进失败，让每次运行都判定「有失败」。
    """
    if code != 403:
        return False
    m = str(dig(body, "msg") or "")
    return "天数不足" in m or "不足" in m


def _redeem_reward_desc(body, tier):
    """兑换成功的奖励描述：优先拼服务端实发的 *_granted，挖不到才回落官方文案。

    注意实发字段名带 _granted 后缀（credit_granted / energy_granted /
    cards_granted / chances_granted）；直接读 `credit` 恒为空，会把兑换所得漏计。
    """
    bits = []
    for field, unit in (("credit_granted", "积分"), ("energy_granted", "能量"),
                        ("cards_granted", "补登卡"), ("chances_granted", "次抽奖")):
        val = _as_int(dig(body, field), 0)
        if val:
            bits.append(f"+{_fmt_credit(val)} {unit}")
    if bits:
        return "（" + " ".join(bits) + "）"
    return f"（{REDEEM_REWARDS.get(tier, '奖励已到账')}）"


def _first_int(body, key, fallback=0):
    """优先取响应里的实际数值，挖不到才用回落值。

    任务列表里的 reward_credit 只是活动配置，与服务端这次实际发放的可能不同；
    上报按响应值才不会虚报。
    """
    if isinstance(body, dict):
        val = dig(body, key)
        if val is not None:
            return _as_int(val)
    return _as_int(fallback)


class GrowthAbort(Exception):
    """成长中心需要提前收尾时抛出（网络不可达 / 认证被拒）。

    只带固定文案，绝不把响应体或 token 带进异常消息。
    """

    def __init__(self, kind, report):
        super().__init__(report)
        self.kind = kind
        self.report = report


class GrowthRunner:
    """成长中心自动化：领旅行礼物→派 Buddy→领任务→补登→连登兑换→开盲盒→开 Buddy。

    各子步骤单独 try，一段失败不影响其余领取；认证 / 权限拒绝时结束整轮。
    用类而非一长串全局变量，是为了把 parts / 计数器的状态收在一起——参考实现的
    同名逻辑散在一堆 nonlocal 上，任何一处漏改都会静默算错。
    """

    def __init__(self, endpoint, headers, log: Log):
        self.base = endpoint.rstrip("/") + GROWTH_PATH
        self.headers = headers
        self.log = log
        self.parts = []
        self.credits = 0
        self.successes = 0
        self.failures = 0
        self.hard_failures = 0
        # 最近一次写请求的状态码，供 lose() 判断要不要记成硬失败
        self._last_code = 200
        # /streak 的复用：同一轮里没必要打两次，补登成功会让它过期
        self.streak_body = None
        self.streak_stale = False

    # ---------- 记账 ----------
    def say(self, text):
        self.parts.append(text)

    def win(self, text, credit=0):
        self.parts.append(text)
        self.successes += 1
        self.credits += _as_int(credit, 0)

    def lose(self, text, hard=False):
        """记录一次失败。hard=True 才会影响最终退出码。"""
        self.parts.append(text)
        self.failures += 1
        if hard or _is_hard_failure(self._last_code):
            self.hard_failures += 1

    def note_http(self, code, body, label):
        """前置查询接口非 2xx 时的统一记录；返回 True 表示调用方应跳过后续处理。

        硬失败（5xx / 网络不可达 / 预算耗尽）必须计入 failures：否则整轮
        successes=0 且 failures=0 会被判成「空跑」，服务端故障就彻底无声无息了。

        4xx 只进报告、不计失败：绝大多数是业务规则（活动未开始、接口下线、
        今日名额已用完），计入会让每次运行都判定「有失败」。
        """
        self._last_code = code
        if 200 <= code < 300:
            return False
        reason = _http_label(code)
        detail = ""
        if isinstance(body, dict):
            detail = str(body.get("error") or body.get("msg") or "")
        # 状态码与服务端给的详情都保留：只知道 500 无法判断影响，只知道 "timed out"
        # 又看不出是网络还是服务端，两者在汇报里都想要
        if detail and detail != reason:
            self.say(f"{label}失败：{reason}（{detail}）")
        else:
            self.say(f"{label}失败：{detail or reason}")
        if _is_hard_failure(code):
            self.failures += 1
            self.hard_failures += 1
        return True

    def auth_blocked(self, code):
        """是否因认证 / 权限被拒而应终止整轮。"""
        return code in (401, 403)

    # ---------- 1. Buddy 旅行：领礼物 + 派出发 ----------
    def run_travel(self):
        url = self.base + "/buddy/travel/status"
        code, body = growth_get(url, self.headers, self.log)
        if code == CODE_BUDGET_OUT:
            self.say("时间预算耗尽，Buddy 旅行跳过")
            return
        if code == CODE_NO_NETWORK:
            # 网络不可达就立刻收手，别把后面 5 个接口的重试 + 等待全跑一遍。
            # 细节写进 abort 的 report，run_growth 会统一拼到汇报里，这里不再 say。
            detail = body.get("error") or ""
            raise GrowthAbort("NETWORK",
                              f"网络不可达，成长中心跳过（{detail}）" if detail
                              else "网络不可达，成长中心跳过")
        if self.auth_blocked(code):
            raise GrowthAbort("AUTH", f"服务端拒绝请求（{_http_label(code)}），成长中心跳过")

        state = dig(body, "state") if 200 <= code < 300 else None
        # 服务端明确给出「今日旅行名额已用完」。读它而不是等 depart 报错，能省掉
        # 一次注定失败的写请求。
        daily_limit = (bool(dig(body, "daily_limit_reached"))
                       if 200 <= code < 300 else False)
        self.note_http(code, body, "查旅行状态")

        if state == "arrived":
            self._claim_travel_gift(body)
            # 只有领取成功后才视为 idle，允许派出发——否则会用新 Buddy 覆盖掉
            # 还没领的奖励
            if self._travel_claimed:
                state = "idle"

        if state == "idle" and daily_limit:
            # 今日名额已用完：直接收手，不碰 config/depart，省掉两个请求
            self.say("今日旅行名额已用完")
        elif state == "idle":
            self._depart_buddy()
        elif state == "traveling":
            loc = dig(body, "location") or {}
            loc_name = loc.get("name", "?") if isinstance(loc, dict) else "?"
            # arrive_at / server_now 是服务端时间戳，比本地时钟可靠
            self.say("Buddy 旅行中（%s%s）" % (
                loc_name, _fmt_eta(dig(body, "arrive_at"), dig(body, "server_now"))))

    def _claim_travel_gift(self, status_body):
        self._travel_claimed = False
        record_id = dig(status_body, "record_id")
        code, body = growth_post(self.base + "/buddy/travel/claim", self.headers,
                                 {"record_id": record_id}, self.log)
        if self.auth_blocked(code):
            raise GrowthAbort("AUTH", f"服务端拒绝请求（{_http_label(code)}），成长中心跳过")
        if 200 <= code < 300 and dig(body, "reward_credit") is not None:
            got = _as_int(dig(body, "reward_credit"))
            self.win(f"领旅行礼物 +{_fmt_credit(got)} 积分", credit=got)
            self._travel_claimed = True
        else:
            # 领失败：带出业务 msg，不再说「HTTP 200」；也不派 Buddy，避免覆盖未领奖励
            msg = dig(body, "msg") or ""
            self._last_code = code
            self.lose(f"领旅行礼物失败：{msg or f'HTTP {code}'}")

    def _depart_buddy(self):
        code, body = growth_get(self.base + "/buddy/travel/config", self.headers, self.log)
        if self.auth_blocked(code):
            raise GrowthAbort("AUTH", f"服务端拒绝请求（{_http_label(code)}），成长中心跳过")
        locs = dig(body, "locations") if 200 <= code < 300 else None
        if not (locs and isinstance(locs[0], dict)):
            return
        loc = locs[0]
        code, body = growth_post(self.base + "/buddy/travel/depart", self.headers,
                                 {"location_id": loc.get("id")}, self.log)
        if self.auth_blocked(code):
            raise GrowthAbort("AUTH", f"服务端拒绝请求（{_http_label(code)}），成长中心跳过")
        if 200 <= code < 300:
            loc_info = dig(body, "location") or {}
            loc_name = loc_info.get("name", "?") if isinstance(loc_info, dict) else "?"
            dur = (dig(body, "duration_hours")
                   or (loc_info.get("duration_hours", "?") if isinstance(loc_info, dict)
                       else "?"))
            self.win(f"派 Buddy 去{loc_name}（{dur} 小时后回）")
        else:
            msg = dig(body, "msg") or ""
            self._last_code = code
            self.lose(f"派 Buddy 失败：{msg or f'HTTP {code}'}")

    # ---------- 2. 任务领奖（放在抽奖前：任务送的抽奖机会 / 能量后面马上能用上）----------
    def run_tasks(self):
        if budget_left() <= 0:
            self.say("时间预算耗尽，任务领奖跳过")
            return
        code, body = growth_get(self.base + "/tasks", self.headers, self.log)
        if self.auth_blocked(code):
            raise GrowthAbort("AUTH", f"服务端拒绝请求（{_http_label(code)}），成长中心跳过")
        if self.note_http(code, body, "查任务列表"):
            return
        tasks = dig(body, "tasks") or []
        if not isinstance(tasks, list):
            return

        # 真实契约（2026-09 从桌面端成长中心 H5 的 growthSpace chunk 读出）：
        #   accept_status: not_accepted | accepted | in_progress | completed | claimed
        #   接单 POST /tasks/accept  body {"task_codes": [code, ...]}   ← 复数数组
        #        （旧的单数 {"task_code": x} 在新服务端一律 400 invalid request）
        #   领奖 POST /tasks/{task_code}/claim   ← 路径带 code、body 空
        titles = {t.get("task_code"): t.get("title", t.get("task_code"))
                  for t in tasks if isinstance(t, dict)}
        self._accept_tasks(tasks, titles)
        self._claim_task_rewards(tasks, titles)

    def _accept_tasks(self, tasks, titles):
        pending = [t.get("task_code") for t in tasks
                   if isinstance(t, dict) and t.get("task_code") and not t.get("locked")
                   and t.get("accept_status") == "not_accepted"]
        for i in range(0, len(pending), 20):   # 分批，别把 body 撑大
            if budget_left() <= 0:
                self.say("时间预算耗尽，剩余任务下次再接单")
                return
            batch = pending[i:i + 20]
            code, body = growth_post(self.base + "/tasks/accept", self.headers,
                                     {"task_codes": batch}, self.log)
            if self.auth_blocked(code):
                raise GrowthAbort("AUTH", f"服务端拒绝请求（{_http_label(code)}），成长中心跳过")
            self._last_code = code
            # 逐条读 results：接单失败必须报出来（常见 "prerequisite not met:
            # first_buddy (no buddy instance found)"），静默吞掉的话接口坏了也没人知道。
            results = dig(body, "results")
            if not isinstance(results, list):
                results = [{"task_code": c,
                            "status": "ok" if 200 <= code < 300 else "error",
                            "message": dig(body, "msg")} for c in batch]
            for r in results:
                if not isinstance(r, dict):
                    continue
                title = titles.get(r.get("task_code"), r.get("task_code"))
                if r.get("status") == "error":
                    self.lose(f"领取任务「{title}」失败："
                              f"{r.get('message') or f'HTTP {code}'}")
                else:
                    self.win(f"领取任务「{title}」（进度开始计）")

    def _claim_task_rewards(self, tasks, titles):
        for t in tasks:
            if budget_left() <= 0:
                self.say("时间预算耗尽，剩余任务奖下次再领")
                return
            if not isinstance(t, dict) or t.get("locked") or t.get("accept_status") != "completed":
                continue   # 只有 completed 才发奖，且走独立路径
            task_code = t.get("task_code")
            title = titles.get(task_code, task_code)
            code, body = growth_post(f"{self.base}/tasks/{task_code}/claim",
                                     self.headers, {}, self.log)
            if self.auth_blocked(code):
                raise GrowthAbort("AUTH", f"服务端拒绝请求（{_http_label(code)}），成长中心跳过")
            self._last_code = code
            if 200 <= code < 300 and not dig(body, "already_claimed"):
                # 优先用服务端实发数值；列表里的 reward_credit 只是活动配置，
                # 改版时会和实发对不上，挖不到才回落到列表值。
                credit = _first_int(body, "credit", t.get("reward_credit"))
                energy = _first_int(body, "energy", t.get("reward_energy"))
                self.win(f"领任务奖「{title}」+{credit} 积分+{energy} 能量", credit=credit)
            elif 200 <= code < 300:
                self.say(f"任务奖「{title}」已领过")
            else:
                self.lose(f"领任务奖「{title}」失败：{dig(body, 'msg') or f'HTTP {code}'}")

    # ---------- 3. 补登卡：断登自动补一张，保住连登 ----------
    def run_makeup(self):
        """官方规则：补登卡上限 4 张、仅可补救当月断登；/streak 的 makeup_dates
        是服务端算好的可补日期。卡攒着不花，超上限后新卡也拿不到，断登优先补。

        放在连登兑换之前：补登会改变连登天数，先补，兑换才能拿到最新解锁状态。
        """
        if budget_left() <= 0:
            self.say("时间预算耗尽，补登跳过")
            return
        code, body = growth_get(self.base + "/streak", self.headers, self.log)
        if self.auth_blocked(code):
            raise GrowthAbort("AUTH", f"服务端拒绝请求（{_http_label(code)}），成长中心跳过")
        if self.note_http(code, body, "查连登状态"):
            return
        self.streak_body = body

        # 余额兼容两种形状：{"makeup_cards":{"balance":2}} 与 {"makeup_cards":2}。
        # 只认前者的话，接口是后者时整个补登会一声不响地永不执行。
        cards_obj = dig(body, "makeup_cards")
        cards = (_as_int(cards_obj.get("balance")) if isinstance(cards_obj, dict)
                 else _as_int(cards_obj))
        # 实测 makeup_dates 在 streak 对象内部（不在顶层），当前值为 []；
        # dig 只做顶层查找，这里手动下钻，两处都兜住以防接口调整。
        streak_obj = dig(body, "streak") or {}
        dates = ((streak_obj.get("makeup_dates") if isinstance(streak_obj, dict) else None)
                 or dig(body, "makeup_dates") or [])
        if cards <= 0 or not isinstance(dates, list) or not dates:
            return

        used = min(cards, MAKEUP_MAX_PER_RUN)
        for target in dates[:used]:
            if budget_left() <= 0:
                self.say("时间预算耗尽，剩余补登下次再做")
                break
            code, body = growth_post(self.base + "/makeup-cards/use", self.headers,
                                     {"target_date": target, "client_token": _client_token()},
                                     self.log)
            if self.auth_blocked(code):
                raise GrowthAbort("AUTH", f"服务端拒绝请求（{_http_label(code)}），成长中心跳过")
            self._last_code = code
            if 200 <= code < 300:
                cards -= 1
                self.streak_stale = True   # 天数变了，最后展示必须重新取
                # 优先报服务端给的余额，本地递减只是接口没给时的兜底
                left_obj = dig(body, "makeup_cards")
                left = (_as_int(left_obj.get("balance"), cards)
                        if isinstance(left_obj, dict) else _as_int(left_obj, cards))
                self.win(f"补登 {target}（剩 {left} 张卡）")
            else:
                msg = dig(body, "msg") or ""
                self.lose(f"补登 {target} 失败：{msg or f'HTTP {code}'}")
        if len(dates) > used and cards > 0:
            self.say(f"另有 {len(dates) - used} 天可补、剩 {cards} 张卡，下轮继续")

    # ---------- 4. 连登奖励兑换（入门 / 进阶 / 巅峰三档）----------
    def run_redeem(self):
        """入门 7 天、进阶 14 天、巅峰 28 天解锁。summary 只报 claimed/locked 两种
        已见状态；「非 claimed 且非 locked」即视为可兑换去尝试。

        tier 传的是**档位标识**（"7d"/"14d"/"28d"），不是天数也不是档位名：实测传
        "starter"/"7"/7 分别得到 unknown tier / unknown tier / invalid request，
        只有 "7d" 会 200。
        """
        if budget_left() <= 0:
            self.say("时间预算耗尽，连登兑换跳过")
            return
        code, body = growth_get(self.base + "/redeem/summary", self.headers, self.log)
        if self.auth_blocked(code):
            raise GrowthAbort("AUTH", f"服务端拒绝请求（{_http_label(code)}），成长中心跳过")
        if self.note_http(code, body, "查连登兑换"):
            return

        for tier, status_key, label, days in REDEEM_TIERS:
            if budget_left() <= 0:
                self.say("时间预算耗尽，剩余连登兑换下次再领")
                break
            status = dig(body, status_key + "_status")
            # 字段缺失（None）同样跳过：接口改版时不该对三档无脑 POST
            if not status or status in ("claimed", "locked"):
                continue
            code, body = growth_post(self.base + "/redeem", self.headers,
                                     {"tier": tier, "client_token": _client_token()},
                                     self.log)
            # 档位标识被判为未知时退回天数再试一次：这类 400 是参数校验阶段的拒绝，
            # 服务端没兑换任何东西，重试不会重复领取
            if _is_unknown_tier(code, body):
                code, body = growth_post(self.base + "/redeem", self.headers,
                                         {"tier": days, "client_token": _client_token()},
                                         self.log)
            # 403「连登天数不足」是业务常态，必须**先于** auth_blocked 判断：
            # 未解锁档位不应被当成权限拒绝并中止整个成长中心。
            if _is_tier_locked(code, body):
                self.say(f"连登兑换「{label}」未解锁（连登天数不足）")
                continue
            if self.auth_blocked(code):
                raise GrowthAbort("AUTH", f"服务端拒绝请求（{_http_label(code)}），成长中心跳过")
            self._last_code = code
            if 200 <= code < 300:
                self.win(f"连登兑换「{label}」{_redeem_reward_desc(body, tier)}",
                         credit=_as_int(dig(body, "credit_granted"), 0))
            else:
                msg = dig(body, "msg") or ""
                self.lose(f"连登兑换「{label}」失败：{msg or f'HTTP {code}'}")

    # ---------- 5. 盲盒 / 抽奖（draw 必须带 client_token，缺了会 400）----------
    def run_lottery(self):
        if budget_left() <= 0:
            self.say("时间预算耗尽，盲盒跳过")
            return
        code, body = growth_get(self.base + "/lottery/chances", self.headers, self.log)
        if self.auth_blocked(code):
            raise GrowthAbort("AUTH", f"服务端拒绝请求（{_http_label(code)}），成长中心跳过")
        chances = 0 if self.note_http(code, body, "查抽奖机会") \
            else _as_int(dig(body, "balance"))
        if chances <= 0:
            return

        code, body = growth_post(self.base + "/lottery/draw", self.headers,
                                 {"client_token": _client_token()}, self.log)
        if self.auth_blocked(code):
            raise GrowthAbort("AUTH", f"服务端拒绝请求（{_http_label(code)}），成长中心跳过")
        self._last_code = code
        if 200 <= code < 300:
            prize = dig(body, "prize_name") or dig(body, "prize") or "未知"
            if not isinstance(prize, str):
                # prize 可能是对象 / 数字；不转 str 会把一次已经中了的抽奖变成
                # 「模块异常」，奖品名和下面这句提醒双双丢失
                prize = str(prize)
            # 奖池含实物周边（冰箱贴 / 胸针 / 杯子），中奖后要用户自己去填收件信息，
            # 脚本代填不了也绝不该代填——但必须提醒，否则奖品会卡在未填地址状态。
            if dig(body, "need_address") or dig(body, "require_address"):
                prize += "（实物奖，需到成长中心填写收件信息）"
            self.win(f"开盲盒获得：{prize}")
            # 一轮只开一次：这条写路径不可逆，剩下的机会留给下一轮更稳妥
            if chances > 1:
                self.say(f"还剩 {chances - 1} 次抽奖机会，下轮继续")
        else:
            msg = dig(body, "msg") or ""
            if _is_no_chance(msg):
                # 次数为 0 是常态（次数来自连登兑换），不是故障
                self.say(f"开盲盒：{msg or '无抽奖机会'}")
            else:
                self.lose(f"开盲盒失败：{msg or f'HTTP {code}'}")

    # ---------- 6. Buddy 盲盒（能量攒够就开；能量没有其它消耗出口）----------
    def run_buddy_box(self):
        if budget_left() <= 0:
            self.say("时间预算耗尽，Buddy 盲盒跳过")
            return
        code, body = growth_get(self.base + "/buddy/quota", self.headers, self.log)
        if self.auth_blocked(code):
            raise GrowthAbort("AUTH", f"服务端拒绝请求（{_http_label(code)}），成长中心跳过")
        if self.note_http(code, body, "查 Buddy 能量"):
            return
        affordable = _as_int(dig(body, "affordable"))
        if affordable <= 0:
            return
        count = min(affordable, _as_int(dig(body, "max_open_count"), 1) or 1)
        code, body = growth_post(self.base + "/buddy/open", self.headers,
                                 {"count": count, "client_token": _client_token()}, self.log)
        if self.auth_blocked(code):
            raise GrowthAbort("AUTH", f"服务端拒绝请求（{_http_label(code)}），成长中心跳过")
        self._last_code = code
        if 200 <= code < 300:
            name = dig(body, "buddy") or dig(body, "name") or dig(body, "buddies")
            self.win(f"开 Buddy 盲盒 ×{count}（{name if isinstance(name, str) else '新 Buddy'}）")
        else:
            msg = dig(body, "msg") or ""
            self.lose(f"开 Buddy 盲盒失败：{msg or f'HTTP {code}'}")

    # ---------- 7. 展示值：能量 & 连签天数（纯展示，不计失败）----------
    def _collect_display(self):
        energy = None
        if budget_left() > 0:
            code, body = growth_get(self.base + "/energy", self.headers, self.log, retry=False)
            if 200 <= code < 300:
                energy = dig(body, "balance")
        # 第 3 段已经取过 /streak，没补登过就直接复用，别在同一轮里打两次同一个接口
        streak_obj = {}
        try:
            if self.streak_body is not None and not self.streak_stale:
                streak_obj = dig(self.streak_body, "streak") or {}
            elif budget_left() > 0:
                code, body = growth_get(self.base + "/streak", self.headers, self.log)
                if 200 <= code < 300:
                    streak_obj = dig(body, "streak") or {}
            streak_days = streak_obj.get("days") if isinstance(streak_obj, dict) else None
        except Exception:  # noqa: BLE001
            streak_days = None
        return energy, streak_days

    # ---------- 编排 ----------
    def run(self):
        """按顺序跑完 7 个模块，返回结构化结果。

        顺序有讲究：任务领奖排在抽奖前（任务送的抽奖机会 / 能量后面马上能用上），
        补登排在连登兑换前（补登会改变连登天数，先补才能拿到最新解锁状态）。
        """
        steps = (("旅行", self.run_travel), ("任务", self.run_tasks),
                 ("补登", self.run_makeup), ("连登兑换", self.run_redeem),
                 ("盲盒", self.run_lottery), ("Buddy 盲盒", self.run_buddy_box))
        for name, fn in steps:
            try:
                fn()
            except GrowthAbort:
                raise          # 网络 / 认证问题要中止整轮，不属于「某模块的意外」
            except Exception as e:  # noqa: BLE001
                self.say(f"{name}模块异常（{type(e).__name__}: {e}）")
                self.failures += 1
                self.hard_failures += 1

        energy, streak_days = self._collect_display()
        tail = []
        if energy is not None:
            tail.append(f"能量 {energy}")
        if streak_days is not None:
            tail.append(f"连签 {streak_days} 天")
        if self.credits:
            tail.append(f"本次 +共 {self.credits} 积分")

        if self.parts:
            report = "；".join(self.parts)
        elif self.failures:
            report = "成长中心各步骤均失败"
        else:
            report = "成长中心无可领取项"
        if tail:
            report += "（" + "，".join(tail) + "）"

        result = {
            "action": "growth",
            "report": report,
            "credits_gained": self.credits,
            "energy": energy,
            "streak_days": streak_days,
            # idle = 既没领到东西也没出错（Buddy 在路上 / 今日名额已用完 / 没有可领项）
            "idle": self.successes == 0 and self.failures == 0,
        }
        if self.failures:
            result["failures"] = self.failures
        return result


def run_growth(endpoint, headers, log: Log):
    """成长中心入口。返回 (exit_code, result_dict)。"""
    runner = GrowthRunner(endpoint, headers, log)
    try:
        result = runner.run()
    except GrowthAbort as e:
        # 提前收尾（网络不可达 / 认证被拒）：已领到的部分照常汇报，不吞掉
        report = e.report
        if runner.parts:
            report = "；".join(runner.parts) + "；" + report
        return 1, {"action": "growth", "report": report, "aborted": e.kind,
                   "credits_gained": runner.credits, "idle": False}
    # 只有「确有需要关注的失败且一件都没成」才算整体失败。派 Buddy 已达每日上限
    # 这类 4xx 是每天的常态，不能让定时任务天天报红。
    return (1 if runner.hard_failures and not runner.successes else 0), result









# ----------------------------- 输出 -----------------------------
def _emit(payload, args, log: Log):
    """统一输出：json 模式只往 stdout 写一行 JSON。"""
    if args.json:
        print(json.dumps(payload, ensure_ascii=False))
    return payload


def _fail(msg, args, log: Log, hint=None, exit_code=2, reason=None, extra=None):
    if args.json:
        payload = {"status": "error", "msg": msg}
        if hint:
            payload["hint"] = hint
        if reason:
            payload["reason"] = reason
        if extra:
            payload.update(extra)
        print(json.dumps(payload, ensure_ascii=False))
    else:
        log.err(msg)
        if hint:
            log.err(f"      建议：{hint}")
    return exit_code


def _report_auth_error(err, args, log: Log):
    """把凭据类异常统一转成退出码 + 结构化输出。

    NO_AUTH 额外带上 looked_in：用户排查「路径不对」时需要看到实际找过哪些地方。
    """
    extra = {"looked_in": [_pretty(p) for p in err.looked_in]} \
        if isinstance(err, NoAuthError) and err.looked_in else None
    reason = getattr(err, "reason", None)
    if isinstance(err, NoAuthError) and not reason:
        reason = "NO_AUTH"
    return _fail(str(err), args, log, hint=err.hint, exit_code=err.exit_code,
                 reason=reason, extra=extra)


def _claim_gift(result, args, log: Log, endpoint, headers):
    """把礼包结果并入 result；礼包失败不改变主流程退出码，但一定会被报告出来。"""
    try:
        g = do_claim_gift(endpoint, headers, args.timeout, log, args.retries)
    except CheckinError as e:
        g = {"ok": False, "points": None, "msg": str(e)}
    except Exception as e:  # noqa: BLE001
        g = {"ok": False, "points": None, "msg": f"未知异常: {e}"}
    result["gift"] = g
    if not args.json:
        if g["ok"]:
            pts = f"，+{g['points']} 积分" if g.get("points") else ""
            log.info(f"今日礼包：{g['msg']}{pts}")
        else:
            log.warn(f"今日礼包领取失败（不影响签到）：{g['msg']}")
    return g


# ----------------------------- 凭据装载 -----------------------------
class NoAuthError(CheckinError):
    """未找到凭据文件：单独一类，好让主流程统一转成 NO_AUTH 退出码。

    looked_in 始终带上实际检查过的路径，避免报错与代码实现漂移。
    """

    exit_code = 1

    def __init__(self, message, hint=None, looked_in=None):
        super().__init__(message, hint)
        self.looked_in = looked_in or []

    @classmethod
    def not_found(cls, looked_in, explicit):
        """按「是否用户显式指定路径」给出不同的建议。"""
        if explicit:
            hint = "指定的凭据文件不存在，请核对路径：" + (looked_in[0] if looked_in else "")
        else:
            hint = ("请先在本机登录 WorkBuddy 桌面端；或用 --auth-file / "
                    "WORKBUDDY_AUTH_FILE 指向 workbuddy-desktop.info。")
        return cls("未找到 WorkBuddy 登录凭据", hint=hint, looked_in=looked_in)


def load_credentials(args, log: Log):
    """返回 (endpoint, headers)。凭据不可用时抛 NoAuthError / AuthError。"""
    # 1) 显式 token：跳过整个文件与解密流程（排障 / CI 场景）
    token = args.token or os.environ.get("WORKBUDDY_ACCESS_TOKEN")
    if token:
        token = token.strip()
        if not _valid_token(token):
            raise AuthError.from_reason("INVALID_FORMAT")
        log.info("使用命令行 / 环境变量提供的 accessToken。")
        auth = {"accessToken": token, "domain": None, "endpoint": None}
        return resolve_endpoint({"auth": auth}, args, log), build_headers(auth, {})

    # 2) 从凭据文件读，必要时解密
    auth_file, looked_in = find_auth_file(args, log)
    if not auth_file:
        explicit = bool(getattr(args, "auth_file", None)
                        or os.environ.get("WORKBUDDY_AUTH_FILE"))
        raise NoAuthError.not_found(looked_in, explicit)

    log.info(f"使用登录态文件：{_pretty(auth_file)}")
    try:
        session = load_session(auth_file, log)
    except json.JSONDecodeError as e:
        raise AuthError(
            f"登录凭据文件不是合法 JSON（{e}）",
            hint="请重新登录一次 WorkBuddy 桌面端，让客户端重建凭据文件。",
        ) from e
    except OSError as e:
        raise AuthError(
            f"读取登录凭据失败（{type(e).__name__}）",
            hint="请检查文件权限，或重新登录 WorkBuddy 桌面端。",
        ) from e

    auth, account = resolve_session(session, log)
    return resolve_endpoint(session, args, log), build_headers(auth, account)


# ----------------------------- 离线体检 -----------------------------
def run_doctor(args, log: Log):
    """只验凭据格式与解密能力，不联网、不提取密钥。"""
    try:
        auth_file, looked_in = find_auth_file(args, log)
        if not auth_file:
            raise NoAuthError.not_found(
                looked_in, bool(getattr(args, "auth_file", None)
                                or os.environ.get("WORKBUDDY_AUTH_FILE")))
        session = load_session(auth_file, log)
        auth, _account = validate_session(session)
        kind = _envelope_kind(auth["accessToken"])
        out = {"status": "ok", "action": "doctor", "credential_format": kind,
               "auth_file": _pretty(auth_file),
               "report": "本地凭据格式有效；未验证服务端登录状态"}
        if kind == "sym-v1":
            out.update(runtime=find_runtime(),
                       electron_version=run_auth_helper({"operation": "probe"}, log)["electron"],
                       report="已识别加密凭据，运行时具备解密能力；"
                              "未提取密钥、未验证服务端登录状态")
    except CheckinError as e:
        return _report_auth_error(e, args, log)

    if not args.json:
        log.info(out["report"])
        if out.get("runtime"):
            log.info(f"客户端运行时：{out['runtime']}（Electron {out.get('electron_version')}）")
    _emit(out, args, log)
    return 0


# ----------------------------- 主流程 -----------------------------
def _summarize(status):
    """从状态响应里抽出汇报所需字段（统一用 dig，兼容信封结构）。"""
    return {
        "today_checked_in": dig(status, "today_checked_in") in (True, 1),
        "streak_days": dig(status, "streak_days"),
        "today_credit": dig(status, "today_credit") or dig(status, "daily_credit"),
        "total_credits": dig(status, "total_credits"),
        "is_streak_day": dig(status, "is_streak_day"),
        "theme_name": dig(status, "theme_name"),
        "activity_name": dig(status, "activity_name"),
    }


def build_parser():
    parser = argparse.ArgumentParser(
        description="WorkBuddy 每日自动签到脚本（单文件版）"
    )
    parser.add_argument("--base-url",
                        help=f"API 域名（默认取凭据里的 endpoint，或 {DEFAULT_ENDPOINT}）")
    parser.add_argument("--token", help="直接传入明文 accessToken（跳过凭据文件与解密）")
    parser.add_argument("--auth-file", help="凭据文件路径（workbuddy-desktop.info）")
    parser.add_argument("--doctor", action="store_true",
                        help="离线体检：只验凭据格式与解密能力，不联网")
    parser.add_argument("--dry-run", action="store_true",
                        help="只查询今日状态，不执行签到")
    parser.add_argument("--gift", action="store_true",
                        help="顺带领取「今日礼包」（今日已签到也会尝试领取）")
    parser.add_argument("--no-growth", action="store_true",
                        help="只签到，不跑成长中心（默认签到 + 成长中心都跑）")
    parser.add_argument("--growth-only", action="store_true",
                        help="只跑成长中心，不签到")
    parser.add_argument("--json", action="store_true",
                        help="仅输出机器可读 JSON 结果（stdout）")
    parser.add_argument("--quiet", "-q", action="store_true", help="静默模式")
    parser.add_argument("--timeout", type=int, default=15, help="请求超时(秒)")
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES,
                        help=f"网络失败/5xx 重试次数（默认 {DEFAULT_RETRIES}，0 表示不重试）")
    return parser


def run_checkin(args, log: Log, endpoint, headers):
    """签到 + 礼包。返回 (exit_code, result_dict)。result 为 None 表示不该继续。"""
    # 1) 查询状态
    body, status = _status_data(endpoint, headers, args.timeout, log, args.retries)

    # 活动未开启：非签到季，属正常，直接收工而不是当成失败
    if dig(body, "active") is False:
        name = dig(body, "activity_name")
        msg = "签到活动未开启" + (f"（{name}）" if name else "")
        if not args.json:
            log.info(msg)
        return 0, {"status": "ok", "action": "inactive", "msg": msg, "active": False}

    summary = _summarize(status)
    if not args.json:
        log.info(f"主题：{summary['theme_name']} / {summary['activity_name']}")
        log.info(f"今日是否已签到：{summary['today_checked_in']}　"
                 f"连续天数：{summary['streak_days']}　"
                 f"今日积分：{summary['today_credit']}　累计：{summary['total_credits']}")

    if args.dry_run:
        if not args.json:
            log.info("仅预览模式，未执行签到。")
        return 0, {"status": "ok", "action": "dry_run", **summary}

    # 2) 今日已签到 → 不重复签，但 --gift 仍照领
    if summary["today_checked_in"]:
        result = {"status": "ok", "action": "skip_already_signed",
                  "msg": "今日已签到，无需重复操作", **summary}
        if args.gift:
            _claim_gift(result, args, log, endpoint, headers)
        if not args.json:
            log.info("今日已签到，无需重复操作。✅")
        return 0, result

    # 3) 执行签到
    log.info("执行每日签到……")
    ck = do_checkin(endpoint, headers, args.timeout, log, args.retries)
    if not ck["ok"]:
        return 2, {"status": "error", "msg": ck.get("msg", "签到失败")}

    # 签到后回查，拿到最新连签/积分（只在字段有效时覆盖，避免抹成 null）
    try:
        _b, latest = _status_data(endpoint, headers, args.timeout, log, args.retries)
        fresh = _summarize(latest)
        for key, val in fresh.items():
            if val is not None:
                summary[key] = val
        # 只做「升级」不做「降级」：签到接口已返回成功，不因回查延迟翻回 false
        if fresh["today_checked_in"]:
            summary["today_checked_in"] = True
    except CheckinError as e:
        log.warn(f"签到后状态回查失败（不影响本次签到）: {e}")

    result = {"status": "ok", "action": ck["action"],
              "points": ck.get("points"), "msg": ck.get("msg"), **summary}

    # 4) （可选）领取礼包
    if args.gift:
        _claim_gift(result, args, log, endpoint, headers)

    if not args.json:
        pts = f"（+{ck['points']} 积分）" if ck.get("points") else ""
        log.info(f"签到成功{pts}！连续 {summary['streak_days']} 天，"
                 f"累计 {summary['total_credits']} 积分。✅")
    return 0, result


def main(argv=None):
    args = build_parser().parse_args(argv)
    log = Log(quiet=args.quiet, json_mode=args.json)

    if args.doctor:
        return run_doctor(args, log)

    # 预算时钟必须在任何网络请求前启动：签到 + 成长中心一整轮最坏要打十几个接口
    warning = start_budget()
    if warning and not args.quiet:
        log.warn(warning)

    try:
        endpoint, headers = load_credentials(args, log)
    except CheckinError as e:
        return _report_auth_error(e, args, log)

    # 默认签到 + 成长中心都跑；--no-growth 只签到，--growth-only 只跑成长中心。
    # --dry-run 的语义是「只查不领」，必须连带跳过成长中心——否则「预览」会
    # 真的把旅行礼物、任务奖、连登兑换全领走。
    want_growth = not (args.no_growth or args.dry_run)

    # --growth-only：跳过签到，只跑成长中心
    if not args.growth_only:
        try:
            code, result = run_checkin(args, log, endpoint, headers)
        except CheckinError as e:
            return _fail(str(e), args, log, hint=getattr(e, "hint", None),
                         exit_code=e.exit_code, reason=getattr(e, "reason", None))
        except Exception as e:  # noqa: BLE001
            return _fail(f"未知异常: {e}", args, log, exit_code=3)
        if not want_growth:
            _emit(result, args, log)
            return code
        if code != 0:
            # 签到本身就失败了：仍可尝试成长中心（有些奖励与签到无关），但先如实报错
            _fail(result.get("msg", "签到失败"), args, log, exit_code=code)
    else:
        code, result = 0, None

    # 成长中心：出任何问题都不能吞掉签到已成功的事实
    if not args.json:
        log.info("—— 成长中心 ——")
    gcode, growth = run_growth(endpoint, headers, log)
    if not args.json:
        log.info(growth["report"])

    if args.growth_only:
        _emit(growth, args, log)
        return gcode

    result["growth"] = growth
    if growth.get("credits_gained"):
        result["credits_gained"] = growth["credits_gained"]
    # 签到成功但成长中心彻底失败时，不把整轮拉成红色——签到事实已经成立
    if gcode != 0 and code == 0:
        code = gcode
    _emit(result, args, log)
    return code


if __name__ == "__main__":
    sys.exit(main())

