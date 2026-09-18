#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Trae Work（TRAE SOLO CN / TraeWork CN 桌面端）每日自动签到脚本（单文件版）

原理
----
1. 从本机 TraeWork 客户端的 storage.json 中读取 iCubeAuthInfo 加密凭证；
2. 按 byteCrypto 信封算法（AES-128-CBC + SHA-512 完整性校验）解密出 accessToken；
   密钥表从本机安装的 TRAE SOLO CN.app 内 out/main.js 动态提取，随版本自适应；
3. 携带 Cloud-IDE-JWT 调用官方签到接口：先查状态，未签到则领取，幂等安全。

特点
----
- 仅依赖 Python 标准库 + pycryptodome（AES 实现）
- 不重启、不操控客户端 UI，纯 API 调用，签到在客户端关闭时也能完成
- 幂等：已签到自动跳过；网络异常自动重试（指数退避）
- 支持 --dry-run 预览、--json 机器可读输出，适合 cron / launchd 定时运行

用法示例
--------
    python3 trae_work_checkin.py                # 执行签到（已签则跳过）
    python3 trae_work_checkin.py --dry-run      # 只看今日状态，不签到
    python3 trae_work_checkin.py --json         # 仅输出机器可读 JSON

依赖安装
--------
    pip3 install pycryptodome

退出码
------
    0  成功（含「今日已签到」）
    1  配置错误（找不到客户端 / 解密失败等）
    2  网络 / 接口错误
    3  未知异常
"""

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

try:
    from Crypto.Cipher import AES
except ImportError:
    print("[ERROR] 缺少依赖 pycryptodome，请执行: pip3 install pycryptodome",
          file=sys.stderr)
    sys.exit(1)

# ----------------------------- 配置 -----------------------------
DEFAULT_UG_HOST = "https://api.trae.cn"
CHECKIN_STATUS_PATH = "/trae/api/v2/ug/checkin_credits/status"
CHECKIN_CLAIM_PATH = "/trae/api/v2/ug/checkin_credits/claim"

# storage.json 候选路径（macOS / Windows）
STORAGE_CANDIDATES = [
    "~/Library/Application Support/TRAE SOLO CN/User/globalStorage/storage.json",
    r"%APPDATA%\TRAE SOLO CN\User\globalStorage\storage.json",
]
# 客户端主程序 main.js 候选路径（用于提取密钥表，随版本自适应）
MAINJS_CANDIDATES = [
    "/Applications/TRAE SOLO CN.app/Contents/Resources/app/out/main.js",
    r"C:\Program Files\TRAE SOLO CN\resources\app\out\main.js",
]

BYTECRYPTO_MARKER = "out-build/vs/base/common/byteCrypto.js"
ENVELOPE_HEADER = bytes([116, 99, 5, 16, 0, 0])  # b"tc\x05\x10\x00\x00"

USER_AGENT = "trae-work-checkin-script/1.0"


class Log:
    def __init__(self, quiet=False):
        self.quiet = quiet

    def _ts(self):
        return time.strftime("%Y-%m-%d %H:%M:%S")

    def info(self, msg):
        if not self.quiet:
            print(f"[{self._ts()}] [INFO] {msg}")

    def warn(self, msg):
        if not self.quiet:
            print(f"[{self._ts()}] [WARN] {msg}", file=sys.stderr)

    def err(self, msg):
        print(f"[{self._ts()}] [ERROR] {msg}", file=sys.stderr)


# ----------------------------- 凭证定位与解密 -----------------------------
def first_existing(candidates, log: Log):
    for cand in candidates:
        path = os.path.expandvars(os.path.expanduser(cand))
        if os.path.isfile(path):
            return path
    return None


def extract_pepper(main_js_path: str, log: Log):
    """从客户端 out/main.js 中提取两张 64 字节硬编码表并异或，得到 pepper。

    表位于 byteCrypto 模块代码内，紧随模块标记之后；逐版本名称可能变化，
    但「模块标记 + 4 张 64 字节数组」的结构稳定，取最后两张（Vie/Qie）。
    """
    src = open(main_js_path, "r", encoding="utf-8", errors="replace").read()
    marker = src.find(BYTECRYPTO_MARKER)
    if marker < 0:
        raise RuntimeError(f"main.js 中未找到 byteCrypto 模块标记: {main_js_path}")
    region = src[marker:marker + 20000]
    tables = []
    for m in re.finditer(
            r"(?:new\s+Uint8Array|Uint8Array\.from)\(\s*\[\s*([0-9\s*,]+?)\s*\]\s*\)",
            region):
        nums = [int(x) for x in m.group(1).split(",") if x.strip()]
        if len(nums) >= 64:
            tables.append(bytes(nums[:64]))
    if len(tables) < 4:
        raise RuntimeError(
            f"main.js 中仅找到 {len(tables)} 张 64 字节表（需 4 张），版本可能不兼容")
    log.info("已从客户端 main.js 提取密钥表")
    vie, qie = tables[-2], tables[-1]
    return bytes(v ^ q for v, q in zip(vie, qie))


def bytecrypto_decrypt(b64_blob: str, pepper: bytes) -> str:
    """解密 TRAE byteCrypto 信封（AES 模式）。

    格式: 6 字节头 + 32 字节 random + AES-128-CBC(SHA512(plain) || plain)
    密钥派生: key/iv = SHA512(SHA512(random) || pepper) || pepper 的前 32 字节
    """
    raw = base64.b64decode(b64_blob)
    if raw[:6] != ENVELOPE_HEADER:
        raise RuntimeError(f"未知的凭证信封头: {raw[:6].hex()}")
    rnd, ct = raw[6:38], raw[38:]
    digest = hashlib.sha512
    mat = digest(digest(rnd).digest() + pepper).digest() + pepper
    key, iv = mat[:16], mat[16:32]
    padded = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    pad_len = padded[-1]
    if not 1 <= pad_len <= 16:
        raise RuntimeError("AES 解密填充非法，密钥表可能不匹配")
    body = padded[:-pad_len]
    tag, plain = body[:64], body[64:]
    if digest(plain).digest() != tag:
        raise RuntimeError("SHA-512 完整性校验失败，凭证已损坏")
    return plain.decode("utf-8")


def load_credentials(log: Log):
    """定位并解密 storage.json，返回 (token, device_id, storage_path)"""
    storage_path = first_existing(STORAGE_CANDIDATES, log)
    if not storage_path:
        raise RuntimeError(
            "未找到 TraeWork 客户端 storage.json，请确认 TRAE SOLO CN 已安装并登录过")
    log.info(f"找到客户端存储: {storage_path}")

    main_js = first_existing(MAINJS_CANDIDATES, log)
    if not main_js:
        raise RuntimeError("未找到客户端 out/main.js，无法提取密钥表")
    pepper = extract_pepper(main_js, log)

    with open(storage_path, "r", encoding="utf-8") as f:
        storage = json.load(f)

    blob = storage.get("iCubeAuthInfo://icube.cloudide")
    if not blob:
        raise RuntimeError("storage.json 中无 iCubeAuthInfo 凭证，请先在客户端登录")

    creds = json.loads(bytecrypto_decrypt(blob, pepper))
    token = creds.get("token")
    if not token:
        raise RuntimeError("解密结果中缺少 token 字段")

    device_id = next(
        (k.split(":")[-1] for k in storage if k.startswith("iCubeAuthInfo://icube-dc:")),
        None)
    if not device_id:
        raise RuntimeError("storage.json 中无设备 ID（icube-dc）")

    expired_at = creds.get("expiredAt", "")
    log.info(f"凭证解密成功，token 过期时间: {expired_at or '未知'}")
    return token, device_id, storage_path


# ----------------------------- 签到接口 -----------------------------
def post_ug(host, path, token, device_id, timeout, retries, log: Log):
    """调用 TraeWork 增长类接口（Cloud-IDE-JWT 鉴权），网络异常自动重试"""
    url = host.rstrip("/") + path
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Cloud-IDE-JWT {token}",
        "x-device-id": device_id,
        "User-Agent": USER_AGENT,
    }
    last_err = None
    for attempt in range(1, max(1, retries) + 1):
        req = urllib.request.Request(url, data=b"{}", headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.getcode(), json.loads(resp.read().decode("utf-8", "replace") or "{}")
        except urllib.error.HTTPError as e:
            try:
                raw = e.read().decode("utf-8", "replace")
            except Exception:
                raw = ""
            try:
                return e.code, json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                return e.code, {"_raw": raw}
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last_err = e
            if attempt < retries:
                wait = min(2 ** attempt, 10)
                log.warn(f"网络异常（第 {attempt}/{retries} 次）：{e}，{wait}s 后重试")
                time.sleep(wait)
    raise RuntimeError(f"网络请求失败（已尝试 {retries} 次）: {last_err}")


def get_checkin_status(token, device_id, host, timeout, retries, log: Log):
    _, body = post_ug(host, CHECKIN_STATUS_PATH, token, device_id, timeout, retries, log)
    if body.get("code") != 0:
        raise RuntimeError(f"状态查询失败: code={body.get('code')} msg={body.get('message')}")
    return {
        "enable": bool(body.get("enable")),
        "checked_in": bool(body.get("checked_in")),
        "credits": body.get("credits"),
    }


def do_claim(token, device_id, host, timeout, retries, log: Log):
    """领取签到积分，code==0 视为成功"""
    _, body = post_ug(host, CHECKIN_CLAIM_PATH, token, device_id, timeout, retries, log)
    if body.get("code") == 0:
        return {"ok": True, "credits": body.get("credits"), "msg": body.get("message") or "OK"}
    msg = body.get("message") or ""
    if "已签到" in msg or "已领取" in msg:
        return {"ok": True, "credits": body.get("credits"), "msg": msg}
    raise RuntimeError(f"签到失败: code={body.get('code')} msg={msg}")


# ----------------------------- 主流程 -----------------------------
def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Trae Work（TRAE SOLO CN）每日自动签到脚本（单文件版）")
    parser.add_argument("--host", default=DEFAULT_UG_HOST,
                        help=f"API 域名（默认 {DEFAULT_UG_HOST}）")
    parser.add_argument("--storage", help="指定 storage.json 路径（默认自动定位）")
    parser.add_argument("--mainjs", help="指定客户端 out/main.js 路径（默认自动定位）")
    parser.add_argument("--dry-run", action="store_true",
                        help="只查询今日签到状态，不执行签到")
    parser.add_argument("--retries", type=int, default=3,
                        help="网络异常自动重试次数（默认 3）")
    parser.add_argument("--timeout", type=int, default=15, help="请求超时（秒）")
    parser.add_argument("--json", action="store_true", help="仅输出机器可读 JSON")
    parser.add_argument("--quiet", "-q", action="store_true", help="静默模式")
    args = parser.parse_args(argv)

    log = Log(quiet=args.quiet)

    def emit(payload):
        if args.json:
            print(json.dumps(payload, ensure_ascii=False))

    try:
        if args.storage:
            STORAGE_CANDIDATES.insert(0, args.storage)
        if args.mainjs:
            MAINJS_CANDIDATES.insert(0, args.mainjs)

        token, device_id, _ = load_credentials(log)

        status = get_checkin_status(token, device_id, args.host,
                                    args.timeout, args.retries, log)
        if not status["enable"]:
            msg = "签到活动未开启或账号不支持签到"
            if args.json:
                emit({"status": "error", "msg": msg})
            else:
                log.err(msg)
            return 1
        if not args.json:
            log.info(f"今日已签到: {status['checked_in']}　每日积分: {status['credits']}")

        if args.dry_run:
            if args.json:
                emit({"status": "ok", "action": "dry_run", **status})
            else:
                log.info("预览模式，未执行签到。")
            return 0

        if status["checked_in"]:
            if args.json:
                emit({"status": "ok", "action": "skip_already_signed",
                      "msg": "今日已签到，无需重复操作", **status})
            else:
                log.info("今日已签到，无需重复操作。✅")
            return 0

        if not args.json:
            log.info("执行每日签到……")
        result = do_claim(token, device_id, args.host, args.timeout, args.retries, log)

        try:
            after = get_checkin_status(token, device_id, args.host,
                                       args.timeout, args.retries, log)
            result["checked_in_after"] = after["checked_in"]
        except Exception:
            pass

        if args.json:
            emit({"status": "ok", "action": "checked_in", **result})
        else:
            pts = f"，领取 +{result['credits']} 积分" if result.get("credits") else ""
            log.info(f"签到成功{pts}！✅")
        return 0

    except RuntimeError as e:
        if args.json:
            emit({"status": "error", "msg": str(e)})
        else:
            log.err(str(e))
        return 2
    except Exception as e:
        msg = f"未知异常: {e}"
        if args.json:
            emit({"status": "error", "msg": msg})
        else:
            log.err(msg)
        return 3


if __name__ == "__main__":
    sys.exit(main())
