# AI-App-Auto-Check-in-Script

五个单文件 Python 自动签到脚本，覆盖常用 AI 应用的「每日签到领积分 / 额度」活动。均为幂等设计（已签到自动跳过，绝不重复领），支持 `--dry-run` 预览与 `--json` 机器可读输出，适合 cron / launchd / 计划任务定时运行。

## 包含的脚本

| 脚本 | 目标应用 | 依赖 | 凭证来源 |
|---|---|---|---|
| `tabbit_checkin.py` | Tabbit 浏览器（国内版 / 国际版） | 无（纯标准库） | 通过 Tabbit 自带 Playwright 桥读取浏览器 Cookie，本地缓存复用 |
| `traecode_checkin.py` | TraeCode（Trae CN 桌面端 IDE） | pycryptodome | 解密客户端 `storage.json` 中的登录凭证 |
| `trae_work_checkin.py` | Trae Work（TRAE SOLO CN 桌面端） | pycryptodome | 解密客户端 `storage.json` 中的登录凭证 |
| `workbuddy_checkin.py` | WorkBuddy 桌面端 | 无（纯标准库） | 读取本机登录态文件；accessToken 为加密信封时，起一个短命的 WorkBuddy 客户端子进程解密 |
| `qoder_checkin.py` | Qoder（国内版 / 国际版） | pycryptodome | 解密客户端 `auth.v1.dat`（Electron safeStorage），并调用客户端 `umid/runtime-info` 生成设备风控身份 |

## 快速开始

```bash
# TraeCode / Trae Work / Qoder 需要 AES 依赖
pip3 install pycryptodome

# Tabbit（默认国内版 + 国际版都签，已签自动跳过）
python3 tabbit_checkin.py

# TraeCode
python3 traecode_checkin.py

# Trae Work
python3 trae_work_checkin.py

# WorkBuddy（默认签到 + 成长中心都跑；--no-growth 只签到）
python3 workbuddy_checkin.py

# Qoder（默认国内版 + 国际版都领，已领自动跳过）
python3 qoder_checkin.py
```

前置条件：

- **Tabbit**：首次运行需 Tabbit 浏览器处于运行状态且已登录对应站点；之后依赖本地 Cookie 缓存（有效期至 JWT 过期，约 7 天），日常签到无需浏览器在线。
- **TraeCode / Trae Work**：本机已安装并登录过对应客户端（客户端关闭时也能签到）。
- **WorkBuddy**：本机已登录 WorkBuddy 客户端。签到 token 以加密信封形式存放，脚本会短暂拉起一个 WorkBuddy 子进程（`ELECTRON_RUN_AS_NODE=1`，不弹 GUI）完成解密，密钥与明文 token 只存在于该子进程内存中，不落盘、不缓存、不打印。
- **Qoder**：本机已安装并登录过 Qoder 客户端（客户端关闭时也能领取）。macOS 首次运行会弹一次钥匙串授权框，点「始终允许」后即可无人值守（可用项会记到 `~/.qoder_checkin/keychain.json`）。

> Qoder 的活动窗口是**每天 10:00 → 次日 09:59（北京时间）**，即每天 10:00 刷新，定时任务请排在 10:05 之后。

## 常用参数

| 参数 | 说明 |
|---|---|
| `--dry-run` | 只查询今日签到状态，不执行签到 |
| `--json` | 仅输出一行机器可读 JSON（日志走 stderr，可安全 `| jq`） |
| `--quiet` / `-q` | 静默模式 |
| `--timeout` | HTTP 超时（秒） |
| `--retries` | 网络异常 / 5xx 自动指数退避重试次数 |

各脚本特有参数见 `--help`：

- `tabbit_checkin.py`：`--site cn|intl|both`、`--refresh-cookie`（强制重读 Cookie）、`--cookie`
- `traecode_checkin.py` / `trae_work_checkin.py`：`--storage`、`--mainjs`（手动指定凭证 / 密钥表路径）、`--host`
- `workbuddy_checkin.py`：`--no-growth`（只签到，默认是签到+成长中心）、`--growth-only`（只跑成长中心）、`--gift`（额外领今日礼包）、`--doctor`（离线体检：只验凭据格式与解密能力，不联网）、`--token`、`--auth-file`（也支持环境变量 `WORKBUDDY_ACCESS_TOKEN` / `WORKBUDDY_AUTH_FILE` / `WORKBUDDY_EXE` / `WORKBUDDY_BUDGET_SECONDS`）
- `qoder_checkin.py`：`--site cn|intl|both`、`--token`、`--token-file`、`--uid`、`--data-dir`、`--resources-dir`、`--keychain-service`（macOS 指定钥匙串项）、`--no-risk`（不生成设备风控身份）

退出码统一约定：`0` 成功（含「今日已签到」）、`1` 配置 / 登录态错误、`2` 网络 / 接口错误、`3` 未知异常。

## 定时运行示例

### cron（每天 09:30）

```cron
30 9 * * * /usr/bin/python3 /path/to/tabbit_checkin.py --quiet >> /tmp/tabbit_checkin.log 2>&1
```

### cron（Qoder，每天 10:05）

Qoder 活动每天 10:00（北京时间）刷新，因此排在 10:05：

```cron
5 10 * * * /usr/bin/python3 /path/to/qoder_checkin.py --quiet >> /tmp/qoder_checkin.log 2>&1
```

### cron（WorkBuddy，每天 09:10）

WorkBuddy 需要拉起客户端子进程解密，比其他脚本慢一些，留足时间：

```cron
10 9 * * * /usr/bin/python3 /path/to/workbuddy_checkin.py --quiet >> /tmp/workbuddy_checkin.log 2>&1
```

> 定时任务环境下若解密失败（`KEY_MISMATCH` / `RUNTIME_UNAVAILABLE`），多半是装了好几个 WorkBuddy 版本导致密钥对不上，用 `WORKBUDDY_EXE` 指定与该凭据匹配的客户端即可。先用 `--doctor` 离线验证，它不会联网。

### WorkBuddy 成长中心

**默认就会跑**（不需要额外参数）。签到之后接着执行 `/v2/activity/growth` 的 7 个模块：

| # | 模块 | 做什么 |
|---|---|---|
| 1 | Buddy 旅行 | 领回程礼物 → 派 Buddy 出发（每日一次） |
| 2 | 任务 | 接单（`not_accepted`）→ 领奖（`completed`） |
| 3 | 补登 | 断登自动用补登卡补回，保住连登 |
| 4 | 连登兑换 | 入门 7 天 / 进阶 14 天 / 巅峰 28 天三档 |
| 5 | 盲盒 | 用抽奖机会开一次 |
| 6 | Buddy 盲盒 | 能量攒够就开 |
| 7 | 展示 | 能量余额、连签天数（纯展示） |

顺序不是随便排的：任务领奖在抽奖前（任务送的抽奖机会马上能用），补登在连登兑换前（补登会改变连登天数，先补才知道档位解没解锁）。

```bash
python3 workbuddy_checkin.py                # 签到 + 成长中心（默认）
python3 workbuddy_checkin.py --no-growth    # 只签到
python3 workbuddy_checkin.py --growth-only  # 只跑成长中心
python3 workbuddy_checkin.py --dry-run      # 只查状态，什么都不领
```

> ⚠️ 参数一律用**英文半角**减号 `--`。写成中文破折号 `—json` 会被 argparse 直接拒绝（`unrecognized arguments`）。`--dry-run` 会连带跳过成长中心——它的语义是「只查不领」。

**幂等性**：每个模块都是「先查状态再决定是否写」，重复运行不会重复领取。中奖的实物周边（冰箱贴 / 胸针 / 杯子）需要你自己去成长中心填收件信息，脚本只提醒不代填。

**时间预算**：一整轮最多十几个接口，加上退避重试，最坏会跑很久。脚本内置 `WORKBUDDY_BUDGET_SECONDS` 预算（默认 240 秒，范围 30–420），预算耗尽就主动收尾并如实记录已领到的部分，剩下的下次再领。**Windows 计划任务须保证 `ExecutionTimeLimit` 大于该值**，否则进程会被系统强杀、当天记录整条丢失。


### launchd（macOS）

创建 `~/Library/LaunchAgents/com.checkin.plist`：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.checkin</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>/path/to/tabbit_checkin.py</string>
        <string>--quiet</string>
    </array>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key><integer>9</integer>
        <key>Minute</key><integer>30</integer>
    </dict>
    <key>StandardOutPath</key><string>/tmp/checkin.log</string>
    <key>StandardErrorPath</key><string>/tmp/checkin.log</string>
</dict>
</plist>
```

```bash
launchctl load ~/Library/LaunchAgents/com.checkin.plist
```

## 安全说明

- 脚本代码不含任何硬编码凭证或个人信息；所有登录凭证均在运行时从本机客户端读取，仅用于向对应应用的**官方接口**发起签到请求，不会发送给任何第三方。
- Tabbit 的 Cookie 会缓存到 `~/.tabbit_checkin/cookies.json`（文件权限 `0600`），请勿将该缓存文件或含凭证参数的运行命令分享给他人。
- WorkBuddy 的解密密钥与明文 token 只存在于一个短命的客户端子进程内存中，用完原地清零：脚本不写临时密钥文件、不缓存明文 token、不改写原凭据，也永远不会打印 token（`Authorization` 头不进入任何日志）。该子进程有独立的超时与管道大小限制。

## 免责声明

本项目仅供个人学习与个人账号自动化签到使用，接口路径与加解密逻辑来自对本机客户端的分析，随客户端版本更新可能失效。请自行评估使用风险，请勿用于商业用途。
