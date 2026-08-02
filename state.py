#!/usr/bin/env python3
"""跨天状态追踪 — 检测「Action 全绿但其实一直没签到成功」的静默失败。

单次运行只能看到当天结果。百度签到有个特殊之处:
「今天已经签过」和「Cookie 失效签不上」积分都是 0，
单看一天分不清，连续多天积分都是 0 就非常可疑。

state.json 提交回仓库，让每次运行都能读到历史。
同时承担保活职责: 每天有 commit，不会触发 GitHub 60 天自动禁用。
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

STATE_FILE = "state.json"

# 连续失败达到该次数 → 紧急告警
ALERT_STREAK_THRESHOLD = 3
# 连续零积分达到该次数 → 紧急告警（Cookie 可能已静默失效）
ZERO_POINT_THRESHOLD = 3
# Cookie 经验寿命（天），超过则提醒轮换
COOKIE_LIFETIME_DAYS = 30
WARN_THRESHOLD_DAYS = 7


def load_state(path: str = STATE_FILE) -> dict:
    if not os.path.exists(path):
        logger.info(f"{path} 不存在，创建新状态")
        return {"version": 1, "accounts": {}, "runs": []}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        data.setdefault("accounts", {})
        data.setdefault("runs", [])
        return data
    except Exception as e:
        logger.warning(f"读取 {path} 失败（{e}），重建状态")
        return {"version": 1, "accounts": {}, "runs": []}


def save_state(state: dict, path: str = STATE_FILE) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2, sort_keys=True)
        logger.info(f"状态已写入 {path}")
    except Exception as e:
        logger.error(f"写入 {path} 失败: {e}")


def fingerprint(value: str) -> str:
    """只存 hash，绝不把 Cookie 明文写进 state.json"""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def check_cookie_age(state: dict, index: int, cookie: str, today: datetime) -> str | None:
    """Cookie 没有可解析的过期时间，按「首见日期 + 经验寿命」推算。

    Cookie 指纹变化 = 用户更新了凭证 = 重置计时。
    """
    key = f"account_{index}"
    entry = state.setdefault("accounts", {}).setdefault(key, {})
    fp = fingerprint(cookie)

    if entry.get("cookie_fingerprint") != fp:
        entry["cookie_fingerprint"] = fp
        entry["cookie_first_seen"] = today.strftime("%Y-%m-%d")
        logger.info(f"  [账号{index}] Cookie 已更新，重置有效期计时")
        return None

    first_seen = entry.get("cookie_first_seen")
    if not first_seen:
        return None

    try:
        seen = datetime.strptime(first_seen, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None

    age = (today - seen).days
    remaining = COOKIE_LIFETIME_DAYS - age
    entry["cookie_days_left"] = remaining

    if remaining <= 0:
        return f"🚨 账号{index} Cookie 已用 {age} 天（经验寿命 {COOKIE_LIFETIME_DAYS} 天）— 建议重新抓取"
    if remaining <= WARN_THRESHOLD_DAYS:
        return f"⚠️ 账号{index} Cookie 预计还有 {remaining} 天失效 — 建议尽快更新 BAIDUWP_ACCOUNTS"
    return None


def record_results(state: dict, results: list[dict], now: datetime) -> list[str]:
    """记录结果，更新连续失败/连续零积分计数，返回需要升级的告警。"""
    from baiduwp import is_signin_success, is_already_signed_message, total_points_for_result

    today = now.strftime("%Y-%m-%d")
    alerts: list[str] = []
    accounts = state.setdefault("accounts", {})

    for index, result in enumerate(results, start=1):
        key = f"account_{index}"
        entry = accounts.setdefault(key, {})
        entry.setdefault("fail_streak", 0)
        entry.setdefault("zero_point_streak", 0)
        entry["last_run"] = today
        entry["total_runs"] = entry.get("total_runs", 0) + 1

        success = is_signin_success(result)
        points = total_points_for_result(result)
        msg = result.get("signin_error_msg", "")

        # --- 连续失败 ---
        if success:
            if entry["fail_streak"] > 0:
                logger.info(f"  [账号{index}] 已恢复（此前连续失败 {entry['fail_streak']} 天）")
                entry["recovered_at"] = today
            entry["fail_streak"] = 0
            entry["last_success"] = today
        else:
            entry["fail_streak"] += 1
            entry["total_fails"] = entry.get("total_fails", 0) + 1
            if entry["fail_streak"] >= ALERT_STREAK_THRESHOLD:
                last_ok = entry.get("last_success") or "从未成功"
                alerts.append(
                    f"🚨 账号{index} 已连续失败 {entry['fail_streak']} 天"
                    f"（最后成功: {last_ok}）— 需要人工介入"
                )

        # --- 连续零积分（静默失效的关键信号）---
        # 「今日已签到」积分为 0 是正常的，不计入
        if points > 0 or is_already_signed_message(msg):
            if entry["zero_point_streak"] >= ZERO_POINT_THRESHOLD:
                logger.info(f"  [账号{index}] 积分已恢复正常")
            entry["zero_point_streak"] = 0
            if points > 0:
                entry["last_point_gain"] = today
        else:
            entry["zero_point_streak"] += 1
            if entry["zero_point_streak"] >= ZERO_POINT_THRESHOLD:
                last_gain = entry.get("last_point_gain") or "从无记录"
                alerts.append(
                    f"🚨 账号{index} 已连续 {entry['zero_point_streak']} 天积分为 0"
                    f"（最后获得积分: {last_gain}）— Cookie 可能已静默失效"
                )

    runs = state.setdefault("runs", [])
    runs.append({
        "date": today,
        "accounts": len(results),
        "total_points": sum(total_points_for_result(r) for r in results),
    })
    state["runs"] = runs[-30:]
    state["last_run_at"] = now.isoformat()

    return alerts


def build_warnings(state: dict, results: list[dict]) -> list[str]:
    """生成报告里的提示行（未达告警阈值的温和提醒）"""
    from baiduwp import is_already_signed_message, total_points_for_result

    lines = []
    accounts = state.get("accounts", {})
    for index, result in enumerate(results, start=1):
        entry = accounts.get(f"account_{index}", {})
        points = total_points_for_result(result)
        msg = result.get("signin_error_msg", "")
        streak = entry.get("zero_point_streak", 0)

        if points == 0 and not is_already_signed_message(msg) and 0 < streak < ZERO_POINT_THRESHOLD:
            lines.append(f"⚠️ 账号{index} 本次积分为 0（连续 {streak} 天）— 留意是否 Cookie 失效")

        fs = entry.get("fail_streak", 0)
        if fs > 1:
            last_ok = entry.get("last_success") or "从未成功"
            lines.append(f"⚠️ 账号{index} 连续失败 {fs} 天，最后成功 {last_ok}")
    return lines
