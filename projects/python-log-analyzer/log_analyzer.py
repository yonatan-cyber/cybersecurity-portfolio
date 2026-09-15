#!/usr/bin/env python3
"""
Analyze Linux auth.log files for authentication and command activity.
"""

import argparse
import os
import re
import shlex
import sys
from typing import Dict, List, Optional


RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"
DIM = "\033[2m"


EVENT_KEYS = (
    "sudo_commands",
    "failed_sudo_attempts",
    "su_usage",
    "new_users",
    "deleted_users",
    "password_changes",
)


def colorize(text, color_code, enabled):
    if not enabled:
        return str(text)
    return f"{color_code}{text}{RESET}"


def parse_timestamp(line: str) -> str:
    """Return the timestamp from a syslog or ISO 8601 log line."""
    iso_match = re.match(
        r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))",
        line,
    )
    if iso_match:
        return iso_match.group(1)

    syslog_match = re.match(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
    return syslog_match.group(1) if syslog_match else "Unknown timestamp"


def parse_key_value_fields(line: str) -> Dict[str, str]:
    """Extract common KEY=value fields from auth.log messages."""
    fields = {}
    for key, value in re.findall(r"\b([A-Z]+)=([^;]+?)(?=\s+[A-Z]+=|$)", line):
        fields[key] = value.strip()
    return fields


def clean_sudo_reason(reason: str) -> str:
    """Remove trailing sudo key/value fields from a failure reason."""
    parts = [part.strip() for part in reason.split(";")]
    useful_parts = []

    for part in parts:
        if re.match(r"^(TTY|PWD|USER|COMMAND)=", part):
            break
        if part:
            useful_parts.append(part)

    return " ; ".join(useful_parts) if useful_parts else "Not available"


def parse_su_identity(value: str) -> Dict[str, str]:
    match = re.match(r"^([A-Za-z0-9_.-]+)(?:\(uid=(\d+)\))?$", value)
    if not match:
        return {"user": value, "uid": "Not available"}

    return {
        "user": match.group(1),
        "uid": match.group(2) if match.group(2) else "Not available",
    }


def parse_sudo_success(line: str) -> Optional[Dict[str, str]]:
    if "sudo:" not in line or "COMMAND=" not in line:
        return None

    if "authentication failure" in line.lower() or "incorrect password" in line.lower():
        return None

    match = re.search(r"sudo:\s+(\S+)\s*:", line)
    fields = parse_key_value_fields(line)

    return {
        "timestamp": parse_timestamp(line),
        "user": match.group(1) if match else "Unknown user",
        "command": fields.get("COMMAND", "Unknown command"),
        "raw": line.strip(),
    }


def parse_sudo_failure(line: str) -> Optional[Dict[str, str]]:
    if "sudo:" not in line:
        return None

    failure_patterns = (
        "authentication failure",
        "incorrect password",
        "user NOT in sudoers",
        "not in the sudoers file",
        "command not allowed",
        "conversation failed",
    )

    lower_line = line.lower()
    if not any(pattern.lower() in lower_line for pattern in failure_patterns):
        return None

    user_match = re.search(r"sudo:\s+(\S+)\s*:", line)
    ruser_match = re.search(r"\bruser=([^\s]+)", line)
    reason_match = re.search(r"sudo:\s+(?:\S+\s*:)?\s*(.+)", line)
    fields = parse_key_value_fields(line)

    user = "Unknown user"
    if user_match:
        user = user_match.group(1)
    elif ruser_match:
        user = ruser_match.group(1)

    return {
        "timestamp": parse_timestamp(line),
        "user": user,
        "command": fields.get("COMMAND", "Not available"),
        "reason": clean_sudo_reason(reason_match.group(1)) if reason_match else "Not available",
        "raw": line.strip(),
    }


def parse_su_usage(line: str) -> Optional[Dict[str, str]]:
    if " su[" not in line and " su:" not in line:
        return None

    su_indicators = (
        "session opened",
        "session closed",
        "successful su",
        "authentication failure",
        "failed su",
    )

    if not any(indicator in line.lower() for indicator in su_indicators):
        return None

    user_match = re.search(r"\bby\s+(\S+)", line)
    target_match = re.search(r"\bfor user\s+(\S+)", line)
    if not target_match:
        target_match = re.search(r"\bsu\s+for\s+(\S+)", line)

    source = parse_su_identity(user_match.group(1)) if user_match else None
    target = parse_su_identity(target_match.group(1)) if target_match else None

    action = "Not available"
    if "session opened" in line.lower():
        action = "session opened"
    elif "session closed" in line.lower():
        action = "session closed"

    return {
        "timestamp": parse_timestamp(line),
        "user": source["user"] if source else "Unknown user",
        "uid": source["uid"] if source else "Not available",
        "target_user": target["user"] if target else "Unknown target",
        "target_uid": target["uid"] if target else "Not available",
        "action": action,
        "raw": line.strip(),
    }


def parse_sudo_user_management(sudo_event: Dict[str, str]) -> Optional[Dict[str, str]]:
    command = sudo_event.get("command", "")

    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()

    if not parts:
        return None

    executable = os.path.basename(parts[0])
    if executable not in {"useradd", "adduser", "userdel", "deluser"}:
        return None

    username = "Unknown username"
    positional_args = [part for part in parts[1:] if not part.startswith("-")]
    if positional_args:
        username = positional_args[-1]

    return {
        "timestamp": sudo_event["timestamp"],
        "username": username,
        "raw": sudo_event["raw"],
        "action": "added" if executable in {"useradd", "adduser"} else "deleted",
    }


def parse_user_added(line: str) -> Optional[Dict[str, str]]:
    patterns = (
        r"\bnew user:\s+name=([^,\s]+)",
        r"\buseradd\[\d+\]:\s+new user:\s+name=([^,\s]+)",
        r"\badduser\[\d+\]:\s+new user\s+'([^']+)'",
    )

    for pattern in patterns:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            return {
                "timestamp": parse_timestamp(line),
                "username": match.group(1),
                "raw": line.strip(),
            }

    return None


def parse_user_deleted(line: str) -> Optional[Dict[str, str]]:
    patterns = (
        r"\bdelete user\s+'([^']+)'",
        r"\bdelete user\s+(\S+)",
        r"\buserdel\[\d+\]:\s+delete user\s+'?([^'\s]+)'?",
        r"\bremoved user\s+'([^']+)'",
    )

    for pattern in patterns:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            return {
                "timestamp": parse_timestamp(line),
                "username": match.group(1),
                "raw": line.strip(),
            }

    return None


def parse_password_change(line: str) -> Optional[Dict[str, str]]:
    patterns = (
        r"\bpassword changed for\s+(\S+)",
        r"\bpassword for\s+(\S+)\s+changed",
        r"\bpasswd\[\d+\]:\s+pam_unix\(passwd:chauthtok\):\s+password changed for\s+(\S+)",
    )

    for pattern in patterns:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            return {
                "timestamp": parse_timestamp(line),
                "username": match.group(1),
                "raw": line.strip(),
            }

    return None


def analyze_log_file(file_path: str) -> Dict[str, List[Dict[str, str]]]:
    results = {key: [] for key in EVENT_KEYS}

    with open(file_path, "r", encoding="utf-8", errors="replace") as log_file:
        for line in log_file:
            sudo_failure = parse_sudo_failure(line)
            if sudo_failure:
                results["failed_sudo_attempts"].append(sudo_failure)
                continue

            sudo_success = parse_sudo_success(line)
            if sudo_success:
                results["sudo_commands"].append(sudo_success)
                user_management = parse_sudo_user_management(sudo_success)
                if user_management and user_management["action"] == "added":
                    results["new_users"].append(user_management)
                elif user_management and user_management["action"] == "deleted":
                    results["deleted_users"].append(user_management)

            su_usage = parse_su_usage(line)
            if su_usage:
                results["su_usage"].append(su_usage)

            user_added = parse_user_added(line)
            if user_added:
                results["new_users"].append(user_added)

            user_deleted = parse_user_deleted(line)
            if user_deleted:
                results["deleted_users"].append(user_deleted)

            password_change = parse_password_change(line)
            if password_change:
                results["password_changes"].append(password_change)

    return results


def print_section(title: str, items: List[Dict[str, str]], formatter, use_color: bool) -> None:
    print(colorize(f"\n==== {title} ====", BOLD + CYAN, use_color))
    if not items:
        print(colorize("No events found.", DIM, use_color))
        return

    for index, item in enumerate(items, start=1):
        print(f"{index}. {formatter(item)}")


def format_summary_line(label: str, count: int, color_code: str, use_color: bool) -> str:
    line = f"{label}: {count}"
    if count <= 0:
        return colorize(line, DIM, use_color)
    return colorize(line, color_code, use_color)


def print_report(results: Dict[str, List[Dict[str, str]]], use_color: bool) -> None:
    print_section(
        "SUDO COMMANDS",
        results["sudo_commands"],
        lambda item: (
            f"{colorize(item['timestamp'], CYAN, use_color)} | "
            f"User: {colorize(item['user'], YELLOW, use_color)} | "
            f"Command: {colorize(item['command'], GREEN, use_color)}"
        ),
        use_color,
    )

    print_section(
        "FAILED SUDO ATTEMPTS",
        results["failed_sudo_attempts"],
        lambda item: (
            f"{colorize('ALERT!', BOLD + RED, use_color)} "
            f"{colorize(item['timestamp'], CYAN, use_color)} | "
            f"User: {colorize(item['user'], YELLOW, use_color)} | "
            f"Command: {colorize(item['command'], GREEN, use_color)} | "
            f"Reason: {item['reason']}"
        ),
        use_color,
    )

    print_section(
        "SU USAGE",
        results["su_usage"],
        lambda item: (
            f"{colorize(item['timestamp'], CYAN, use_color)} | "
            f"User: {colorize(item['user'], YELLOW, use_color)} | "
            f"UID: {item['uid']} | "
            f"Target: {colorize(item['target_user'], YELLOW, use_color)} | "
            f"Target UID: {item['target_uid']} | "
            f"Action: {item['action']} | Details: {item['raw']}"
        ),
        use_color,
    )

    print_section(
        "NEW USERS",
        results["new_users"],
        lambda item: (
            f"{colorize(item['timestamp'], CYAN, use_color)} | "
            f"Username: {colorize(item['username'], YELLOW, use_color)} | "
            f"Details: {item['raw']}"
        ),
        use_color,
    )

    print_section(
        "DELETED USERS",
        results["deleted_users"],
        lambda item: (
            f"{colorize(item['timestamp'], CYAN, use_color)} | "
            f"Username: {colorize(item['username'], YELLOW, use_color)} | "
            f"Details: {item['raw']}"
        ),
        use_color,
    )

    print_section(
        "PASSWORD CHANGES",
        results["password_changes"],
        lambda item: (
            f"{colorize(item['timestamp'], CYAN, use_color)} | "
            f"Username: {colorize(item['username'], YELLOW, use_color)} | "
            f"Details: {item['raw']}"
        ),
        use_color,
    )

    print(colorize("\n==== SUMMARY ====", BOLD + BLUE, use_color))
    print(format_summary_line("Sudo commands", len(results["sudo_commands"]), GREEN, use_color))
    print(format_summary_line("Failed sudo attempts", len(results["failed_sudo_attempts"]), BOLD + RED, use_color))
    print(format_summary_line("Su usage events", len(results["su_usage"]), CYAN, use_color))
    print(format_summary_line("New users", len(results["new_users"]), GREEN, use_color))
    print(format_summary_line("Deleted users", len(results["deleted_users"]), YELLOW, use_color))
    print(format_summary_line("Password changes", len(results["password_changes"]), CYAN, use_color))


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze a Linux auth.log file for important activity."
    )
    parser.add_argument("log_file", help="Path to the auth.log file to analyze")
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in the terminal report",
    )
    return parser


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()
    use_color = not args.no_color and sys.stdout.isatty()

    if not os.path.isfile(args.log_file):
        print(f"Error: File not found: {args.log_file}", file=sys.stderr)
        sys.exit(1)

    if not os.access(args.log_file, os.R_OK):
        print(f"Error: File cannot be read: {args.log_file}", file=sys.stderr)
        sys.exit(1)

    try:
        results = analyze_log_file(args.log_file)
    except OSError as error:
        print(f"Error: Could not read file: {error}", file=sys.stderr)
        sys.exit(1)

    print_report(results, use_color)


if __name__ == "__main__":
    main()
