"""
engine.py - deterministic SSH brute-force detection, severity scoring and
incident-report generation.

Everything that must be *correct* (counting, grouping, severity, firewall
commands, Wazuh rules) is computed here in plain Python. The LLM (llm.py) is
only used to write the narrative parts of the report, so it can never
miscount or invent a command.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections import Counter, OrderedDict, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
DEFAULT_PRIVILEGED = ["root", "admin", "administrator", "ubuntu", "pi", "oracle", "postgres"]
SEVERITY_ORDER = ["Informational", "Low", "Medium", "High", "Critical"]
SEVERITY_COLORS = {
    "Critical": "#dc2626",
    "High": "#ea580c",
    "Medium": "#d97706",
    "Low": "#2563eb",
    "Informational": "#6b7280",
}

ATTACK_GUESSING = "Password Guessing"
ATTACK_SPRAYING = "Password Spraying"
ATTACK_DICTIONARY = "Dictionary / Bot Attack"
ATTACK_ISOLATED = "N/A (Isolated Failure)"

SAMPLE_LOG = """May 14 10:15:01 server sshd[1201]: Failed password for invalid user admin from 192.168.1.150 port 49152 ssh2
May 14 10:15:02 server sshd[1204]: Failed password for invalid user admin from 192.168.1.150 port 49154 ssh2
May 14 10:15:03 server sshd[1208]: Failed password for invalid user root from 192.168.1.150 port 49158 ssh2
May 14 10:15:04 server sshd[1212]: Failed password for invalid user guest from 192.168.1.150 port 49162 ssh2

May 14 10:20:10 server sshd[1301]: Failed password for user alice from 10.0.0.88 port 52100 ssh2
May 14 10:20:12 server sshd[1304]: Failed password for user bob from 10.0.0.88 port 52102 ssh2
May 14 10:20:15 server sshd[1308]: Failed password for user charlie from 10.0.0.88 port 52104 ssh2
May 14 10:20:18 server sshd[1312]: Failed password for user david from 10.0.0.88 port 52106 ssh2

May 14 10:25:01 server sshd[1400]: Accepted password for user john from 10.0.0.45 port 51234 ssh2

May 14 10:30:00 server sshd[1500]: Failed password for user carol from 203.0.113.50 port 40001 ssh2
May 14 10:30:03 server sshd[1501]: Failed password for user carol from 203.0.113.50 port 40003 ssh2
May 14 10:30:06 server sshd[1502]: Failed password for user carol from 203.0.113.50 port 40005 ssh2
May 14 10:30:09 server sshd[1503]: Failed password for user carol from 203.0.113.50 port 40007 ssh2
May 14 10:30:12 server sshd[1504]: Failed password for user carol from 203.0.113.50 port 40009 ssh2
May 14 10:30:15 server sshd[1505]: Accepted password for carol from 203.0.113.50 port 40011 ssh2"""

# --------------------------------------------------------------------------- #
# Settings
# --------------------------------------------------------------------------- #
@dataclass
class Settings:
    min_failures: int = 3                      # failures from one IP before it is "suspicious"
    privileged: list = field(default_factory=lambda: list(DEFAULT_PRIVILEGED))
    firewall: str = "iptables"                 # iptables | ufw | firewalld | all
    critical_on_privileged: bool = False       # force Critical when root/admin is targeted
    custom_rules: str = ""                     # free-text guidance for the LLM narrative
    use_llm: bool = True


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
_TS_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)")
_TS_SYSLOG = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})")
_SSHD = re.compile(r"sshd(?:\[\d+\])?:\s*(?P<msg>.*)$")
_FAILED = re.compile(
    r"Failed (?P<method>[\w-]+(?:/[\w-]+)?) for (?P<invalid>invalid user )?(?:user )?(?P<user>\S+) "
    r"from (?P<ip>[0-9A-Fa-f:.]+)(?: port (?P<port>\d+))?"
)
_ACCEPTED = re.compile(
    r"Accepted (?P<method>[\w-]+) for (?:user )?(?P<user>\S+) from (?P<ip>[0-9A-Fa-f:.]+)(?: port (?P<port>\d+))?"
)
_INVALID = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[0-9A-Fa-f:.]+)")
_INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128")]
_SAFE_USER_CMD = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


@dataclass
class Event:
    line_no: int
    ts: Optional[datetime]
    kind: str            # fail | accept | invalid
    user: str
    ip: str
    method: str
    invalid: bool = False


def _clean_user(u: str) -> str:
    """Neutralise attacker-controlled usernames (log injection, prompt injection, shell)."""
    u = re.sub(r"[^A-Za-z0-9_.@-]", "?", u)[:32]
    return u or "?"


def _norm_ip(s: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(s.rstrip(":.")))
    except ValueError:
        return None


def _parse_ts(line: str, year: int) -> Optional[datetime]:
    m = _TS_ISO.match(line)
    if m:
        s = m.group(1).replace(",", ".").replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(s).replace(tzinfo=None)
        except ValueError:
            try:
                return datetime.fromisoformat(s[:19]).replace(tzinfo=None)
            except ValueError:
                return None
    m = _TS_SYSLOG.match(line)
    if m:
        try:
            return datetime.strptime(f"{year} {m.group(1)} {int(m.group(2)):02d} {m.group(3)}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
    return None


def parse_events(raw_text: str, year: int):
    events, total_lines = [], 0
    for n, line in enumerate(raw_text.splitlines(), 1):
        total_lines += 1
        if "sshd" not in line:
            continue
        m = _SSHD.search(line)
        if not m:
            continue
        msg = m.group("msg")
        ts = _parse_ts(line, year)
        if (f := _FAILED.search(msg)):
            ip = _norm_ip(f.group("ip"))
            if ip:
                events.append(Event(n, ts, "fail", _clean_user(f.group("user")), ip,
                                    f.group("method"), bool(f.group("invalid"))))
        elif (a := _ACCEPTED.search(msg)):
            ip = _norm_ip(a.group("ip"))
            if ip:
                events.append(Event(n, ts, "accept", _clean_user(a.group("user")), ip, a.group("method")))
        elif (i := _INVALID.search(msg)):
            ip = _norm_ip(i.group("ip"))
            if ip:
                events.append(Event(n, ts, "invalid", _clean_user(i.group("user")), ip, "", True))
    return events, total_lines


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #
def _fmt_ts(ts: Optional[datetime], line_no: int) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S") if ts else f"line {line_no}"


def fmt_duration(sec: float) -> str:
    sec = int(sec)
    if sec < 60:
        return f"{sec}s"
    if sec < 3600:
        return f"{sec // 60}m {sec % 60}s"
    return f"{sec // 3600}h {(sec % 3600) // 60}m"


def _classify(n, unique_users, invalid_ratio, priv_ratio, settings) -> str:
    if n < settings.min_failures:
        return ATTACK_ISOLATED
    if unique_users >= 3:
        if invalid_ratio >= 0.5 or priv_ratio >= 0.5:
            return ATTACK_DICTIONARY
        return ATTACK_SPRAYING
    return ATTACK_GUESSING


def _score(a: dict, settings: Settings) -> tuple[int, list]:
    n = a["failed_attempts"]
    if n < settings.min_failures:
        return 0, [{"factor": "Below detection threshold", "points": 0}]
    pts = []
    if n >= 200:
        pts.append(("Very high volume (200+ failures)", 35))
    elif n >= 50:
        pts.append(("High volume (50+ failures)", 30))
    elif n >= 10:
        pts.append(("Moderate volume (10+ failures)", 20))
    else:
        pts.append((f"Threshold reached ({settings.min_failures}+ failures)", 10))
    r = a["rate_per_min"]
    if r >= 30:
        pts.append((f"Very fast automated rate ({r}/min)", 20))
    elif r >= 10:
        pts.append((f"Fast rate ({r}/min)", 15))
    elif r >= 3:
        pts.append((f"Elevated rate ({r}/min)", 5))
    u = a["unique_users"]
    if u >= 10:
        pts.append((f"Wide account spread ({u} accounts)", 15))
    elif u >= 3:
        pts.append((f"Multiple accounts targeted ({u})", 10))
    if a["privileged_targeted"]:
        pts.append(("Privileged/default account targeted", 15))
    if a["invalid_ratio"] >= 0.5:
        pts.append(("Mostly non-existent usernames", 10))
    if a["attack_type"] == ATTACK_SPRAYING:
        pts.append(("Password-spraying pattern", 10))
    elif a["attack_type"] == ATTACK_DICTIONARY:
        pts.append(("Dictionary/bot pattern", 5))
    if a["internal_source"]:
        pts.append(("Internal source (possible lateral movement / compromised host)", 10))
    if a["compromised"]:
        pts.append(("SUCCESSFUL LOGIN after failures (possible compromise)", 40))
    score = min(100, sum(p for _, p in pts))
    return score, [{"factor": f, "points": p} for f, p in pts]


def _level(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 55:
        return "High"
    if score >= 30:
        return "Medium"
    if score >= 10:
        return "Low"
    return "Informational"


def analyze(raw_text: str, settings: Settings, year: Optional[int] = None) -> dict:
    year = year or datetime.now().year
    priv = {p.strip().lower() for p in settings.privileged if p.strip()}
    events, total_lines = parse_events(raw_text, year)

    fails_by_ip: "OrderedDict[str, list[Event]]" = OrderedDict()
    invalid_seen: dict[str, set] = defaultdict(set)
    accepts: list[Event] = []
    for e in events:
        if e.kind == "fail":
            fails_by_ip.setdefault(e.ip, []).append(e)
        elif e.kind == "accept":
            accepts.append(e)
        else:
            invalid_seen[e.ip].add(e.user)

    attackers = []
    for ip, evs in fails_by_ip.items():
        n = len(evs)
        users = Counter(e.user for e in evs)
        inv_users = {e.user for e in evs if e.invalid} | invalid_seen.get(ip, set())
        invalid_ratio = sum(c for u, c in users.items() if u in inv_users) / n
        priv_hits = [u for u in users if u.lower() in priv]
        priv_ratio = sum(users[u] for u in priv_hits) / n
        stamps = sorted(e.ts for e in evs if e.ts)
        first_ts = stamps[0] if stamps else None
        last_ts = stamps[-1] if stamps else None
        duration = (last_ts - first_ts).total_seconds() if first_ts and last_ts else 0.0
        rate = round(n / max(duration, 1.0) * 60, 1) if n >= 2 else 0.0
        internal = any(ipaddress.ip_address(ip) in net for net in _INTERNAL_NETS
                       if net.version == ipaddress.ip_address(ip).version)

        # success-after-failures check (log order, so it works without timestamps)
        hits = [s for s in accepts if s.ip == ip and sum(1 for f in evs if f.line_no < s.line_no) >= settings.min_failures]
        compromised_users = sorted({s.user for s in hits})

        a = {
            "ip": ip,
            "failed_attempts": n,
            "targets": dict(users.most_common()),
            "unique_users": len(users),
            "invalid_ratio": round(invalid_ratio, 2),
            "privileged_targeted": sorted(priv_hits),
            "first_seen": _fmt_ts(first_ts, evs[0].line_no),
            "last_seen": _fmt_ts(last_ts, evs[-1].line_no),
            "duration_sec": duration,
            "rate_per_min": rate,
            "internal_source": internal,
            "methods": sorted({e.method for e in evs}),
            "compromised": bool(hits),
            "compromised_users": compromised_users,
            "successes_after_failures": [
                {"user": s.user, "time": _fmt_ts(s.ts, s.line_no), "failures_before": sum(1 for f in evs if f.line_no < s.line_no)}
                for s in hits
            ],
        }
        a["attack_type"] = _classify(n, a["unique_users"], invalid_ratio, priv_ratio, settings)
        score, breakdown = _score(a, settings)
        level = _level(score)
        if a["compromised"]:
            level = "Critical"
        elif settings.critical_on_privileged and a["privileged_targeted"] and n >= settings.min_failures:
            level = "Critical"
            breakdown.append({"factor": "Policy: privileged account targeted => Critical", "points": 0})
        a.update(score=score, severity=level, score_breakdown=breakdown)
        a["verdict"] = "Compromised" if a["compromised"] else (
            "Suspicious" if a["attack_type"] != ATTACK_ISOLATED else "Trustworthy")
        attackers.append(a)

    attackers.sort(key=lambda x: (-SEVERITY_ORDER.index(x["severity"]), -x["score"], -x["failed_attempts"]))
    suspicious_ips = {a["ip"] for a in attackers if a["verdict"] != "Trustworthy"}

    # ----- timeline & per-minute series -----
    tl = []
    for a in attackers:
        if a["ip"] not in suspicious_ips:
            continue
        evs = fails_by_ip[a["ip"]]
        tl.append(((evs[0].ts or datetime.min), evs[0].line_no, a["ip"], "First failed attempt", evs[0]))
        if len(evs) > 1:
            tl.append(((evs[-1].ts or datetime.min), evs[-1].line_no, a["ip"], f"Last failed attempt ({a['failed_attempts']} total)", evs[-1]))
    for s in accepts:
        if s.ip in suspicious_ips:
            comp = any(s.user in a["compromised_users"] and a["ip"] == s.ip for a in attackers)
            label = f"SUCCESSFUL LOGIN as '{s.user}'" + (" after brute force - POSSIBLE COMPROMISE" if comp else "")
            tl.append(((s.ts or datetime.min), s.line_no, s.ip, label, s))
    tl.sort(key=lambda t: (t[0], t[1]))
    timeline = [{"time": _fmt_ts(t[4].ts, t[1]), "ip": t[2], "event": t[3]} for t in tl]

    buckets: Counter = Counter()
    for ip in suspicious_ips:
        for e in fails_by_ip.get(ip, []):
            if e.ts:
                buckets[(e.ts.replace(second=0, microsecond=0).isoformat(sep=" "), ip)] += 1
    series = [{"minute": m, "ip": ip, "failures": c} for (m, ip), c in sorted(buckets.items())]

    successful_logins = [
        {"time": _fmt_ts(s.ts, s.line_no), "user": s.user, "ip": s.ip, "method": s.method,
         "after_brute_force": any(s.ip == a["ip"] and s.user in a["compromised_users"] for a in attackers)}
        for s in accepts
    ]

    overall = max((a["severity"] for a in attackers if a["verdict"] != "Trustworthy"),
                  key=SEVERITY_ORDER.index, default="Informational")
    stamps_all = [e.ts for e in events if e.ts]
    return {
        "attackers": attackers,
        "successful_logins": successful_logins,
        "timeline": timeline,
        "series": series,
        "overall_severity": overall,
        "compromise_detected": any(a["compromised"] for a in attackers),
        "stats": {
            "total_lines": total_lines,
            "parsed_events": len(events),
            "failed_events": sum(len(v) for v in fails_by_ip.values()),
            "accepted_events": len(accepts),
            "unique_source_ips": len(fails_by_ip),
            "flagged_ips": len(suspicious_ips),
            "log_start": _fmt_ts(min(stamps_all), 0) if stamps_all else "n/a",
            "log_end": _fmt_ts(max(stamps_all), 0) if stamps_all else "n/a",
        },
    }


# --------------------------------------------------------------------------- #
# Response artefacts (all deterministic)
# --------------------------------------------------------------------------- #
def containment_commands(a: dict, firewall: str = "iptables") -> str:
    ip = a["ip"]
    v6 = ":" in ip
    L = [f"# ---- {ip}  [{a['severity']}] {a['attack_type']} ----"]
    if a["internal_source"]:
        L.append("# NOTE: private/internal address. Identify the host owner first - this may be a compromised internal machine.")
    if firewall in ("iptables", "all"):
        L += ["# iptables", f"sudo {'ip6tables' if v6 else 'iptables'} -I INPUT -s {ip} -j DROP"]
    if firewall in ("ufw", "all"):
        L += ["# ufw", f"sudo ufw insert 1 deny from {ip} to any"]
    if firewall in ("firewalld", "all"):
        fam = "ipv6" if v6 else "ipv4"
        L += ["# firewalld",
              f"sudo firewall-cmd --permanent --add-rich-rule='rule family=\"{fam}\" source address=\"{ip}\" drop'",
              "sudo firewall-cmd --reload"]
    L += ["# terminate existing sessions from this IP",
          f"sudo ss -K dst {ip}            # needs kernel CONFIG_INET_DIAG_DESTROY",
          f"sudo ss -tnp state established dst {ip}   # fallback: find the sshd PID, then: sudo kill <PID>"]
    for u in a["compromised_users"]:
        if _SAFE_USER_CMD.match(u):
            L += [f"# account '{u}' logged in after the attack - treat as compromised",
                  f"sudo loginctl terminate-user {u}",
                  f"sudo passwd -l {u}",
                  f"sudo find ~{u}/.ssh -name authorized_keys -ls   # look for unknown keys"]
        else:
            L.append(f"# account name '{u}' contains unusual characters - handle manually")
    return "\n".join(L)


def wazuh_rules(min_failures: int) -> tuple[str, str]:
    freq = max(5, min_failures)
    rules = f"""<!-- /var/ossec/etc/rules/local_rules.xml  (validate with: /var/ossec/bin/wazuh-logtest) -->
<group name="local,sshd,brute_force,">

  <!-- {freq}+ failed SSH logins from the same IP within 2 minutes -->
  <rule id="100100" level="10" frequency="{freq}" timeframe="120">
    <if_matched_sid>5760</if_matched_sid>
    <same_source_ip />
    <description>sshd: brute-force - {freq}+ failed logins from the same source IP in 120s</description>
    <mitre><id>T1110</id></mitre>
    <group>authentication_failures,</group>
  </rule>

  <!-- probing of non-existent accounts (dictionary / bot behaviour) -->
  <rule id="100101" level="12" frequency="3" timeframe="120">
    <if_matched_sid>5710</if_matched_sid>
    <same_source_ip />
    <description>sshd: repeated login attempts for non-existent users from the same IP</description>
    <mitre><id>T1110.001</id></mitre>
  </rule>

  <!-- successful login right after a brute-force alert = probable compromise -->
  <rule id="100102" level="14">
    <if_sid>5715</if_sid>
    <if_matched_sid>100100</if_matched_sid>
    <same_source_ip />
    <description>sshd: successful login after brute-force from the same IP - POSSIBLE COMPROMISE</description>
    <mitre><id>T1078</id></mitre>
  </rule>

</group>"""
    ar = """<!-- /var/ossec/etc/ossec.conf (manager) - block the attacker for 1 hour -->
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100100,100101</rules_id>
  <timeout>3600</timeout>
</active-response>"""
    return rules, ar


def triage_checklist(analysis: dict) -> list[str]:
    items = []
    for a in analysis["attackers"]:
        if a["verdict"] == "Trustworthy":
            continue
        ip = a["ip"]
        items.append(f"**{ip}** - confirm whether any attempt succeeded: "
                     f"`grep -E \"Accepted .* from {ip}\" /var/log/auth.log` (use `/var/log/secure` on RHEL/CentOS)")
        items.append(f"**{ip}** - review login history: `last -i | grep {ip}` and `sudo lastb -i | grep {ip}`")
        if a["compromised"]:
            items.append(f"**{ip}** - URGENT: account(s) {', '.join('`'+u+'`' for u in a['compromised_users'])} "
                         "logged in after failures. Preserve evidence, then review `~/.bash_history`, "
                         "`~/.ssh/authorized_keys`, cron jobs, new users and listening ports.")
        if a["privileged_targeted"]:
            items.append(f"**{ip}** - privileged account(s) targeted ({', '.join(a['privileged_targeted'])}); "
                         "verify `PermitRootLogin no` in `/etc/ssh/sshd_config`.")
        if a["internal_source"]:
            items.append(f"**{ip}** - internal address: locate the host, check it for malware/compromise.")
    items += [
        "Check for recently modified SSH keys: `sudo find /home /root -name authorized_keys -mtime -2`",
        "Check for new accounts: `sudo awk -F: '$3>=1000{print $1}' /etc/passwd` and compare with the approved list.",
        "Search other services (web, VPN, RDP) for the same source IPs.",
    ]
    return items


def baseline_recommendations(analysis: dict) -> list[str]:
    recs = [
        "Disable password authentication and use SSH keys (`PasswordAuthentication no`).",
        "Set `PermitRootLogin no` and restrict logins with `AllowUsers` / `AllowGroups`.",
        "Deploy fail2ban or Wazuh active response to auto-ban repeated offenders.",
        "Require MFA for any internet-facing SSH access, or place SSH behind a VPN / bastion host.",
        "Rate-limit new SSH connections at the firewall (e.g. `iptables -m recent` / `ufw limit ssh`).",
    ]
    if analysis["compromise_detected"]:
        recs.insert(0, "Rotate credentials and SSH keys of every account that logged in after the attack.")
    return recs


# --------------------------------------------------------------------------- #
# LLM context + deterministic fallback narrative
# --------------------------------------------------------------------------- #
def llm_context(analysis: dict) -> dict:
    return {
        "overall_severity": analysis["overall_severity"],
        "compromise_detected": analysis["compromise_detected"],
        "stats": analysis["stats"],
        "attackers": [
            {k: a[k] for k in ("ip", "failed_attempts", "unique_users", "attack_type", "severity", "score",
                               "rate_per_min", "internal_source", "privileged_targeted", "compromised",
                               "compromised_users", "first_seen", "last_seen")}
            | {"top_targets": list(a["targets"].items())[:8]}
            for a in analysis["attackers"] if a["verdict"] != "Trustworthy"
        ][:10],
    }


def fallback_narrative(analysis: dict) -> str:
    s = analysis["stats"]
    flagged = [a for a in analysis["attackers"] if a["verdict"] != "Trustworthy"]
    if not flagged:
        return ("### Executive Summary\nNo brute-force activity was detected. "
                f"{s['failed_events']} failed login(s) were seen but none reached the detection threshold.")
    lines = [f"### Executive Summary\n{len(flagged)} source IP(s) showed brute-force behaviour across "
             f"{s['failed_events']} failed SSH logins. Overall severity is **{analysis['overall_severity']}**."]
    if analysis["compromise_detected"]:
        lines.append("**A successful login followed the failed attempts from at least one attacker IP; "
                     "treat the account as compromised until proven otherwise.**")
    lines.append("\n### Attacker Assessment")
    for a in flagged:
        lines.append(f"- `{a['ip']}`: {a['attack_type']}, {a['failed_attempts']} failures against "
                     f"{a['unique_users']} account(s) at {a['rate_per_min']}/min - {a['severity']} (score {a['score']}).")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Report assembly
# --------------------------------------------------------------------------- #
def _cell(s: str) -> str:
    return str(s).replace("|", "\\|")


def build_report(analysis: dict, narrative: str, settings: Settings, filename: str, incident_id: str) -> dict:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    flagged = [a for a in analysis["attackers"] if a["verdict"] != "Trustworthy"]
    cmds = {a["ip"]: containment_commands(a, settings.firewall) for a in flagged}
    rules, ar = wazuh_rules(settings.min_failures)
    st = analysis["stats"]

    md = [f"# Incident Report {incident_id}",
          f"**Generated:** {now}  |  **Source:** `{filename}`  |  **Log window:** {st['log_start']} to {st['log_end']}",
          f"**Overall severity:** {analysis['overall_severity']}  |  **Possible compromise:** "
          f"{'YES' if analysis['compromise_detected'] else 'No evidence'}",
          "", "## 1. Executive Summary & Assessment", narrative.strip(), "",
          "## 2. Threat Summary & Detection Table",
          "| Source IP | Target Account(s) | Failed Attempts | Time Span / Frequency | Attack Type | Severity (Score) | Verdict |",
          "|---|---|---|---|---|---|---|"]
    for a in analysis["attackers"]:
        t = ", ".join(f"{u} ({c})" for u, c in list(a["targets"].items())[:5])
        if len(a["targets"]) > 5:
            t += f" +{len(a['targets']) - 5} more"
        span = f"{a['first_seen']} to {a['last_seen']} ({fmt_duration(a['duration_sec'])}, {a['rate_per_min']}/min)"
        md.append(f"| {a['ip']} | {_cell(t)} | {a['failed_attempts']} | {span} | {a['attack_type']} | "
                  f"{a['severity']} ({a['score']}) | {a['verdict']} |")

    md += ["", "## 3. Timeline"]
    md += ([f"- `{e['time']}` - **{e['ip']}** - {e['event']}" for e in analysis["timeline"]] or ["- No suspicious activity."])

    md += ["", "## 4. Indicators of Compromise (IOCs)",
           "**Source IPs:** " + (", ".join(f"`{a['ip']}`" for a in flagged) or "none"),
           "**Targeted accounts:** " + (", ".join(f"`{u}`" for u in sorted({u for a in flagged for u in a['targets']})) or "none")]

    md += ["", "## 5. Compromise Assessment"]
    comp = [a for a in analysis["attackers"] if a["compromised"]]
    if comp:
        for a in comp:
            for s in a["successes_after_failures"]:
                md.append(f"- **POSSIBLE COMPROMISE:** `{s['user']}` logged in from `{a['ip']}` at {s['time']} "
                          f"after {s['failures_before']} failed attempts.")
    else:
        md.append("- No successful login from any flagged IP was found in this log.")
    other = [s for s in analysis["successful_logins"] if not s["after_brute_force"]]
    if other:
        md.append("- Other successful logins (not linked to an attack): " +
                  ", ".join(f"`{s['user']}`@{s['ip']}" for s in other))

    md += ["", "## 6. Triage & Investigation Checklist"] + [f"- [ ] {i}" for i in triage_checklist(analysis)]

    md += ["", f"## 7. Immediate Containment Commands ({settings.firewall})",
           "_Generated from the parsed data (IPs validated); review before running._"]
    md += (["```bash", "\n\n".join(cmds.values()), "```"] if cmds else ["No containment required."])

    md += ["", "## 8. Wazuh Rule & Active Response", "```xml", rules, "```", "```xml", ar, "```",
           "", "## 9. Remediation Recommendations"] + [f"- {r}" for r in baseline_recommendations(analysis)]

    md += ["", "## Appendix: Severity Scoring",
           "Score = volume + rate + account spread + privileged target + invalid-user ratio + attack type + internal source "
           "+ 40 if a successful login followed the failures. Levels: >=75 Critical, >=55 High, >=30 Medium, >=10 Low. "
           "A success-after-failures finding is always Critical."]
    for a in flagged:
        md.append(f"\n**{a['ip']}** - {a['score']}/100")
        md += [f"- {b['factor']}: +{b['points']}" for b in a["score_breakdown"]]

    return {"markdown": "\n".join(md), "commands": cmds, "wazuh_rules": rules, "active_response": ar}


def run_analysis(raw_text: str, filename: str, settings: Settings,
                 narrative_fn: Optional[Callable[[dict, Settings, set], str]] = None) -> dict:
    """Full pipeline. narrative_fn(context, settings, known_ips) -> markdown; may raise."""
    analysis = analyze(raw_text, settings)
    known_ips = {a["ip"] for a in analysis["attackers"]}
    narrative, llm_used, llm_error = None, False, None
    if settings.use_llm and narrative_fn and any(a["verdict"] != "Trustworthy" for a in analysis["attackers"]):
        try:
            narrative = narrative_fn(llm_context(analysis), settings, known_ips)
            llm_used = True
        except Exception as exc:  # LLM down / timeout -> deterministic fallback
            llm_error = str(exc)
    if not narrative:
        narrative = fallback_narrative(analysis)

    digest = hashlib.sha256(raw_text.encode("utf-8", "ignore")).hexdigest()[:6].upper()
    incident_id = f"INC-{datetime.now():%Y%m%d}-{digest}"
    rep = build_report(analysis, narrative, settings, filename, incident_id)
    return {
        "status": "success", "filename": filename, "incident_id": incident_id,
        "llm_used": llm_used, "llm_error": llm_error,
        "analysis": analysis, "report": rep["markdown"],
        "commands": rep["commands"], "wazuh_rules": rep["wazuh_rules"], "active_response": rep["active_response"],
    }


if __name__ == "__main__":
    out = run_analysis(SAMPLE_LOG, "sample.log", Settings(use_llm=False))
    print(out["report"])
    json.dumps(out)  # must be JSON-serialisable
