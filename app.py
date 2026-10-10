"""
app.py - Streamlit dashboard.   Run:  streamlit run app.py
Talks to the FastAPI backend; if the backend is down it falls back to the local
deterministic engine (no AI narrative) so the tool still works.
"""
import json

import altair as alt
import pandas as pd
import requests
import streamlit as st

from engine import (DEFAULT_PRIVILEGED, SAMPLE_LOG, SEVERITY_COLORS, SEVERITY_ORDER,
                    Settings, run_analysis, fmt_duration)

st.set_page_config(page_title="AI Brute-Force IR Platform", page_icon="🛡️", layout="wide")

DEFAULT_RULES = ("- Prioritise containment of internal source IPs.\n"
                 "- Mention checking IP reputation (e.g. AbuseIPDB) for external IPs.")

# ----------------------------- state ----------------------------------------
for k, v in {"custom_rules": DEFAULT_RULES, "log_text": "", "log_name": "", "result": None,
             "uploader_key": 0}.items():
    st.session_state.setdefault(k, v)

# ----------------------------- styling --------------------------------------
st.markdown("""
<style>
.block-container {padding-top: 1.2rem; max-width: 1400px;}
.hero {background: linear-gradient(120deg,#0f172a 0%,#1e3a8a 60%,#2563eb 100%);
       padding: 22px 28px; border-radius: 16px; color: #fff; margin-bottom: 14px;}
.hero h1 {margin:0; font-size: 1.9rem; color:#fff;} .hero p {margin:4px 0 0; opacity:.85;}
.kpi {background: var(--secondary-background-color); border-radius: 14px; padding: 14px 16px;
      border-left: 6px solid var(--c,#64748b);}
.kpi .l {font-size:.75rem; text-transform:uppercase; letter-spacing:.06em; opacity:.7;}
.kpi .v {font-size:1.8rem; font-weight:700; line-height:1.2;}
.badge {display:inline-block; padding:2px 10px; border-radius:999px; color:#fff; font-weight:600; font-size:.8rem;}
.banner {border-radius:12px; padding:14px 18px; color:#fff; font-weight:600; margin:10px 0;}
</style>
""", unsafe_allow_html=True)


def badge(level: str) -> str:
    return f'<span class="badge" style="background:{SEVERITY_COLORS[level]}">{level}</span>'


def kpi(col, label, value, color="#64748b"):
    col.markdown(f'<div class="kpi" style="--c:{color}"><div class="l">{label}</div>'
                 f'<div class="v">{value}</div></div>', unsafe_allow_html=True)


@st.cache_data(ttl=8, show_spinner=False)
def backend_health(url: str):
    try:
        return requests.get(f"{url}/health", timeout=1.5).json()
    except Exception:
        return None


# ----------------------------- sidebar --------------------------------------
with st.sidebar:
    st.title("⚙️ Configuration")
    backend_url = st.text_input("Backend URL", "http://127.0.0.1:8000")
    health = backend_health(backend_url)
    if health is None:
        st.error("Backend offline - local engine (no AI) will be used")
    elif health["ollama"]["reachable"] and health["ollama"]["model_installed"]:
        st.success(f"Backend + Ollama ({health['ollama']['model']}) ready")
    elif health["ollama"]["reachable"]:
        st.warning(f"Ollama up, model '{health['ollama']['model']}' not installed")
    else:
        st.warning("Backend online, Ollama unreachable - report will use fallback narrative")

    st.subheader("Detection")
    min_failures = st.slider("Min. failed logins to flag an IP", 2, 20, 3)
    privileged = st.text_input("Privileged / default accounts", ",".join(DEFAULT_PRIVILEGED))
    critical_priv = st.checkbox("Force 'Critical' when a privileged account is targeted", False)
    firewall = st.selectbox("Firewall for containment commands", ["iptables", "ufw", "firewalld", "all"])

    st.subheader("AI narrative")
    use_llm = st.toggle("Use local Llama 3 for the narrative", True)
    rules = st.text_area("Analyst guidance (wording & priorities only)", st.session_state["custom_rules"], height=140,
                         help="Severity and counts are computed in code and cannot be changed by this text.")
    c1, c2 = st.columns(2)
    if c1.button("Save", type="primary", use_container_width=True):
        st.session_state["custom_rules"] = rules
        st.toast("Guidance saved")
    if c2.button("Reset", use_container_width=True):
        st.session_state["custom_rules"] = DEFAULT_RULES
        st.rerun()

# ----------------------------- header ---------------------------------------
st.markdown('<div class="hero"><h1>🛡️ AI Brute-Force Incident Response Platform</h1>'
            '<p>Log detection &rarr; severity scoring &rarr; AI playbook &rarr; incident report, in one lightweight tool</p></div>',
            unsafe_allow_html=True)

# ----------------------------- ingestion ------------------------------------
st.subheader("1 · Ingest authentication logs")
left, right = st.columns([1.2, 1])
with left:
    up = st.file_uploader("Upload .log / .txt / .csv (syslog or ISO-timestamp sshd logs)", type=["log", "txt", "csv"],
                          key=f"up_{st.session_state['uploader_key']}")
    if up is not None:
        st.session_state["log_text"] = up.getvalue().decode("utf-8", errors="ignore")
        st.session_state["log_name"] = up.name
with right:
    st.write("")
    st.write("")
    b1, b2 = st.columns(2)
    if b1.button("Load sample log", use_container_width=True):
        st.session_state.update(log_text=SAMPLE_LOG, log_name="sample_ssh_bruteforce.log", result=None)
    if b2.button("Clear", use_container_width=True):
        st.session_state.update(log_text="", log_name="", result=None,
                                uploader_key=st.session_state["uploader_key"] + 1)
        st.rerun()

log_text, log_name = st.session_state["log_text"], st.session_state["log_name"]
if log_text:
    with st.expander(f"Preview: {log_name} ({len(log_text.splitlines())} lines)", expanded=False):
        st.code(log_text[:4000] + ("\n... [truncated for display]" if len(log_text) > 4000 else ""), language="log")
    run = st.button("🔍 Analyze & generate incident report", type="primary", use_container_width=True)
else:
    run = False
    st.info("Upload a log file or click **Load sample log** to begin.")

# ----------------------------- run ------------------------------------------
if run:
    settings = Settings(min_failures=min_failures,
                        privileged=[p.strip() for p in privileged.split(",") if p.strip()],
                        firewall=firewall, critical_on_privileged=critical_priv,
                        custom_rules=st.session_state["custom_rules"], use_llm=use_llm)
    with st.status("Running analysis pipeline...", expanded=True) as status:
        st.write("Parsing sshd events and grouping by source IP...")
        st.write("Scoring severity and checking for successful logins after failures...")
        try:
            if health is None:
                raise requests.exceptions.ConnectionError
            st.write("Generating AI narrative via backend..." if use_llm else "Building report...")
            resp = requests.post(
                f"{backend_url}/analyze-logs",
                files={"file": (log_name, log_text.encode("utf-8"), "text/plain")},
                data={"custom_rules": settings.custom_rules, "min_failures": min_failures,
                      "privileged_accounts": privileged, "firewall": firewall,
                      "critical_on_privileged": str(critical_priv).lower(), "use_llm": str(use_llm).lower()},
                timeout=320)
            if resp.status_code != 200:
                status.update(label="Analysis failed", state="error")
                st.error(resp.json().get("detail", "Unknown backend error"))
                st.stop()
            st.session_state["result"] = resp.json()
        except requests.exceptions.ConnectionError:
            st.warning("Backend unreachable - used the local engine (deterministic report, no AI narrative).")
            settings.use_llm = False
            st.session_state["result"] = run_analysis(log_text, log_name, settings)
        except requests.exceptions.Timeout:
            status.update(label="Timed out", state="error")
            st.error("The backend timed out. Ollama may still be processing - try again or disable the AI narrative.")
            st.stop()
        status.update(label="Analysis complete", state="complete", expanded=False)

# ----------------------------- results --------------------------------------
res = st.session_state["result"]
if res:
    A = res["analysis"]
    st_ = A["stats"]
    sev = A["overall_severity"]
    st.subheader("2 · Incident dashboard")

    if A["compromise_detected"]:
        st.markdown('<div class="banner" style="background:#7f1d1d">🚨 POSSIBLE COMPROMISE - a successful login '
                    'followed a brute-force attack. Contain and investigate immediately.</div>', unsafe_allow_html=True)
    elif sev in ("High", "Critical"):
        st.markdown(f'<div class="banner" style="background:{SEVERITY_COLORS[sev]}">⚠️ {sev} severity brute-force '
                    'activity detected - no successful login observed.</div>', unsafe_allow_html=True)
    elif st_["flagged_ips"] == 0:
        st.markdown('<div class="banner" style="background:#166534">✅ No brute-force activity detected.</div>',
                    unsafe_allow_html=True)

    k = st.columns(5)
    kpi(k[0], "Incident ID", f'<span style="font-size:1.1rem">{res["incident_id"]}</span>', "#2563eb")
    kpi(k[1], "Overall severity", sev, SEVERITY_COLORS[sev])
    kpi(k[2], "Failed logins", st_["failed_events"], "#ea580c")
    kpi(k[3], "Flagged attacker IPs", st_["flagged_ips"], "#dc2626" if st_["flagged_ips"] else "#16a34a")
    kpi(k[4], "AI narrative", "Llama 3" if res["llm_used"] else "Fallback", "#7c3aed" if res["llm_used"] else "#64748b")
    if res.get("llm_error"):
        st.caption(f"AI narrative unavailable ({res['llm_error'][:120]}); deterministic summary used.")

    tabs = st.tabs(["📊 Overview", "🎯 Attackers", "📄 Incident report", "🛠️ Response playbook", "🕒 Timeline"])
    attackers = A["attackers"]

    with tabs[0]:
        if attackers:
            df = pd.DataFrame([{"ip": a["ip"], "failures": a["failed_attempts"], "severity": a["severity"],
                                "score": a["score"]} for a in attackers])
            c1, c2 = st.columns(2)
            color = alt.Color("severity:N", scale=alt.Scale(domain=SEVERITY_ORDER,
                              range=[SEVERITY_COLORS[s] for s in SEVERITY_ORDER]), legend=alt.Legend(orient="bottom"))
            c1.markdown("**Failed attempts per source IP**")
            c1.altair_chart(alt.Chart(df).mark_bar(cornerRadiusEnd=4).encode(
                x="failures:Q", y=alt.Y("ip:N", sort="-x", title=None), color=color,
                tooltip=["ip", "failures", "severity", "score"]).properties(height=60 + 38 * len(df)),
                use_container_width=True)
            c2.markdown("**Risk score per source IP (0-100)**")
            c2.altair_chart(alt.Chart(df).mark_bar(cornerRadiusEnd=4).encode(
                x=alt.X("score:Q", scale=alt.Scale(domain=[0, 100])), y=alt.Y("ip:N", sort="-x", title=None),
                color=color, tooltip=["ip", "score", "severity"]).properties(height=60 + 38 * len(df)),
                use_container_width=True)
        if A["series"]:
            st.markdown("**Failed logins per minute (flagged IPs)**")
            sdf = pd.DataFrame(A["series"])
            sdf["minute"] = pd.to_datetime(sdf["minute"])
            st.altair_chart(alt.Chart(sdf).mark_line(point=True).encode(
                x=alt.X("minute:T", title=None), y=alt.Y("failures:Q", title="failures / min"),
                color="ip:N", tooltip=["minute", "ip", "failures"]).properties(height=260), use_container_width=True)
        if A["successful_logins"]:
            st.markdown("**Successful logins in the log**")
            st.dataframe(pd.DataFrame(A["successful_logins"]).rename(columns={"after_brute_force": "after attack?"}),
                         hide_index=True, use_container_width=True)

    with tabs[1]:
        if not attackers:
            st.info("No failed logins found.")
        for a in attackers:
            with st.expander(f"{a['ip']}  ·  {a['severity']}  ·  {a['attack_type']}  ·  {a['failed_attempts']} failures",
                             expanded=a["severity"] in ("Critical", "High")):
                st.markdown(badge(a["severity"]) + f" &nbsp; **Score {a['score']}/100** &nbsp; Verdict: **{a['verdict']}**"
                            + (" &nbsp; 🏠 internal" if a["internal_source"] else ""), unsafe_allow_html=True)
                m = st.columns(4)
                m[0].metric("Failures", a["failed_attempts"])
                m[1].metric("Accounts targeted", a["unique_users"])
                m[2].metric("Rate / min", a["rate_per_min"])
                m[3].metric("Duration", fmt_duration(a["duration_sec"]))
                st.caption(f"{a['first_seen']}  →  {a['last_seen']}")
                c1, c2 = st.columns(2)
                c1.markdown("**Targeted accounts**")
                c1.dataframe(pd.DataFrame(list(a["targets"].items()), columns=["account", "attempts"]),
                             hide_index=True, use_container_width=True)
                c2.markdown("**Why this score**")
                c2.dataframe(pd.DataFrame(a["score_breakdown"]), hide_index=True, use_container_width=True)
                for s in a["successes_after_failures"]:
                    st.error(f"Possible compromise: '{s['user']}' logged in at {s['time']} after {s['failures_before']} failures.")

    with tabs[2]:
        d1, d2, _ = st.columns([1, 1, 3])
        d1.download_button("⬇️ Markdown", res["report"], file_name=f"{res['incident_id']}.md", mime="text/markdown",
                           use_container_width=True)
        d2.download_button("⬇️ JSON", json.dumps(res, indent=2), file_name=f"{res['incident_id']}.json",
                           mime="application/json", use_container_width=True)
        st.markdown(res["report"])

    with tabs[3]:
        st.markdown("#### Containment commands")
        st.caption("Generated from validated, parsed IPs - review before running. Private IPs carry a warning.")
        if res["commands"]:
            for ip, cmd in res["commands"].items():
                st.code(cmd, language="bash")
        else:
            st.info("No containment needed.")
        st.markdown("#### Wazuh custom rules (`local_rules.xml`)")
        st.code(res["wazuh_rules"], language="xml")
        st.markdown("#### Active response (`ossec.conf`)")
        st.code(res["active_response"], language="xml")

    with tabs[4]:
        if A["timeline"]:
            st.dataframe(pd.DataFrame(A["timeline"]), hide_index=True, use_container_width=True)
        else:
            st.info("No suspicious activity to show.")
