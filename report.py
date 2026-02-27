import json
from collections import defaultdict
from models import ScanResult, SEVERITY_ORDER

try:
    from colorama import Fore, Style
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = WHITE = MAGENTA = BLUE = ""
    class Style:
        RESET_ALL = BRIGHT = ""

SEV_COLOR = {
    "CRITICAL": Fore.RED + Style.BRIGHT,
    "HIGH":     Fore.RED,
    "MEDIUM":   Fore.YELLOW,
    "LOW":      Fore.CYAN,
    "INFO":     Fore.WHITE,
}
SEV_BADGE_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#ca8a04",
    "LOW":      "#2563eb",
    "INFO":     "#6b7280",
}

# Stats keys rendered in dedicated sections rather than the generic flat table
_SPECIAL_STATS = {
    # original
    "adcs_template_inventory",
    "laps_covered", "laps_missing", "laps_total_hosts",
    "laps_legacy_schema", "laps_winlaps_schema",
    "deprecated_os_count",
    "unconstrained_delegation_computers", "unconstrained_delegation_users",
    "constrained_delegation_proto_transition", "constrained_delegation_standard",
    "admincount1_total", "admincount1_disabled",
    "admincount1_stale", "admincount1_orphaned",
    "passwords_in_descriptions_users", "passwords_in_descriptions_admins",
    "passwords_in_descriptions_computers",
    "gpo_disabled", "gpo_orphaned", "gpo_unlinked", "gpo_empty",
    # new – checks 25–35
    "gpp_sysvol_accessible", "gpp_cpassword_count",
    "adminsdholder_risky_aces",
    "sid_history_count",
    "shadow_credentials_count",
    "rc4_service_accounts", "rc4_domain_controllers", "admin_no_aes_encryption",
    "foreign_security_principals_in_priv_groups",
    "pre_win2k_members", "pre_win2k_everyone", "pre_win2k_anon",
    "dangerous_delegation_targets",
    "subnet_count", "orphaned_subnet_count",
    "frs_subscriber_count", "dfsr_subscriber_count", "sysvol_using_frs",
    "rbcd_on_domain_object", "rbcd_on_dc_count",
}

_FINDINGS_COLGROUP = """
<colgroup>
  <col style="width:90px">
  <col style="width:40%">
  <col>
  <col style="width:52px">
</colgroup>"""

_GLANCE_MAX  = 5
_GLANCE_SEVS = {"CRITICAL", "HIGH"}


# ── At-a-glance ───────────────────────────────────────────────────────────────

def _top_critical_findings(result: ScanResult, max_n: int = _GLANCE_MAX):
    eligible = [f for f in result.findings if f.severity in _GLANCE_SEVS]
    eligible.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 5), -(f.risk_score or 0)))
    return eligible[:max_n]


# ── Stat-card builder ─────────────────────────────────────────────────────────

def _build_stat_cards(result: ScanResult) -> list:
    s     = result.stats
    cards = []

    # LAPS coverage
    total = s.get("laps_total_hosts")
    if total is not None:
        missing  = s.get("laps_missing", 0)
        covered  = s.get("laps_covered", 0)
        pct_ok   = int(100 * covered / total) if total else 100
        col      = "#16a34a" if pct_ok == 100 else ("#ca8a04" if pct_ok >= 80 else "#dc2626")
        cards.append({"label": "LAPS Coverage",
                      "value": f"{pct_ok}%",
                      "sub":   f"{covered}/{total} hosts",
                      "color": col})

    # Deprecated OS
    dep = s.get("deprecated_os_count")
    if dep is not None:
        cards.append({"label": "Deprecated OS",
                      "value": str(dep),
                      "sub":   "active computers",
                      "color": "#dc2626" if dep > 0 else "#16a34a"})

    # Unconstrained delegation
    unc_c = s.get("unconstrained_delegation_computers")
    unc_u = s.get("unconstrained_delegation_users")
    if unc_c is not None:
        total_unc = (unc_c or 0) + (unc_u or 0)
        cards.append({"label": "Unconstrained Delegation",
                      "value": str(total_unc),
                      "sub":   f"{unc_c} computers / {unc_u} users",
                      "color": "#dc2626" if total_unc > 0 else "#16a34a"})

    # adminCount=1
    adm_total  = s.get("admincount1_total")
    adm_orphan = s.get("admincount1_orphaned")
    if adm_total is not None:
        col = "#dc2626" if adm_orphan else ("#ca8a04" if adm_total > 20 else "#16a34a")
        cards.append({"label": "adminCount=1 Accounts",
                      "value": str(adm_total),
                      "sub":   f"{adm_orphan} orphaned" if adm_orphan else "no orphans",
                      "color": col})

    # Passwords in descriptions
    pwd_adm   = s.get("passwords_in_descriptions_admins", 0) or 0
    pwd_usr   = s.get("passwords_in_descriptions_users",  0) or 0
    pwd_cmp   = s.get("passwords_in_descriptions_computers", 0) or 0
    pwd_total = pwd_adm + pwd_usr + pwd_cmp
    if s.get("passwords_in_descriptions_admins") is not None or \
       s.get("passwords_in_descriptions_users")  is not None:
        col = "#dc2626" if pwd_adm else ("#ea580c" if pwd_total else "#16a34a")
        cards.append({"label": "Passwords in Descriptions",
                      "value": str(pwd_total),
                      "sub":   f"{pwd_adm} admin / {pwd_usr} user / {pwd_cmp} computer",
                      "color": col})

    # GPO hygiene
    gpo_total = s.get("gpo_count")
    gpo_bad   = (s.get("gpo_orphaned") or 0) + (s.get("gpo_unlinked") or 0)
    if gpo_total is not None:
        col = "#dc2626" if gpo_bad > 10 else ("#ca8a04" if gpo_bad else "#16a34a")
        cards.append({"label": "GPOs",
                      "value": str(gpo_total),
                      "sub":   f"{gpo_bad} orphaned/unlinked",
                      "color": col})

    # ── New cards (checks 25–35) ──────────────────────────────────────────────

    # GPP cpassword
    gpp_count = s.get("gpp_cpassword_count")
    if gpp_count is not None:
        col = "#dc2626" if gpp_count > 0 else "#16a34a"
        accessible = s.get("gpp_sysvol_accessible", False)
        sub = f"{gpp_count} plaintext password(s)" if accessible else "SYSVOL not accessible"
        cards.append({"label": "GPP cpassword (MS14-025)",
                      "value": str(gpp_count) if accessible else "?",
                      "sub":   sub,
                      "color": col})

    # SID history
    sid_hist = s.get("sid_history_count")
    if sid_hist is not None:
        cards.append({"label": "SID History Entries",
                      "value": str(sid_hist),
                      "sub":   "accounts with sIDHistory set",
                      "color": "#dc2626" if sid_hist > 0 else "#16a34a"})

    # Shadow credentials
    shadow = s.get("shadow_credentials_count")
    if shadow is not None:
        cards.append({"label": "Shadow Credentials",
                      "value": str(shadow),
                      "sub":   "msDS-KeyCredentialLink entries",
                      "color": "#dc2626" if shadow > 0 else "#16a34a"})

    # RC4 service accounts
    rc4_svc = s.get("rc4_service_accounts")
    if rc4_svc is not None:
        cards.append({"label": "RC4-Permitted Service Accts",
                      "value": str(rc4_svc),
                      "sub":   "Kerberoastable with weak hash",
                      "color": "#dc2626" if rc4_svc > 0 else "#16a34a"})

    # AdminSDHolder
    ash = s.get("adminsdholder_risky_aces")
    if ash is not None:
        cards.append({"label": "AdminSDHolder Bad ACEs",
                      "value": str(ash),
                      "sub":   "non-privileged write ACEs",
                      "color": "#dc2626" if ash > 0 else "#16a34a"})

    # RBCD on domain / DCs
    rbcd_dom = s.get("rbcd_on_domain_object")
    rbcd_dc  = s.get("rbcd_on_dc_count", 0) or 0
    if rbcd_dom is not None:
        total_rbcd = (1 if rbcd_dom else 0) + rbcd_dc
        cards.append({"label": "RBCD on Domain/DCs",
                      "value": str(total_rbcd),
                      "sub":   "domain obj + DC objects affected",
                      "color": "#dc2626" if total_rbcd > 0 else "#16a34a"})

    return cards


# ── Console helpers ───────────────────────────────────────────────────────────

def _cs(label: str, value, warn_above: int = 0):
    if value is None:
        return
    col   = (Fore.RED + Style.BRIGHT) if (isinstance(value, (int, float)) and value > warn_above) \
            else (Fore.RED + Style.BRIGHT if value is True else Fore.GREEN)
    reset = Style.RESET_ALL
    print(f"  {label:<40} {col}{value}{reset}")


# ── Console report ────────────────────────────────────────────────────────────

def print_report(result: ScanResult):
    W = 72
    print(f"\n{'='*W}")
    print("  ADPulse ACTIVE DIRECTORY SECURITY SCAN REPORT")
    print(f"{'='*W}")
    print(f"  Domain      : {result.domain}")
    print(f"  DC          : {result.dc_ip}")
    print(f"  Scanned     : {result.scan_time}")
    score = result.total_score
    sc    = Fore.GREEN if score >= 80 else (Fore.YELLOW if score >= 60 else Fore.RED)
    print(f"  Risk Score  : {sc}{score}/100  [{result.risk_level}]{Style.RESET_ALL}")
    print(f"{'='*W}\n")

    counts = result.counts()
    print("SUMMARY:")
    for sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
        c = counts.get(sev, 0)
        if c:
            print(f"  {SEV_COLOR[sev]}{sev:<10}{Style.RESET_ALL}: {c} finding(s)")

    top = _top_critical_findings(result)
    print(f"\n{'─'*W}")
    print("AT A GLANCE — MOST CRITICAL FINDINGS:")
    print(f"{'─'*W}")
    if top:
        for f in top:
            col = SEV_COLOR.get(f.severity, "")
            print(f"  {col}[{f.severity}]{Style.RESET_ALL}  {f.title}")
            print(f"    {f.description}")
            if f.recommendation:
                print(f"    {Fore.GREEN}>> {f.recommendation}{Style.RESET_ALL}")
        print()
    else:
        print(f"  {Fore.GREEN}No critical or high-severity findings.{Style.RESET_ALL}\n")

    cards = _build_stat_cards(result)
    if cards:
        print(f"{'─'*W}")
        print("KEY METRICS:")
        print(f"{'─'*W}")
        c_map = {
            "#dc2626": Fore.RED + Style.BRIGHT,
            "#ea580c": Fore.RED,
            "#ca8a04": Fore.YELLOW,
            "#16a34a": Fore.GREEN,
        }
        for card in cards:
            col = c_map.get(card["color"], "")
            print(f"  {card['label']:<38}{col}{card['value']:<8}{Style.RESET_ALL} ({card['sub']})")

    print(f"\n{'─'*W}")
    print("FINDINGS (sorted by severity):")
    print(f"{'─'*W}\n")

    for f in result.findings_by_severity():
        if f.severity == "INFO":
            continue
        color = SEV_COLOR.get(f.severity, "")
        print(f"  {color}[{f.severity}]{Style.RESET_ALL} [{f.category}]  {f.title}")
        print(f"    {f.description}")
        if f.details:
            for d in f.details[:10]:
                print(f"      * {d}")
            if len(f.details) > 10:
                print(f"      ... (+{len(f.details) - 10} more)")
        if f.recommendation:
            print(f"    {Fore.GREEN}>> {f.recommendation}{Style.RESET_ALL}")
        if f.references:
            for ref in f.references:
                print(f"    {Fore.BLUE}-> {ref}{Style.RESET_ALL}")
        print()

    inventory = result.stats.get("adcs_template_inventory", [])
    if inventory:
        print(f"{'─'*W}")
        print("ADCS TEMPLATE INVENTORY:")
        print(f"{'─'*W}")
        for entry in inventory:
            name, status = entry.split(": ", 1)
            if status == "OK":
                col = Fore.GREEN; marker = "[OK]   "
            else:
                col = Fore.RED;   marker = "[VULN] "
            print(f"  {col}{marker}{Style.RESET_ALL} {name:<45} {status}")
        print()

    s = result.stats
    print(f"{'─'*W}")
    print("ADDITIONAL CHECK SUMMARY:")
    print(f"{'─'*W}")
    # Original stats
    _cs("Deprecated OS computers",          s.get("deprecated_os_count"))
    _cs("Unconstrained deleg. (computers)", s.get("unconstrained_delegation_computers"))
    _cs("Unconstrained deleg. (users)",     s.get("unconstrained_delegation_users"))
    _cs("Constrained deleg. (proto-xtn)",   s.get("constrained_delegation_proto_transition"))
    _cs("Constrained deleg. (standard)",    s.get("constrained_delegation_standard"), warn_above=-1)
    _cs("LAPS missing (non-DC hosts)",      s.get("laps_missing"))
    laps_t = s.get("laps_total_hosts")
    if laps_t:
        pct = int(100 * (s.get("laps_covered") or 0) / laps_t)
        col = Fore.GREEN if pct==100 else (Fore.YELLOW if pct>=80 else Fore.RED+Style.BRIGHT)
        print(f"  {'LAPS coverage':<40} {col}{pct}%{Style.RESET_ALL}  ({s.get('laps_covered')}/{laps_t})")
    _cs("adminCount=1 (total)",             s.get("admincount1_total"), warn_above=20)
    _cs("adminCount=1 (orphaned)",          s.get("admincount1_orphaned"))
    _cs("adminCount=1 (disabled/ghost)",    s.get("admincount1_disabled"))
    _cs("adminCount=1 (stale)",             s.get("admincount1_stale"))
    _cs("Passwords in desc. (admins)",      s.get("passwords_in_descriptions_admins"))
    _cs("Passwords in desc. (users)",       s.get("passwords_in_descriptions_users"))
    _cs("Passwords in desc. (computers)",   s.get("passwords_in_descriptions_computers"))
    _cs("GPOs (orphaned)",                  s.get("gpo_orphaned"))
    _cs("GPOs (unlinked)",                  s.get("gpo_unlinked"))
    _cs("GPOs (empty/never edited)",        s.get("gpo_empty"))
    # New stats (checks 25–35)
    print()
    gpp_acc = s.get("gpp_sysvol_accessible")
    if gpp_acc is False:
        print(f"  {'GPP cpassword scan':<40} {Fore.YELLOW}SYSVOL not accessible{Style.RESET_ALL}")
    else:
        _cs("GPP cpassword hits (MS14-025)",     s.get("gpp_cpassword_count"))
    _cs("AdminSDHolder risky ACEs",         s.get("adminsdholder_risky_aces"))
    _cs("SID history (total accounts)",     s.get("sid_history_count"))
    _cs("Shadow credentials (total)",       s.get("shadow_credentials_count"))
    _cs("RC4-permitted service accounts",   s.get("rc4_service_accounts"))
    _cs("RC4-permitted domain controllers", s.get("rc4_domain_controllers"))
    _cs("Admin accts without AES enctype",  s.get("admin_no_aes_encryption"))
    _cs("FSPs in privileged groups",        s.get("foreign_security_principals_in_priv_groups"))
    pre_ev = s.get("pre_win2k_everyone")
    pre_an = s.get("pre_win2k_anon")
    if pre_ev is not None:
        tag = ""
        if pre_ev: tag += " [EVERYONE]"
        if pre_an: tag += " [ANON]"
        col = (Fore.RED+Style.BRIGHT) if (pre_ev or pre_an) else Fore.GREEN
        print(f"  {'Pre-Win2k group (dangerous members)':<40} {col}{pre_ev or pre_an}{tag}{Style.RESET_ALL}")
    _cs("Dangerous delegation targets",     s.get("dangerous_delegation_targets"))
    _cs("Orphaned AD subnets",              s.get("orphaned_subnet_count"))
    frs = s.get("sysvol_using_frs")
    if frs is not None:
        col = Fore.RED+Style.BRIGHT if frs else Fore.GREEN
        print(f"  {'SYSVOL uses legacy FRS':<40} {col}{frs}{Style.RESET_ALL}")
    rbcd_dom = s.get("rbcd_on_domain_object")
    if rbcd_dom is not None:
        col = Fore.RED+Style.BRIGHT if rbcd_dom else Fore.GREEN
        print(f"  {'RBCD on domain object':<40} {col}{rbcd_dom}{Style.RESET_ALL}")
    _cs("RBCD on DC computer objects",      s.get("rbcd_on_dc_count"))
    print()


# ── JSON export ───────────────────────────────────────────────────────────────

def export_json(result: ScanResult, path: str):
    data = {
        "domain":     result.domain,
        "dc_ip":      result.dc_ip,
        "scan_time":  result.scan_time,
        "risk_score": result.total_score,
        "risk_level": result.risk_level,
        "stats":      result.stats,
        "findings": [
            {
                "category":       f.category,
                "title":          f.title,
                "severity":       f.severity,
                "description":    f.description,
                "details":        f.details,
                "recommendation": f.recommendation,
                "risk_score":     f.risk_score,
                "references":     f.references,
            }
            for f in result.findings
        ],
    }
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(data, fp, indent=2, default=str)
    print(f"[+] JSON report -> {path}")


# ── HTML helpers ──────────────────────────────────────────────────────────────

def _build_template_inventory_html(inventory: list) -> str:
    if not inventory:
        return ""
    rows = ""
    vuln_count = clean_count = 0
    for entry in inventory:
        name, status = entry.split(": ", 1)
        if status == "OK":
            clean_count += 1
            badge = '<span class="badge" style="background:#16a34a">OK</span>'
        else:
            vuln_count += 1
            badge = "".join(
                f'<span class="badge" style="background:#dc2626;margin-right:3px">{e.strip()}</span>'
                for e in status.split(",")
            )
        rows += f"<tr><td><code>{name}</code></td><td>{badge}</td></tr>"
    header_badge = (
        '<span class="badge" style="background:#dc2626">CRITICAL</span>'
        if vuln_count else
        '<span class="badge" style="background:#16a34a">OK</span>'
    )
    summary = (f"{vuln_count} vulnerable / {clean_count} clean"
               if vuln_count else f"All {clean_count} templates clean")
    return (
        f'<div class="cat-section" style="margin-top:1rem">'
        f'<div class="cat-header" onclick="toggle(this)">'
        f'{header_badge}'
        f'<span class="cat-title">ADCS Certificate Template Inventory</span>'
        f'<span class="cat-count">{summary}</span>'
        f'<span class="chevron">&#9660;</span>'
        f"</div>"
        f'<div class="cat-body collapsed">'
        f"<table>"
        f"<colgroup><col style='width:60%'><col></colgroup>"
        f"<tr><th>Template</th><th>Status</th></tr>{rows}</table>"
        f"</div></div>"
    )


def _build_stat_cards_html(result: ScanResult) -> str:
    cards = _build_stat_cards(result)
    if not cards:
        return ""
    html = '<div class="card-row">'
    for c in cards:
        html += (
            f'<div class="stat-card" style="border-top:3px solid {c["color"]}">'
            f'<div class="card-label">{c["label"]}</div>'
            f'<div class="card-value" style="color:{c["color"]}">{c["value"]}</div>'
            f'<div class="card-sub">{c["sub"]}</div>'
            f"</div>"
        )
    html += "</div>"
    return html


def _build_critical_findings_html(result: ScanResult) -> str:
    top = _top_critical_findings(result)
    if not top:
        return (
            '<div class="glance-empty">'
            '<span style="color:#16a34a;font-weight:bold">'
            '&#10003; No critical or high-severity findings</span>'
            '</div>'
        )
    items = ""
    for f in top:
        col = SEV_BADGE_COLOR.get(f.severity, "#6b7280")
        rec = (f'<div class="glance-rec">{f.recommendation}</div>'
               if f.recommendation else "")
        items += (
            f'<div class="glance-item" style="border-left:3px solid {col}">'
            f'<div class="glance-header">'
            f'<span class="badge" style="background:{col}">{f.severity}</span>'
            f'<span class="glance-title">{f.title}</span>'
            f'<span class="glance-score">-{f.risk_score} pts</span>'
            f'</div>'
            f'<div class="glance-desc">{f.description}</div>'
            f'{rec}'
            f'</div>'
        )
    return items


def _bool_badge(val) -> str:
    if val is True:
        return '<span style="color:#dc2626;font-weight:bold">YES &#9888;</span>'
    if val is False:
        return '<span style="color:#16a34a;font-weight:bold">No</span>'
    return str(val)


def _int_cell(val, warn_above: int = 0) -> str:
    if val is None:
        return "—"
    col = "#dc2626" if val > warn_above else "#16a34a"
    return f'<span style="color:{col};font-weight:bold">{val}</span>'


def _build_new_checks_table_html(result: ScanResult) -> str:
    s = result.stats

    # ── Original rows ──
    orig_rows = [
        ("Deprecated OS computers",          s.get("deprecated_os_count"),               0),
        ("Unconstrained deleg. (comp.)",     s.get("unconstrained_delegation_computers"), 0),
        ("Unconstrained deleg. (users)",     s.get("unconstrained_delegation_users"),     0),
        ("Constrained deleg. (proto-xtn)",   s.get("constrained_delegation_proto_transition"), 0),
        ("Constrained deleg. (standard)",    s.get("constrained_delegation_standard"),    None),
        ("LAPS hosts missing password",      s.get("laps_missing"),                      0),
        ("adminCount=1 (total)",             s.get("admincount1_total"),                 None),
        ("adminCount=1 (orphaned)",          s.get("admincount1_orphaned"),              0),
        ("adminCount=1 (disabled/ghost)",    s.get("admincount1_disabled"),              0),
        ("adminCount=1 (stale)",             s.get("admincount1_stale"),                 0),
        ("Passwords in desc. (admins)",      s.get("passwords_in_descriptions_admins"),  0),
        ("Passwords in desc. (users)",       s.get("passwords_in_descriptions_users"),   0),
        ("Passwords in desc. (computers)",   s.get("passwords_in_descriptions_computers"), 0),
        ("GPOs (orphaned)",                  s.get("gpo_orphaned"),                      0),
        ("GPOs (unlinked)",                  s.get("gpo_unlinked"),                      0),
        ("GPOs (empty/never edited)",        s.get("gpo_empty"),                         0),
    ]

    # LAPS coverage percentage
    laps_t      = s.get("laps_total_hosts")
    laps_cov_html = ""
    if laps_t:
        pct = int(100 * (s.get("laps_covered") or 0) / laps_t)
        col = "#16a34a" if pct == 100 else ("#ca8a04" if pct >= 80 else "#dc2626")
        laps_cov_html = (
            f"<tr><td>LAPS coverage</td>"
            f'<td><span style="color:{col};font-weight:bold">{pct}%</span> '
            f'({s.get("laps_covered")}/{laps_t} hosts)</td></tr>'
        )

    orig_html = ""
    for label, val, warn in orig_rows:
        if val is None:
            continue
        col = "#dc2626" if (warn is not None and val > warn) else ("#e2e8f0" if warn is None else "#16a34a")
        orig_html += (
            f"<tr><td>{label}</td>"
            f'<td><span style="color:{col};font-weight:bold">{val}</span></td></tr>'
        )

    # ── New rows (checks 25–35) ──
    gpp_acc   = s.get("gpp_sysvol_accessible")
    gpp_count = s.get("gpp_cpassword_count")
    if gpp_acc is False:
        gpp_cell = '<span style="color:#ca8a04;font-weight:bold">SYSVOL not accessible</span>'
    elif gpp_count is not None:
        gpp_cell = _int_cell(gpp_count, warn_above=0)
    else:
        gpp_cell = "—"

    pre_ev = s.get("pre_win2k_everyone")
    pre_an = s.get("pre_win2k_anon")
    if pre_ev is not None:
        if pre_ev or pre_an:
            who = []
            if pre_ev: who.append("Everyone")
            if pre_an: who.append("Anonymous")
            pre_cell = (
                f'<span style="color:#dc2626;font-weight:bold">'
                f'YES — {", ".join(who)} &#9888;</span>'
            )
        else:
            pre_cell = '<span style="color:#16a34a;font-weight:bold">No dangerous members</span>'
    else:
        pre_cell = "—"

    rbcd_dom = s.get("rbcd_on_domain_object")
    rbcd_dc  = s.get("rbcd_on_dc_count", 0) or 0

    new_rows_html = f"""
      <tr><td colspan="2" style="background:#0f1f35;color:#64748b;font-size:.78rem;
          padding:6px 8px;letter-spacing:.04em">NEW CHECKS (25–35)</td></tr>
      <tr><td>GPP cpassword hits (MS14-025)</td><td>{gpp_cell}</td></tr>
      <tr><td>AdminSDHolder risky ACEs</td><td>{_int_cell(s.get("adminsdholder_risky_aces"), 0)}</td></tr>
      <tr><td>SID history accounts</td><td>{_int_cell(s.get("sid_history_count"), 0)}</td></tr>
      <tr><td>Shadow credentials</td><td>{_int_cell(s.get("shadow_credentials_count"), 0)}</td></tr>
      <tr><td>RC4-permitted service accounts</td><td>{_int_cell(s.get("rc4_service_accounts"), 0)}</td></tr>
      <tr><td>RC4-permitted domain controllers</td><td>{_int_cell(s.get("rc4_domain_controllers"), 0)}</td></tr>
      <tr><td>Admin accounts without AES enctype</td><td>{_int_cell(s.get("admin_no_aes_encryption"), 0)}</td></tr>
      <tr><td>FSPs in privileged groups</td><td>{_int_cell(s.get("foreign_security_principals_in_priv_groups"), 0)}</td></tr>
      <tr><td>Pre-Win2k group (dangerous members)</td><td>{pre_cell}</td></tr>
      <tr><td>Dangerous delegation targets (DC)</td><td>{_int_cell(s.get("dangerous_delegation_targets"), 0)}</td></tr>
      <tr><td>Orphaned AD subnets</td><td>{_int_cell(s.get("orphaned_subnet_count"), 0)}</td></tr>
      <tr><td>SYSVOL using legacy FRS</td><td>{_bool_badge(s.get("sysvol_using_frs"))}</td></tr>
      <tr><td>RBCD on domain object</td><td>{_bool_badge(rbcd_dom)}</td></tr>
      <tr><td>RBCD on DC objects</td><td>{_int_cell(rbcd_dc, 0)}</td></tr>
    """

    if not orig_html and not laps_cov_html and not new_rows_html:
        return ""

    return (
        '<div class="cat-section" style="margin-top:1rem">'
        '<div class="cat-header" onclick="toggle(this)">'
        '<span class="cat-title">Additional Check Summary</span>'
        '<span class="chevron">&#9660;</span>'
        "</div>"
        '<div class="cat-body collapsed">'
        "<table>"
        "<colgroup><col style='width:60%'><col></colgroup>"
        "<tr><th>Check</th><th>Result</th></tr>"
        f"{laps_cov_html}{orig_html}{new_rows_html}"
        "</table></div></div>"
    )


# ── HTML export ───────────────────────────────────────────────────────────────

def export_html(result: ScanResult, path: str):
    counts = result.counts()
    score  = result.total_score
    sc_col = "#16a34a" if score >= 80 else ("#ca8a04" if score >= 60 else "#dc2626")

    summary_bars = ""
    for sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
        c = counts.get(sev, 0)
        if c:
            col = SEV_BADGE_COLOR[sev]
            summary_bars += (
                f'<div class="sbar" style="background:{col}">'
                f"<strong>{sev}</strong><br>{c}</div>"
            )

    cat_map = defaultdict(list)
    for f in result.findings_by_severity():
        cat_map[f.category].append(f)

    sorted_cats = sorted(
        cat_map.items(),
        key=lambda x: min(SEVERITY_ORDER.get(f.severity, 5) for f in x[1])
    )

    sections = ""
    for cat, cat_findings in sorted_cats:
        cat_findings = [f for f in cat_findings if f.severity != "INFO"]
        if not cat_findings:
            continue
        worst   = cat_findings[0].severity
        cat_col = SEV_BADGE_COLOR.get(worst, "#6b7280")
        trows   = ""
        for f in cat_findings:
            col       = SEV_BADGE_COLOR.get(f.severity, "#6b7280")
            dets      = "".join(f"<li>{d}</li>" for d in f.details)
            dets_html = f"<ul>{dets}</ul>" if dets else ""
            refs      = "".join(
                f'<a href="{r}" target="_blank" class="ref">{r}</a>'
                for r in f.references
            )
            trows += (
                f"<tr>"
                f'<td class="col-sev"><span class="badge" style="background:{col}">{f.severity}</span></td>'
                f'<td class="col-finding"><strong>{f.title}</strong>'
                f'<br><span class="desc">{f.description}</span>{dets_html}</td>'
                f'<td class="col-rec">{f.recommendation}{refs}</td>'
                f'<td class="col-score">{f.risk_score}</td>'
                f"</tr>"
            )
        sections += (
            f'<div class="cat-section">'
            f'<div class="cat-header" onclick="toggle(this)">'
            f'<span class="badge" style="background:{cat_col}">{worst}</span>'
            f'<span class="cat-title">{cat}</span>'
            f'<span class="cat-count">{len(cat_findings)} finding(s)</span>'
            f'<span class="chevron">&#9660;</span>'
            f"</div>"
            f'<div class="cat-body">'
            f"<table>"
            f"{_FINDINGS_COLGROUP}"
            f"<tr>"
            f'<th class="col-sev">Severity</th>'
            f'<th class="col-finding">Finding</th>'
            f'<th class="col-rec">Recommendation</th>'
            f'<th class="col-score">Score</th>'
            f"</tr>"
            f"{trows}"
            f"</table></div></div>"
        )

    # Generic stats table — exclude keys with dedicated sections
    stat_rows = ""
    for k, v in result.stats.items():
        if k in _SPECIAL_STATS:
            continue
        if isinstance(v, list):
            vd = ", ".join(str(x) for x in v[:10])
            if len(v) > 10:
                vd += f" ... (+{len(v)-10})"
        else:
            vd = str(v)
        stat_rows += f"<tr><td>{k}</td><td>{vd}</td></tr>"

    critical_findings_html = _build_critical_findings_html(result)
    stat_cards_html        = _build_stat_cards_html(result)
    new_checks_html        = _build_new_checks_table_html(result)
    template_inv_html      = _build_template_inventory_html(
        result.stats.get("adcs_template_inventory", []))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ADPulse Active Directory Security Report - {result.domain}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:"Segoe UI",Arial,sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem}}
  h1{{color:#38bdf8;font-size:1.8rem;margin-bottom:.3rem}}
  h2{{color:#94a3b8;font-size:1rem;font-weight:bold;margin:1.5rem 0 .5rem;
      text-transform:uppercase;letter-spacing:.05em}}
  .meta{{color:#64748b;font-size:.9rem;margin-bottom:1rem}}
  .score-box{{display:inline-block;font-size:3rem;font-weight:900;color:{sc_col};
              border:3px solid {sc_col};border-radius:12px;padding:.2rem 1.2rem;margin:.5rem 0}}
  .level{{font-size:1.2rem;color:{sc_col};font-weight:bold}}
  .summary{{display:flex;gap:.8rem;flex-wrap:wrap;margin:1rem 0}}
  .sbar{{padding:.5rem 1rem;border-radius:8px;color:#fff;font-size:.85rem;
         min-width:80px;text-align:center}}
  .card-row{{display:flex;gap:.8rem;flex-wrap:wrap;margin:1rem 0}}
  .stat-card{{background:#1e293b;border-radius:8px;padding:.8rem 1.1rem;
              min-width:160px;flex:1}}
  .card-label{{font-size:.75rem;color:#64748b;text-transform:uppercase;
               letter-spacing:.05em;margin-bottom:.3rem}}
  .card-value{{font-size:2rem;font-weight:900;line-height:1}}
  .card-sub{{font-size:.75rem;color:#64748b;margin-top:.2rem}}
  .glance-item{{background:#1e293b;border-radius:8px;padding:.8rem 1rem;margin-bottom:.5rem}}
  .glance-header{{display:flex;align-items:center;gap:.6rem}}
  .glance-title{{font-weight:bold;font-size:.95rem;flex:1}}
  .glance-score{{color:#dc2626;font-weight:bold;font-size:.85rem;white-space:nowrap}}
  .glance-desc{{color:#94a3b8;font-size:.82rem;margin-top:.35rem;line-height:1.5}}
  .glance-rec{{color:#4ade80;font-size:.8rem;margin-top:.3rem}}
  .glance-empty{{background:#1e293b;border-radius:8px;padding:1rem;text-align:center}}
  .cat-section{{margin-bottom:.6rem;border:1px solid #1e293b;border-radius:8px;overflow:hidden}}
  .cat-header{{display:flex;align-items:center;gap:.7rem;padding:.7rem 1rem;
               background:#1e293b;cursor:pointer;user-select:none}}
  .cat-header:hover{{background:#263348}}
  .cat-title{{font-weight:bold;font-size:1rem;flex:1}}
  .cat-count{{color:#64748b;font-size:.85rem}}
  .chevron{{color:#64748b;font-size:.8rem;transition:transform .2s}}
  .cat-body.collapsed{{display:none}}
  table{{width:100%;border-collapse:collapse;font-size:.85rem;table-layout:fixed}}
  th,td{{padding:8px;vertical-align:top;border-bottom:1px solid #1e293b;
         overflow-wrap:break-word;word-break:break-word}}
  th{{background:#0f1f35;color:#94a3b8;text-align:left}}
  tr:hover td{{background:#1a2740}}
  .col-sev{{width:90px;white-space:nowrap}}
  .col-finding{{width:40%}}
  .col-rec{{color:#4ade80;font-size:.8rem}}
  .col-score{{width:52px;text-align:center;font-weight:bold;white-space:nowrap}}
  .badge{{color:#fff;padding:2px 8px;border-radius:4px;font-size:.75rem;white-space:nowrap}}
  .desc{{color:#94a3b8;font-size:.8rem}}
  .ref{{display:block;color:#38bdf8;font-size:.75rem;word-break:break-all;margin-top:2px}}
  ul{{margin:.3rem 0;padding-left:1.2rem;color:#94a3b8}}
  code{{background:#0f1f35;padding:1px 5px;border-radius:3px;font-size:.82rem}}
  .stats-grid td{{padding:4px 8px;border-bottom:1px solid #1e293b;font-size:.82rem}}
  .btn{{background:#1e293b;color:#e2e8f0;border:1px solid #334155;
        padding:4px 12px;border-radius:4px;cursor:pointer;margin-right:.4rem}}
  .btn:hover{{background:#263348}}
  .legend{{display:flex;gap:1.5rem;flex-wrap:wrap;margin-bottom:1rem}}
  .legend-score,.legend-sev{{flex:1;min-width:280px;background:#1e293b;
                              border-radius:8px;padding:1rem}}
  .legend-title{{font-weight:bold;color:#38bdf8;margin-bottom:.6rem;font-size:.95rem}}
  .legend-desc{{color:#94a3b8;font-size:.82rem;margin-bottom:.7rem;line-height:1.5}}
  .legend-table{{width:100%;border-collapse:collapse;font-size:.85rem}}
  .legend-table th{{background:#0f1f35;color:#94a3b8;padding:8px;text-align:left}}
  .legend-table td{{border-bottom:1px solid #1e293b;padding:8px;color:#cbd5e1;vertical-align:top}}
  .legend-table tr:last-child td{{border-bottom:none}}
  footer{{margin-top:2rem;color:#475569;font-size:.75rem;text-align:center}}
</style>
<script>
  function toggle(h) {{
    var b=h.nextElementSibling, c=h.querySelector('.chevron');
    b.classList.toggle('collapsed');
    c.style.transform=b.classList.contains('collapsed')?'rotate(-90deg)':'';
  }}
  function expandAll()   {{ document.querySelectorAll('.cat-body').forEach(b=>b.classList.remove('collapsed')); }}
  function collapseAll() {{ document.querySelectorAll('.cat-body').forEach(b=>b.classList.add('collapsed')); }}
</script>
</head>
<body>
<h1>ADPulse Active Directory Security Report</h1>
<div class="meta">
  Domain: <strong>{result.domain}</strong> &nbsp;|&nbsp;
  DC: <strong>{result.dc_ip}</strong> &nbsp;|&nbsp;
  Scanned: <strong>{result.scan_time}</strong>
</div>
<div class="score-box">{score}</div>
<span class="level"> / 100 &nbsp;&mdash; {result.risk_level} RISK</span>
<div class="summary">{summary_bars}</div>

<h2>At a Glance &mdash; Most Critical Findings</h2>
{critical_findings_html}

<h2>Scoring Legend</h2>
<div class="legend">
  <div class="legend-score">
    <div class="legend-title">Risk Score</div>
    <div class="legend-desc">
      Starts at <strong>100</strong>; deductions applied per finding.
    </div>
    <table class="legend-table">
      <tr><th>Score</th><th>Risk Level</th><th>Meaning</th></tr>
      <tr><td>80&ndash;100</td><td><span class="badge" style="background:#16a34a">LOW</span></td><td>Good posture, minor issues only</td></tr>
      <tr><td>60&ndash;79</td><td><span class="badge" style="background:#ca8a04">MEDIUM</span></td><td>Notable weaknesses to address</td></tr>
      <tr><td>40&ndash;59</td><td><span class="badge" style="background:#ea580c">HIGH</span></td><td>Significant vulnerabilities</td></tr>
      <tr><td>0&ndash;39</td><td><span class="badge" style="background:#dc2626">CRITICAL</span></td><td>Severe risks &mdash; immediate action</td></tr>
    </table>
  </div>
  <div class="legend-sev">
    <div class="legend-title">Severity Levels</div>
    <table class="legend-table">
      <tr><th>Severity</th><th>Deduction</th><th>Meaning</th></tr>
      <tr><td><span class="badge" style="background:#dc2626">CRITICAL</span></td><td>20&ndash;25 pts</td><td>Directly exploitable, likely leads to full domain compromise</td></tr>
      <tr><td><span class="badge" style="background:#ea580c">HIGH</span></td><td>10&ndash;15 pts</td><td>Serious misconfiguration enabling privilege escalation</td></tr>
      <tr><td><span class="badge" style="background:#ca8a04">MEDIUM</span></td><td>5&ndash;10 pts</td><td>Security weakness increasing attack surface</td></tr>
      <tr><td><span class="badge" style="background:#2563eb">LOW</span></td><td>2&ndash;5 pts</td><td>Minor hardening gap</td></tr>
      <tr><td><span class="badge" style="background:#6b7280">INFO</span></td><td>0 pts</td><td>Informational, manual review recommended</td></tr>
    </table>
  </div>
</div>

<h2>Findings</h2>
<div style="margin-bottom:.8rem">
  <button class="btn" onclick="expandAll()">Expand All</button>
  <button class="btn" onclick="collapseAll()">Collapse All</button>
</div>
{sections}

<h2>Statistics</h2>
<h2 style="margin-top:0;color:#64748b;font-size:.85rem;text-transform:none;letter-spacing:0">Key Metrics</h2>
{stat_cards_html}
{new_checks_html}
{template_inv_html}
<div class="cat-section" style="margin-top:.6rem">
  <div class="cat-header" onclick="toggle(this)">
    <span class="cat-title">Domain Statistics</span>
    <span class="chevron">&#9660;</span>
  </div>
  <div class="cat-body collapsed">
    <table class="stats-grid" style="table-layout:fixed">
      <colgroup><col style="width:35%"><col></colgroup>
      <tr><th>Key</th><th>Value</th></tr>
      {stat_rows}
    </table>
  </div>
</div>

<footer>Generated by ADPulse Active Directory Security Scanner &mdash; for authorised use only</footer>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as fp:
        fp.write(html)
    print(f"[+] HTML report -> {path}")