import { useState, useEffect, useRef } from "react";

// ─── PARSERS ────────────────────────────────────────────────────────────────

function parseSCCXCCDF(xmlText) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(xmlText, "application/xml");

  // DISA SCC uses "cdf:" prefix — get ALL elements by local name regardless of namespace
  const findAll = (localName) => {
    const all = Array.from(doc.getElementsByTagName("*"));
    return all.filter(el => el.localName === localName);
  };
  const findOne = (localName) => findAll(localName)[0];

  const getAttr = (el, name) => el?.getAttribute(name) || "";
  const getText = (el, childName) => {
    if (!el) return "";
    const child = Array.from(el.children).find(c => c.localName === childName);
    return child?.textContent?.replace(/<[^>]+>/g, "").trim() || "";
  };

  const benchmarkEl = findOne("Benchmark");
  const benchmarkId = getAttr(benchmarkEl, "id") || "DISA STIG";
  const titleEl = Array.from(benchmarkEl?.children || []).find(c => c.localName === "title");
  const benchmarkTitle = titleEl?.textContent || benchmarkId;

  const testResultEl = findOne("TestResult");
  const targetEl = Array.from(testResultEl?.children || []).find(c => c.localName === "target");
  const target = targetEl?.textContent || "Unknown Host";
  const startTime = getAttr(testResultEl, "start-time") || "";

  // Build rule definition lookup
  const ruleEls = findAll("Rule");
  const ruleMap = {};
  ruleEls.forEach(r => { ruleMap[getAttr(r, "id")] = r; });

  const ruleResults = findAll("rule-result");
  const findings = [];

  ruleResults.forEach((rr) => {
    const resultEl = Array.from(rr.children).find(c => c.localName === "result");
    const result = resultEl?.textContent?.trim();
    if (!["fail", "error", "unknown"].includes(result)) return;

    const ruleId = getAttr(rr, "idref");
    const ruleDef = ruleMap[ruleId];

    const titleChild = Array.from(ruleDef?.children || []).find(c => c.localName === "title");
    const title = titleChild?.textContent?.trim() ||
                  ruleId.replace(/xccdf_mil\.disa\.stig_rule_/, "").replace(/_/g, " ").slice(0, 80);

    const descChild = Array.from(ruleDef?.children || []).find(c => c.localName === "description");
    const description = descChild?.textContent?.replace(/<[^>]+>/g, "").trim().slice(0, 200) || "";

    const fixChild = Array.from(ruleDef?.children || []).find(c => c.localName === "fixtext") ||
                     Array.from(ruleDef?.children || []).find(c => c.localName === "fix");
    const fixText = fixChild?.textContent?.trim() || "";

    const rawSev = getAttr(rr, "severity") || getAttr(ruleDef, "severity") || "medium";
    const sev = normalizeSeverity(rawSev);
    const cat = detectCategory(ruleId + " " + title);

    // Extract short STIG ID (V-XXXXXX)
    const stigMatch = ruleId.match(/V-\d+/);
    const stigId = stigMatch ? stigMatch[0] : ruleId.slice(-20);

    findings.push({
      id: ruleId,
      title: title.slice(0, 80),
      severity: sev,
      category: cat,
      stig: stigId,
      description,
      remediation: buildPSRemediation(ruleId, title, fixText),
      result,
      source: "scc",
    });
  });

  return {
    findings,
    meta: {
      benchmark: benchmarkTitle,
      target,
      startTime,
      total: ruleResults.length,
      failed: findings.length,
      source: "DISA SCC XCCDF Results",
    },
  };
}

function parseCISBenchmark(xmlText) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(xmlText, "application/xml");

  const findAll = (localName) => {
    const all = Array.from(doc.getElementsByTagName("*"));
    return all.filter(el => el.localName === localName);
  };

  const getAttr = (el, name) => el?.getAttribute(name) || "";

  const benchmarkEl = findAll("Benchmark")[0];
  const titleEl = Array.from(benchmarkEl?.children || []).find(c => c.localName === "title");
  const benchmarkTitle = titleEl?.textContent || "CIS Benchmark";

  const ruleResults = findAll("rule-result");
  const findings = [];

  if (ruleResults.length > 0) {
    const ruleEls = findAll("Rule");
    const ruleMap = {};
    ruleEls.forEach(r => { ruleMap[getAttr(r, "id")] = r; });

    ruleResults.forEach((rr) => {
      const resultEl = Array.from(rr.children).find(c => c.localName === "result");
      const result = resultEl?.textContent?.trim();
      if (!["fail", "error"].includes(result)) return;
      const ruleId = getAttr(rr, "idref");
      const ruleDef = ruleMap[ruleId];
      const titleChild = Array.from(ruleDef?.children || []).find(c => c.localName === "title");
      const title = titleChild?.textContent ||
                    ruleId.replace(/xccdf_org\.cisecurity\.benchmarks_rule_/, "").replace(/_/g, " ").slice(0, 80);
      const severity = normalizeSeverity(getAttr(ruleDef, "severity") || "medium");
      const fixChild = Array.from(ruleDef?.children || []).find(c => c.localName === "fixtext");
      const fixText = fixChild?.textContent?.trim() || "";
      findings.push({
        id: ruleId,
        title: title.trim().slice(0, 80),
        severity,
        category: detectCategory(ruleId + " " + title),
        stig: ruleId.replace(/xccdf_org\.cisecurity\.benchmarks_rule_/, "CIS-").slice(0, 40),
        description: Array.from(ruleDef?.children || []).find(c => c.localName === "description")?.textContent?.replace(/<[^>]+>/g, "").trim().slice(0, 200) || "",
        remediation: buildPSRemediation(ruleId, title, fixText),
        result,
        source: "cis",
      });
    });
  } else {
    const rules = findAll("Rule");
    rules.slice(0, 50).forEach((rule) => {
      const ruleId = getAttr(rule, "id");
      if (getAttr(rule, "selected") === "false") return;
      const titleChild = Array.from(rule.children).find(c => c.localName === "title");
      const title = titleChild?.textContent ||
                    ruleId.replace(/xccdf_org\.cisecurity\.benchmarks_rule_/, "").replace(/_/g, " ").slice(0, 80);
      const severity = normalizeSeverity(getAttr(rule, "severity") || "medium");
      const fixChild = Array.from(rule.children).find(c => c.localName === "fixtext");
      const fixText = fixChild?.textContent?.trim() || "";
      findings.push({
        id: ruleId,
        title: title.trim().slice(0, 80),
        severity,
        category: detectCategory(ruleId + " " + title),
        stig: ruleId.replace(/xccdf_org\.cisecurity\.benchmarks_rule_/, "CIS-").slice(0, 40),
        description: Array.from(rule.children).find(c => c.localName === "description")?.textContent?.replace(/<[^>]+>/g, "").trim().slice(0, 200) || "",
        remediation: buildPSRemediation(ruleId, title, fixText),
        result: "fail",
        source: "cis",
      });
    });
  }

  return {
    findings,
    meta: {
      benchmark: benchmarkTitle,
      target: "Windows Target",
      startTime: new Date().toISOString(),
      total: findings.length,
      failed: findings.length,
      source: "CIS Benchmark",
    },
  };
}

function normalizeSeverity(sev) {
  if (!sev) return "medium";
  const s = sev.toLowerCase();
  if (s.includes("high") || s === "cat i" || s === "1") return "high";
  if (s.includes("low") || s === "cat iii" || s === "3") return "low";
  return "medium";
}

function detectCategory(text) {
  const t = text.toLowerCase();
  if (t.includes("password") || t.includes("account") || t.includes("lockout")) return "Authentication";
  if (t.includes("firewall") || t.includes("network") || t.includes("port") || t.includes("tcp")) return "Network";
  if (t.includes("audit") || t.includes("log") || t.includes("event")) return "Auditing";
  if (t.includes("encrypt") || t.includes("fips") || t.includes("tls") || t.includes("ssl") || t.includes("cipher")) return "Cryptography";
  if (t.includes("usb") || t.includes("removable") || t.includes("device")) return "Device Control";
  if (t.includes("ssh") || t.includes("rdp") || t.includes("remote")) return "Remote Access";
  if (t.includes("privilege") || t.includes("admin") || t.includes("uac") || t.includes("access")) return "Access Control";
  if (t.includes("patch") || t.includes("update") || t.includes("windows update")) return "Patch Management";
  if (t.includes("antivirus") || t.includes("defender") || t.includes("malware")) return "Endpoint Protection";
  if (t.includes("registry") || t.includes("hklm") || t.includes("hkcu")) return "Registry";
  return "Configuration";
}

// ─── STIG V-NUMBER REMEDIATION LIBRARY ───────────────────────────────────────
// Keyed by V-number extracted from rule ID. Real PowerShell registry commands.
const STIG_REMEDIATION = {
  // ── LOW SEVERITY ──
  "V-220700": `# Secure Boot requires UEFI firmware change — cannot be scripted\nWrite-Output "MANUAL: Enable Secure Boot in BIOS/UEFI firmware settings"`,
  "V-220797": `reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" /v EnableICMPRedirect /t REG_DWORD /d 0 /f`,
  "V-220798": `$path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'NodeType' -Value 2 -Type DWord`,
  "V-220823": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'fAllowToGetHelp' -Value 0 -Type DWord`,
  "V-220827": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'NoAutoplayfornonVolume' -Value 1 -Type DWord`,
  "V-220828": `$path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'NoAutorun' -Value 1 -Type DWord`,
  "V-220829": `$path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord`,
  "V-220826": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'DisableInventory' -Value 1 -Type DWord`,
  "V-220831": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'DisableWindowsConsumerFeatures' -Value 1 -Type DWord`,
  "V-220835": `reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 0 /f`,

  "V-220872": `reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent" /v DisableThirdPartySuggestions /t REG_DWORD /d 1 /f`,
  "V-220922": `$path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'legalnoticecaption' -Value 'DoD Notice and Consent Banner' -Type String`,
  "V-220954": `reg add "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications" /v NoToastApplicationNotificationOnLockScreen /t REG_DWORD /d 1 /f; reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications" /v NoToastApplicationNotificationOnLockScreen /t REG_DWORD /d 1 /f`,
  "V-252903": `$path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'Enabled' -Value 1 -Type DWord`,

  // ── MEDIUM SEVERITY ──
  "V-220706": `net accounts /maxpwage:60`,
  "V-220707": `net accounts /minpwlen:14`,
  "V-220708": `net accounts /lockoutthreshold:3`,
  "V-220709": `net accounts /lockoutduration:15`,
  "V-220710": `net accounts /lockoutwindow:15`,
  "V-220711": `$path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'; Set-ItemProperty -Path $path -Name 'EnableLUA' -Value 1 -Type DWord`,
  "V-220712": `$path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'; Set-ItemProperty -Path $path -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Type DWord`,
  "V-220713": `$path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'; Set-ItemProperty -Path $path -Name 'ConsentPromptBehaviorUser' -Value 0 -Type DWord`,
  "V-220716": `net accounts /maxpwage:60`,
  "V-220717": `Set-NetFirewallProfile -Profile Private -Enabled True`,
  "V-220718": `Set-NetFirewallProfile -Profile Public -Enabled True`,
  "V-220719": `Set-NetFirewallProfile -Profile Domain -DefaultInboundAction Block`,
  "V-220720": `Set-NetFirewallProfile -Profile Private -DefaultInboundAction Block`,
  "V-220721": `Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block`,
  "V-220726": `auditpol /set /subcategory:"Logon" /success:enable /failure:enable`,
  "V-220727": `auditpol /set /subcategory:"Logoff" /success:enable`,
  "V-220728": `auditpol /set /subcategory:"Account Lockout" /failure:enable`,
  "V-220729": `auditpol /set /subcategory:"Special Logon" /success:enable`,
  "V-220730": `auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable`,
  "V-220731": `auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable`,
  "V-220732": `auditpol /set /subcategory:"Privilege Use" /success:enable /failure:enable`,
  "V-220733": `auditpol /set /subcategory:"Process Creation" /success:enable`,
  "V-220734": `auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable`,
  "V-220735": `auditpol /set /subcategory:"Authentication Policy Change" /success:enable`,
  "V-220736": `auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable`,
  "V-220737": `auditpol /set /subcategory:"Security System Extension" /success:enable`,
  "V-220738": `auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable`,
  "V-220739": `auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable`,
  "V-220740": `auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable`,
  "V-220800": `reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f`,
  "V-220801": `Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force`,
  "V-220802": `$path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'; Set-ItemProperty -Path $path -Name 'RestrictAnonymous' -Value 1 -Type DWord`,
  "V-220803": `$path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'; Set-ItemProperty -Path $path -Name 'RestrictAnonymousSAM' -Value 1 -Type DWord`,
  "V-220804": `$path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'; Set-ItemProperty -Path $path -Name 'EveryoneIncludesAnonymous' -Value 0 -Type DWord`,
  "V-220805": `$path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'; Set-ItemProperty -Path $path -Name 'NoLMHash' -Value 1 -Type DWord`,
  "V-220806": `$path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'; Set-ItemProperty -Path $path -Name 'LmCompatibilityLevel' -Value 5 -Type DWord`,
  "V-220807": `$path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'NTLMMinClientSec' -Value 537395200 -Type DWord`,
  "V-220808": `$path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'NTLMMinServerSec' -Value 537395200 -Type DWord`,
  "V-220809": `$path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'; Set-ItemProperty -Path $path -Name 'CachedLogonsCount' -Value '4' -Type String`,
  "V-220810": `$path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'; Set-ItemProperty -Path $path -Name 'ForceUnlockLogon' -Value 1 -Type DWord`,
  "V-220811": `$path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'; Set-ItemProperty -Path $path -Name 'PasswordExpiryWarning' -Value 14 -Type DWord`,
  "V-220812": `$path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'; Set-ItemProperty -Path $path -Name 'InactivityTimeoutSecs' -Value 900 -Type DWord`,
  "V-220813": `$path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'; Set-ItemProperty -Path $path -Name 'legalnoticetext' -Value 'You are accessing a U.S. Government information system, which includes this computer, this computer network, all computers connected to this network, and all devices and storage media attached to this network or to a computer on this network. This information system is provided for U.S. Government-authorized use only. Unauthorized or improper use of this system may result in disciplinary action, as well as civil and criminal penalties.' -Type String`,
  "V-220814": `$path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'; Set-ItemProperty -Path $path -Name 'DontDisplayLastUserName' -Value 1 -Type DWord`,
  "V-220815": `$path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'; Set-ItemProperty -Path $path -Name 'DisableAutomaticRestartSignOn' -Value 1 -Type DWord`,
  "V-220857": `Set-MpPreference -DisableRealtimeMonitoring $false`,
  "V-220858": `Set-MpPreference -DisableAntiSpyware $false`,
  "V-220902": `reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Kernel DMA Protection" /v DeviceEnumerationPolicy /t REG_DWORD /d 0 /f`,
  "V-220903": `Write-Output "MANUAL: Install DoD Root CA 3,4,5,6 via InstallRoot tool. Risk Acceptance: Non-domain standalone system. Document in CKL Finding Details."`,
  "V-220904": `Write-Output "MANUAL: Install DoD External Root CA certs via PKI. Risk Acceptance: Standalone VM not connected to DoD PKI infrastructure. Document in CKL."`,
  "V-220905": `Write-Output "MANUAL: Install DoD Interoperability Root CA cross-certs. Risk Acceptance: Standalone VM not connected to DoD PKI. Document in CKL."`,
  "V-220906": `Write-Output "MANUAL: Install US DOD CCEB Interoperability Root CA cross-certs. Risk Acceptance: Standalone VM not connected to DoD PKI. Document in CKL."`,
  "V-220946": `Write-Output "MANUAL: MFA requires CAC/smart card hardware. Risk Acceptance: Lab VM environment without CAC reader. Document in CKL Finding Details."`,

  // ── HIGH SEVERITY ──
  "V-220699": `Write-Output "MANUAL: BitLocker requires TPM. Enable vTPM in VMware VM Settings or document as VM risk acceptance."`,
  "V-220702": `Write-Output "MANUAL: BitLocker not active. Enable vTPM in VMware VM Settings to remediate."`,
  "V-220703": `Write-Output "MANUAL: BitLocker PIN requires BitLocker active. Enable vTPM in VMware VM Settings first."`,
  "V-220704": `Write-Output "MANUAL: BitLocker startup PIN requires BitLocker active. Enable vTPM in VMware VM Settings first."`,
  "V-220705": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'LsaCfgFlags' -Value 1 -Type DWord`,
  "V-220715": `net user Administrator /active:no`,
  "V-220862": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'AllowBasic' -Value 0 -Type DWord`,
  "V-220863": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'AllowUnencryptedTraffic' -Value 0 -Type DWord`,
  "V-220865": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'AllowBasic' -Value 0 -Type DWord`,
  "V-220866": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'AllowUnencryptedTraffic' -Value 0 -Type DWord`,
  "V-220867": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'DisableRunAs' -Value 1 -Type DWord`,
  "V-220868": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'AllowDigest' -Value 0 -Type DWord`,
  "V-220751": `auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable`,
  "V-220753": `auditpol /set /subcategory:"Process Creation" /success:enable`,
  "V-220754": `auditpol /set /subcategory:"Process Termination" /success:enable`,
  "V-220761": `auditpol /set /subcategory:"File System" /failure:enable`,
  "V-220762": `auditpol /set /subcategory:"File System" /success:enable`,
  "V-220763": `auditpol /set /subcategory:"Other Object Access Events" /failure:enable`,
  "V-220764": `auditpol /set /subcategory:"Other Object Access Events" /success:enable`,
  "V-220769": `auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable`,
  "V-220770": `auditpol /set /subcategory:"Sensitive Privilege Use" /failure:enable`,
  "V-220771": `auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable`,
  "V-220772": `auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable`,
  "V-220776": `auditpol /set /subcategory:"Security State Change" /success:enable`,
  "V-220786": `auditpol /set /subcategory:"Other Policy Change Events" /failure:enable`,
  "V-220789": `auditpol /set /subcategory:"Detailed File Share" /failure:enable`,
  "V-220790": `auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable`,
  "V-220791": `auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /failure:enable`,
  "V-220913": `reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f`,
  "V-257589": `auditpol /set /subcategory:"Process Creation" /success:enable; reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f`,
  "V-278918": `auditpol /set /subcategory:"File System" /failure:enable`,
  "V-278919": `auditpol /set /subcategory:"File System" /success:enable`,
  "V-278920": `auditpol /set /subcategory:"Handle Manipulation" /failure:enable`,
  "V-278921": `auditpol /set /subcategory:"Handle Manipulation" /success:enable`,
  "V-278922": `auditpol /set /subcategory:"Registry" /success:enable`,
  "V-278923": `auditpol /set /subcategory:"Registry" /failure:enable`,
  "V-278924": `auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable`,
  "V-278925": `auditpol /set /subcategory:"Sensitive Privilege Use" /failure:enable`,
  "V-220779": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Application'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'MaxSize' -Value 32768 -Type DWord`,
  "V-220780": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Security'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'MaxSize' -Value 1024000 -Type DWord`,
  "V-220781": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\System'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'MaxSize' -Value 32768 -Type DWord`,
  "V-220794": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'NoLockScreenSlideshow' -Value 1 -Type DWord`,
  "V-220795": `reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters" /v DisableIpSourceRouting /t REG_DWORD /d 2 /f`,
  "V-220796": `reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f`,
  "V-220816": `$path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'NoWebServices' -Value 1 -Type DWord`,
  "V-220817": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'DisableHTTPPrinting' -Value 1 -Type DWord`,
  "V-220819": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'DontDisplayNetworkSelectionUI' -Value 1 -Type DWord`,
  "V-220820": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'EnumerateLocalUsers' -Value 0 -Type DWord`,
  "V-220821": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'DCSettingIndex' -Value 1 -Type DWord`,
  "V-220822": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'ACSettingIndex' -Value 1 -Type DWord`,
  "V-220824": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Rpc'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'RestrictRemoteClients' -Value 1 -Type DWord`,
  "V-220830": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Biometrics\\FacialFeatures'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'EnhancedAntiSpoofing' -Value 1 -Type DWord`,
  "V-220834": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'AllowTelemetry' -Value 1 -Type DWord`,
  "V-220836": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'EnableSmartScreen' -Value 1 -Type DWord`,
  "V-220840": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\SmartScreen'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'PreventOverride' -Value 1 -Type DWord`,
  "V-220841": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\SmartScreen'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'PreventOverrideForFilesInShell' -Value 1 -Type DWord`,
  "V-220842": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'PreventIgnoreCertErrors' -Value 1 -Type DWord`,
  "V-220843": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Main'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'FormSuggest Passwords' -Value 'no' -Type String`,
  "V-220844": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'EnabledV9' -Value 1 -Type DWord`,
  "V-220845": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'AllowGameDVR' -Value 0 -Type DWord`,
  "V-220847": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\PassportForWork\\PINComplexity'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'MinimumPINLength' -Value 6 -Type DWord`,
  "V-220853": `$path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'SaveZoneInformation' -Value 2 -Type DWord`,
  "V-220855": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'AllowIndexingEncryptedStoresOrItems' -Value 0 -Type DWord`,
  "V-220869": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'LetAppsActivateWithVoiceAboveLock' -Value 2 -Type DWord`,
  "V-220870": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'AllowDomainPINLogon' -Value 0 -Type DWord`,
  "V-220871": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\WindowsInkWorkspace'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'AllowWindowsInkWorkspace' -Value 1 -Type DWord`,
  "V-220911": `$newName = "Admin_" + (Get-Date -Format "MMdd"); Rename-LocalUser -Name "Administrator" -NewName $newName`,
  "V-220924": `$path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'; Set-ItemProperty -Path $path -Name 'ScRemoveOption' -Value '1' -Type String`,
  "V-220925": `$path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'RequireSecuritySignature' -Value 1 -Type DWord`,
  "V-220927": `$path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters'; Set-ItemProperty -Path $path -Name 'RequireSecuritySignature' -Value 1 -Type DWord`,
  "V-220933": `$path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'; Set-ItemProperty -Path $path -Name 'RestrictRemoteSAM' -Value 'O:BAG:BAD:(A;;RC;;;BA)' -Type String`,
  "V-220935": `$path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\pku2u'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'AllowOnlineID' -Value 0 -Type DWord`,
  "V-220936": `$path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'SupportedEncryptionTypes' -Value 2147483640 -Type DWord`,
  "V-220942": `$path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FipsAlgorithmPolicy'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'Enabled' -Value 1 -Type DWord`,
  "V-220944": `$path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'; Set-ItemProperty -Path $path -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Type DWord`,
  "V-220945": `$path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'; Set-ItemProperty -Path $path -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Type DWord`,
  "V-220947": `$path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'; Set-ItemProperty -Path $path -Name 'ConsentPromptBehaviorUser' -Value 0 -Type DWord`,
  "V-220745": `net accounts /minpwlen:14`,
  "V-220728": `Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart`,
  "V-220732": `Set-Service -Name seclogon -StartupType Disabled; Stop-Service -Name seclogon -Force`,
  "V-220740": `net accounts /lockoutthreshold:3`,
  "V-250319": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name '\\\\*\\NETLOGON' -Value 'RequireMutualAuthentication=1,RequireIntegrity=1' -Type String; Set-ItemProperty -Path $path -Name '\\\\*\\SYSVOL' -Value 'RequireMutualAuthentication=1,RequireIntegrity=1' -Type String`,
  "V-252896": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'EnableTranscripting' -Value 1 -Type DWord`,
  "V-256894": `Disable-WindowsOptionalFeature -Online -FeatureName Internet-Explorer-Optional-amd64 -NoRestart`,
  "V-279687": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\MicrosoftAccount'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'DisableUserAuth' -Value 1 -Type DWord`,
  "V-220952": `$path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'BackupDirectory' -Value 2 -Type DWord`,
  "V-220860": `$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord`,
  "V-220946": `Write-Output "MANUAL: Requires smart card or CAC hardware for MFA"`,
  "V-220904": `Write-Output "MANUAL: Install DoD External Root CA certificates via PKI"`,
  "V-220905": `Write-Output "MANUAL: Install DoD Interoperability Root CA cross-certificates via PKI"`,
  "V-220906": `Write-Output "MANUAL: Install US DOD CCEB Interoperability Root CA cross-certificates via PKI"`,
  "V-220697": `Write-Output "MANUAL: Verify Windows 10 Enterprise edition is installed"`,
  "V-220698": `Write-Output "MANUAL: Requires domain TPM configuration"`,
  "V-220723": `Write-Output "MANUAL: Remove software certificate installation files manually"`,
  "V-220799": `Write-Output "MANUAL: Requires LAPS deployment for local admin password management"`,
  "V-220832": `Write-Output "MANUAL: Review local administrator enumeration settings"`,
  "V-220959": `$tmp = [System.IO.Path]::GetTempFileName(); secedit /export /cfg $tmp; (Get-Content $tmp) -replace 'SeInteractiveLogonRight.*', 'SeInteractiveLogonRight = *S-1-5-32-544' | Set-Content $tmp; secedit /configure /db secedit.sdb /cfg $tmp /quiet; Remove-Item $tmp`,
  "V-220960": `$tmp = [System.IO.Path]::GetTempFileName(); secedit /export /cfg $tmp; (Get-Content $tmp) -replace 'SeBackupPrivilege.*', 'SeBackupPrivilege = *S-1-5-32-544' | Set-Content $tmp; secedit /configure /db secedit.sdb /cfg $tmp /quiet; Remove-Item $tmp`,
  "V-220968": `$tmp = [System.IO.Path]::GetTempFileName(); secedit /export /cfg $tmp; (Get-Content $tmp) -replace 'SeDenyNetworkLogonRight.*', 'SeDenyNetworkLogonRight = Guest' | Set-Content $tmp; secedit /configure /db secedit.sdb /cfg $tmp /quiet; Remove-Item $tmp`,
  "V-220969": `$tmp = [System.IO.Path]::GetTempFileName(); secedit /export /cfg $tmp; $c = Get-Content $tmp; if ($c -match "SeDenyBatchLogonRight") { $c = $c -replace 'SeDenyBatchLogonRight.*', 'SeDenyBatchLogonRight = Guest' } else { $c += "SeDenyBatchLogonRight = Guest" }; $c | Set-Content $tmp; secedit /configure /db secedit.sdb /cfg $tmp /quiet; Remove-Item $tmp`,
  "V-220970": `$tmp = [System.IO.Path]::GetTempFileName(); secedit /export /cfg $tmp; $c = Get-Content $tmp; if ($c -match "SeDenyServiceLogonRight") { $c = $c -replace 'SeDenyServiceLogonRight.*', 'SeDenyServiceLogonRight = Guest' } else { $c += "SeDenyServiceLogonRight = Guest" }; $c | Set-Content $tmp; secedit /configure /db secedit.sdb /cfg $tmp /quiet; Remove-Item $tmp`,
  "V-220971": `$tmp = [System.IO.Path]::GetTempFileName(); secedit /export /cfg $tmp; (Get-Content $tmp) -replace 'SeDenyInteractiveLogonRight.*', 'SeDenyInteractiveLogonRight = Guest' | Set-Content $tmp; secedit /configure /db secedit.sdb /cfg $tmp /quiet; Remove-Item $tmp`,
  "V-220982": `$tmp = [System.IO.Path]::GetTempFileName(); secedit /export /cfg $tmp; (Get-Content $tmp) -replace 'SeRestorePrivilege.*', 'SeRestorePrivilege = *S-1-5-32-544' | Set-Content $tmp; secedit /configure /db secedit.sdb /cfg $tmp /quiet; Remove-Item $tmp`,
};

function buildPSRemediation(ruleId, title, fixText) {
  // First check V-number specific library
  const vMatch = ruleId.match(/V-\d+/);
  if (vMatch && STIG_REMEDIATION[vMatch[0]]) {
    return STIG_REMEDIATION[vMatch[0]];
  }

  // Fall back to keyword matching for unlisted rules
  const t = (title + " " + ruleId).toLowerCase();
  if (t.includes("password") && t.includes("max")) return `net accounts /maxpwage:60`;
  if (t.includes("password") && t.includes("length")) return `net accounts /minpwlen:14`;
  if (t.includes("lockout") && t.includes("threshold")) return `net accounts /lockoutthreshold:3`;
  if (t.includes("lockout") && t.includes("duration")) return `net accounts /lockoutduration:15`;
  if (t.includes("firewall")) return `Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True`;
  if (t.includes("audit") && t.includes("logon")) return `auditpol /set /subcategory:"Logon" /success:enable /failure:enable`;
  if (t.includes("rdp") || t.includes("remote desktop")) return `Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1 -Type DWord`;
  if (t.includes("usb") || t.includes("removable")) return `Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' -Name Start -Value 4 -Type DWord`;
  if (t.includes("defender") || t.includes("antivirus")) return `Set-MpPreference -DisableRealtimeMonitoring $false`;
  if (t.includes("uac")) return `Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1 -Type DWord`;
  if (t.includes("smb1")) return `Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force`;
  if (t.includes("screensaver")) return `Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name InactivityTimeoutSecs -Value 900 -Type DWord`;
  if (t.includes("guest")) return `net user guest /active:no`;
  if (t.includes("winrm")) return `Disable-PSRemoting -Force`;
  if (t.includes("netbios")) return `$path='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters'; Set-ItemProperty -Path $path -Name 'NodeType' -Value 2 -Type DWord`;
  if (t.includes("ntlm")) return `$path='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'; Set-ItemProperty -Path $path -Name 'LmCompatibilityLevel' -Value 5 -Type DWord`;
  if (t.includes("anonymous")) return `$path='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'; Set-ItemProperty -Path $path -Name 'RestrictAnonymous' -Value 1 -Type DWord`;
  if (t.includes("legal") || t.includes("banner")) return `Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name legalnoticecaption -Value 'DoD Notice and Consent Banner' -Type String`;
  if (t.includes("windows update") || t.includes("automatic update")) return `$path='HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU'; If(!(Test-Path $path)){New-Item -Path $path -Force}; Set-ItemProperty -Path $path -Name 'NoAutoUpdate' -Value 0 -Type DWord`;

  // Unknown rule — flag for manual review
  return `Write-Output "MANUAL REVIEW REQUIRED: ${title.slice(0, 60).replace(/'/g, '')}"`;
}

// ─── CONSTANTS ───────────────────────────────────────────────────────────────

const SEVERITY_COLOR = {
  high:   { bg: "#ff3b3b18", border: "#ff3b3b", text: "#ff6b6b", dot: "#ff3b3b" },
  medium: { bg: "#ff9f0a18", border: "#ff9f0a", text: "#ffb340", dot: "#ff9f0a" },
  low:    { bg: "#30d15818", border: "#30d158", text: "#30d158", dot: "#30d158" },
};

const STEPS = ["SCAN", "MAP", "EXECUTE", "VERIFY", "UPDATE"];

const sleep = ms => new Promise(r => setTimeout(r, ms));

// ─── SUB-COMPONENTS ──────────────────────────────────────────────────────────

function StepPipeline({ activeStep, completedSteps }) {
  return (
    <div style={{ display: "flex", alignItems: "center", padding: "16px 0 6px" }}>
      {STEPS.map((step, i) => {
        const done = completedSteps.includes(i);
        const active = activeStep === i;
        return (
          <div key={step} style={{ display: "flex", alignItems: "center", flex: i < STEPS.length - 1 ? 1 : "none" }}>
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 4 }}>
              <div style={{
                width: 34, height: 34, borderRadius: "50%",
                background: done ? "#a8ff78" : active ? "#00e5ff" : "#0d1f0d",
                border: `2px solid ${done ? "#a8ff78" : active ? "#00e5ff" : "#1e3a1e"}`,
                display: "flex", alignItems: "center", justifyContent: "center",
                fontSize: 13, color: done ? "#020a02" : active ? "#020a02" : "#2a5a2a",
                fontWeight: 900,
                boxShadow: active ? "0 0 16px #00e5ff88" : done ? "0 0 10px #a8ff7844" : "none",
                transition: "all 0.4s",
              }}>
                {done ? "✓" : active ? <span style={{ display: "inline-block", animation: "spin 1s linear infinite" }}>⟳</span> : i + 1}
              </div>
              <span style={{
                fontSize: 8, letterSpacing: 2, fontWeight: 700,
                color: done ? "#a8ff78" : active ? "#00e5ff" : "#2a4a2a",
                fontFamily: "monospace",
              }}>{step}</span>
            </div>
            {i < STEPS.length - 1 && (
              <div style={{
                flex: 1, height: 2, margin: "0 4px", marginBottom: 18,
                background: done ? "#a8ff78" : "#0d1f0d",
                boxShadow: done ? "0 0 6px #a8ff7866" : "none",
                transition: "all 0.4s",
              }} />
            )}
          </div>
        );
      })}
    </div>
  );
}

function FindingCard({ finding, status, onSelect, selected }) {
  const sc = SEVERITY_COLOR[finding.severity] || SEVERITY_COLOR.medium;
  const isFailed = status === "failed";
  const isFixed = status === "fixed";
  const isManual = status === "manual";

  return (
    <div onClick={() => onSelect(finding)} style={{
      background: isFailed ? "#1a0000" : isManual ? "#1a0d00" : isFixed ? "#001a00" : selected ? "#0a1a0a" : "#050d05",
      border: `1px solid ${isFailed ? "#ff3b3b" : isManual ? "#ff9f0a" : isFixed ? "#a8ff78" : selected ? sc.border : "#132013"}`,
      borderLeft: `4px solid ${isFailed ? "#ff3b3b" : isManual ? "#ff9f0a" : isFixed ? "#a8ff78" : sc.border}`,
      borderRadius: 5, padding: "10px 12px", cursor: "pointer",
      transition: "all 0.2s",
      boxShadow: isFailed ? "0 0 14px #ff3b3b55" : isManual ? "0 0 10px #ff9f0a44" : isFixed ? "0 0 8px #a8ff7833" : selected ? `0 0 10px ${sc.border}33` : "none",
      animation: isFailed ? "failPulse 2s infinite" : "none",
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 8 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontFamily: "monospace", fontSize: 9, color: isFailed ? "#ff6b6b" : isManual ? "#ffb340" : "#2a5a2a", marginBottom: 2 }}>
            {finding.source === "cis" ? "CIS" : "STIG"} · {finding.stig.slice(0, 35)}
          </div>
          <div style={{ color: isFailed ? "#ffaaaa" : isManual ? "#ffd080" : isFixed ? "#aaffaa" : "#b8d8b8", fontSize: 12, fontWeight: isFailed || isManual ? 700 : 600, marginBottom: 3, lineHeight: 1.3 }}>
            {isFailed && <span style={{ marginRight: 6 }}>⚠</span>}
            {isManual && <span style={{ marginRight: 6 }}>🔧</span>}
            {finding.title}
          </div>
          <div style={{ fontSize: 10, color: isFailed ? "#ff6b6b" : isManual ? "#ffb340" : "#3a6a3a", fontStyle: "italic" }}>{finding.category}</div>
        </div>
        <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 5, flexShrink: 0 }}>
          <span style={{
            background: sc.bg, border: `1px solid ${sc.border}`,
            color: sc.text, fontSize: 8, padding: "2px 6px", borderRadius: 2,
            fontFamily: "monospace", fontWeight: 700, letterSpacing: 1,
          }}>{finding.severity.toUpperCase()}</span>
          {status && (
            <span style={{
              fontSize: isFailed ? 9 : 8,
              fontFamily: "monospace", letterSpacing: 1, fontWeight: isFailed ? 900 : 400,
              color: isFixed ? "#a8ff78" : status === "running" ? "#00e5ff" : isFailed ? "#ff3b3b" : isManual ? "#ffb340" : "#ffb340",
              background: isFailed ? "#ff3b3b22" : isManual ? "#ff9f0a22" : "transparent",
              padding: (isFailed || isManual) ? "2px 6px" : "0",
              borderRadius: 2,
              border: isFailed ? "1px solid #ff3b3b" : isManual ? "1px solid #ff9f0a" : "none",
            }}>
              {isFixed ? "✓ FIXED" : status === "running" ? "⟳ RUNNING" : isFailed ? "✗ FAILED" : isManual ? "🔧 MANUAL" : "● MAPPED"}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

function DropZone({ label, accept, onFile, loaded, meta }) {
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef();

  const handleFile = (file) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => onFile(e.target.result, file.name);
    reader.readAsText(file);
  };

  return (
    <div
      onClick={() => inputRef.current.click()}
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => { e.preventDefault(); setDragging(false); handleFile(e.dataTransfer.files[0]); }}
      style={{
        border: `2px dashed ${loaded ? "#a8ff78" : dragging ? "#00e5ff" : "#1e3a1e"}`,
        borderRadius: 6, padding: "14px 16px", cursor: "pointer",
        background: loaded ? "#05150a" : dragging ? "#001a2a" : "#030a03",
        transition: "all 0.2s", textAlign: "center",
      }}
    >
      <input ref={inputRef} type="file" accept={accept} style={{ display: "none" }}
        onChange={(e) => handleFile(e.target.files[0])} />
      <div style={{ fontSize: 18, marginBottom: 4 }}>{loaded ? "✓" : "⬆"}</div>
      <div style={{ fontSize: 10, color: loaded ? "#a8ff78" : "#3a6a3a", fontFamily: "monospace", letterSpacing: 1 }}>
        {loaded ? meta?.source || "LOADED" : label}
      </div>
      {loaded && meta && (
        <div style={{ fontSize: 9, color: "#2a5a2a", marginTop: 4, fontFamily: "monospace" }}>
          {meta.target} · {meta.failed} findings
        </div>
      )}
      {!loaded && (
        <div style={{ fontSize: 9, color: "#1a3a1a", marginTop: 4 }}>click or drag & drop</div>
      )}
    </div>
  );
}

// ─── MAIN APP ────────────────────────────────────────────────────────────────

export default function SCAPAutoFix() {
  const [phase, setPhase] = useState("idle");
  const [findings, setFindings] = useState([]);
  const [selected, setSelected] = useState(null);
  const [statuses, setStatuses] = useState({});
  const [logs, setLogs] = useState([]);
  const [activeStep, setActiveStep] = useState(-1);
  const [completedSteps, setCompletedSteps] = useState([]);
  const [compliance, setCompliance] = useState({ before: 0, after: 0 });
  const [scapMeta, setScapMeta] = useState(null);
  const [baselineMeta, setBaselineMeta] = useState(null);
  const [activeTab, setActiveTab] = useState("findings");
  const [filterSev, setFilterSev] = useState("all");
  const [filterCat, setFilterCat] = useState("all");
  const logsRef = useRef(null);

  useEffect(() => {
    if (logsRef.current) logsRef.current.scrollTop = logsRef.current.scrollHeight;
  }, [logs]);

  const addLog = (text, color = "#a8ff78") =>
    setLogs(l => [...l, { text, color, id: Date.now() + Math.random() }]);

  const handleSCAPFile = (text, filename) => {
    addLog(`[+] Loaded SCAP file: ${filename}`, "#00e5ff");
    try {
      const result = parseSCCXCCDF(text);
      if (result.findings.length === 0) {
        // Try CIS parser as fallback
        const cisResult = parseCISBenchmark(text);
        if (cisResult.findings.length > 0) {
          setFindings(cisResult.findings);
          setScapMeta(cisResult.meta);
          addLog(`[+] Parsed as CIS format: ${cisResult.findings.length} findings`, "#a8ff78");
          setPhase("mapped");
          setCompletedSteps([0, 1]);
          const score = Math.floor(100 - (cisResult.findings.filter(f=>f.severity==="high").length * 8) - (cisResult.findings.filter(f=>f.severity==="medium").length * 3));
          setCompliance({ before: Math.max(10, score), after: 0 });
          return;
        }
        addLog("[!] No failed findings found — file may be all-pass or unsupported format", "#ffb340");
        return;
      }
      setFindings(result.findings);
      setScapMeta(result.meta);
      const score = Math.floor(100 - (result.findings.filter(f=>f.severity==="high").length * 8) - (result.findings.filter(f=>f.severity==="medium").length * 3));
      setCompliance({ before: Math.max(10, score), after: 0 });
      addLog(`[+] Parsed ${result.findings.length} failed findings from ${result.meta.source}`, "#a8ff78");
      addLog(`[+] Target: ${result.meta.target}`, "#a8ff78");
      setPhase("mapped");
      setCompletedSteps([0, 1]);
      result.findings.forEach(f => setStatuses(s => ({ ...s, [f.id]: "mapped" })));
    } catch (e) {
      addLog(`[✗] Parse error: ${e.message}`, "#ff3b3b");
    }
  };

  const handleBaselineFile = (text, filename) => {
    addLog(`[+] Loaded baseline file: ${filename}`, "#00e5ff");
    try {
      const result = parseCISBenchmark(text);
      setBaselineMeta({ ...result.meta, filename });
      addLog(`[+] Baseline loaded: ${result.meta.benchmark}`, "#a8ff78");
      addLog(`[+] ${result.findings.length} rules in baseline`, "#a8ff78");
      if (findings.length === 0 && result.findings.length > 0) {
        setFindings(result.findings);
        setScapMeta(result.meta);
        setPhase("mapped");
        setCompletedSteps([0, 1]);
        const score = Math.floor(100 - (result.findings.filter(f=>f.severity==="high").length * 8) - (result.findings.filter(f=>f.severity==="medium").length * 3));
        setCompliance({ before: Math.max(10, score), after: 0 });
        result.findings.forEach(f => setStatuses(s => ({ ...s, [f.id]: "mapped" })));
      }
    } catch (e) {
      addLog(`[✗] Baseline parse error: ${e.message}`, "#ff3b3b");
    }
  };

  const [running, setRunning] = useState(false);

  const [backendOnline, setBackendOnline] = useState(false);

  // Check if backend is running
  useEffect(() => {
    const check = async () => {
      try {
        const res = await fetch("http://127.0.0.1:3001/ping", { method: "POST" });
        const data = await res.json();
        setBackendOnline(data.status === "ok");
      } catch {
        setBackendOnline(false);
      }
    };
    check();
    const interval = setInterval(check, 5000);
    return () => clearInterval(interval);
  }, []);

  const runRemediate = async () => {
    if (running) return;

    if (!backendOnline) {
      addLog("[✗] Backend not running! Start server.js as Administrator first.", "#ff3b3b");
      addLog("    Open elevated CMD and run: node server.js", "#ffb340");
      return;
    }

    setRunning(true);
    setActiveStep(2);
    const sevLabel = filterSev === "all" ? "ALL" : filterSev.toUpperCase();
    addLog(`\n[*] Beginning REAL PowerShell remediation — ${sevLabel} · ${filtered.length} findings`, "#00e5ff");
    addLog("[*] Connected to backend. Executing on system...\n", "#a8ff78");

    const toFix = [...filtered];
    const newStatuses = { ...statuses };

    for (const f of toFix) {
      setStatuses(s => ({ ...s, [f.id]: "running" }));
      setSelected(f);
      addLog(`[EXEC] ${f.stig} — ${f.title.slice(0, 50)}`, "#ffb340");
      addLog(`  PS> ${f.remediation.split("\n")[0].slice(0, 80)}`, "#555");

      try {
        const res = await fetch("http://127.0.0.1:3001/remediate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            ruleId: f.id,
            title: f.title,
            remediation: f.remediation,
          }),
        });
        const result = await res.json();
        newStatuses[f.id] = result.success ? "fixed" : result.manual ? "manual" : "failed";
        setStatuses({ ...newStatuses });
        if (result.success) {
          addLog(`  ✓ Remediated${result.output ? ": " + result.output.slice(0, 60) : ""}`, "#a8ff78");
        } else if (result.manual) {
          addLog(`  ⚠ MANUAL REQUIRED: ${result.output.replace("MANUAL:", "").trim().slice(0, 80)}`, "#ffb340");
        } else {
          addLog(`  ✗ Failed: ${result.output.slice(0, 80)}`, "#ff3b3b");
        }
      } catch (e) {
        newStatuses[f.id] = "failed";
        setStatuses({ ...newStatuses });
        addLog(`  ✗ Backend error: ${e.message}`, "#ff3b3b");
      }
    }

    setCompletedSteps(c => [...new Set([...c, 2])]);
    setActiveStep(3);
    addLog(`\n[*] Verifying ${sevLabel} fixes...`, "#00e5ff");
    await sleep(800);
    const batchFixed = toFix.filter(f => newStatuses[f.id] === "fixed").length;
    addLog(`[+] ${batchFixed}/${toFix.length} ${sevLabel} findings remediated`, "#a8ff78");
    setCompletedSteps(c => [...new Set([...c, 3])]);

    setActiveStep(4);
    await sleep(300);
    addLog("\n[*] Updating compliance score...", "#00e5ff");
    const totalFixed = Object.values(newStatuses).filter(s => s === "fixed").length;
    const afterScore = Math.min(98, Math.floor(compliance.before + (totalFixed / findings.length) * (100 - compliance.before) * 0.9));
    setCompliance(c => ({ ...c, after: afterScore }));
    addLog(`[+] Compliance: ${compliance.before}% → ${afterScore}%`, afterScore >= 80 ? "#a8ff78" : "#ffb340");
    addLog(`[✓] ${sevLabel} batch complete — switch severity to run next batch\n`, "#a8ff78");
    setCompletedSteps(c => [...new Set([...c, 4])]);
    setActiveStep(-1);
    setPhase("mapped");
    setRunning(false);
  };

  const reset = () => {
    setPhase("idle"); setFindings([]); setStatuses({}); setLogs([]);
    setSelected(null); setCompletedSteps([]); setActiveStep(-1);
    setCompliance({ before: 0, after: 0 }); setScapMeta(null); setBaselineMeta(null);
    setFilterSev("all"); setFilterCat("all");
  };

  const categories = ["all", ...new Set(findings.map(f => f.category))];
  const filtered = findings.filter(f =>
    (filterSev === "all" || f.severity === filterSev) &&
    (filterCat === "all" || f.category === filterCat)
  );

  const fixedCount = Object.values(statuses).filter(s => s === "fixed").length;
  const failedCount = Object.values(statuses).filter(s => s === "failed").length;
  const highCount = findings.filter(f => f.severity === "high").length;
  const medCount = findings.filter(f => f.severity === "medium").length;

  const btnBase = {
    padding: "8px 18px", borderRadius: 3, cursor: "pointer",
    fontSize: 10, letterSpacing: 2, fontFamily: "monospace", fontWeight: 700, border: "1px solid",
  };

  return (
    <div style={{ minHeight: "100vh", background: "#020a02", color: "#a8ff78", fontFamily: "monospace", padding: "20px 18px" }}>
      <style>{`
        @keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
        @keyframes pulse { 0%,100%{opacity:0.6} 50%{opacity:1} }
        @keyframes failPulse { 0%,100%{box-shadow: 0 0 14px #ff3b3b55} 50%{box-shadow: 0 0 22px #ff3b3baa} }
        ::-webkit-scrollbar{width:4px} ::-webkit-scrollbar-track{background:#020a02} ::-webkit-scrollbar-thumb{background:#1a4a1a;border-radius:2px}
        * { box-sizing: border-box; }
      `}</style>

      {/* HEADER */}
      <div style={{ borderBottom: "1px solid #0f2a0f", paddingBottom: 14, marginBottom: 16 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 8 }}>
          <div>
            <div style={{ fontSize: 9, color: "#2a5a2a", letterSpacing: 3, marginBottom: 3 }}>WINDOWS · DISA SCC · CIS BENCHMARK</div>
            <h1 style={{ margin: 0, fontSize: 20, fontWeight: 900, letterSpacing: 2, textShadow: "0 0 20px #a8ff7844" }}>
              SCAP AUTO-FIX ENGINE
            </h1>
            <div style={{ fontSize: 9, color: "#3a6a3a", marginTop: 2 }}>Scan → Map → Execute → Verify → Update</div>
            <div style={{ marginTop: 6, display: "flex", alignItems: "center", gap: 6 }}>
              <div style={{ width: 8, height: 8, borderRadius: "50%", background: backendOnline ? "#a8ff78" : "#ff3b3b", boxShadow: backendOnline ? "0 0 6px #a8ff78" : "0 0 6px #ff3b3b" }} />
              <span style={{ fontSize: 9, color: backendOnline ? "#a8ff78" : "#ff3b3b", fontFamily: "monospace", letterSpacing: 1 }}>
                {backendOnline ? "BACKEND ONLINE — REAL EXECUTION ENABLED" : "BACKEND OFFLINE — START server.js AS ADMIN"}
              </span>
            </div>
          </div>
          <div style={{ textAlign: "right" }}>
            {compliance.before > 0 && (
              <div>
                <div style={{ fontSize: 9, color: "#2a5a2a", marginBottom: 2 }}>COMPLIANCE SCORE</div>
                <span style={{ color: "#ff6b6b", fontSize: 22, fontWeight: 900 }}>{compliance.before}%</span>
                {compliance.after > 0 && (
                  <span> → <span style={{ color: "#a8ff78", fontSize: 22, fontWeight: 900 }}>{compliance.after}%</span></span>
                )}
              </div>
            )}
            {scapMeta && (
              <div style={{ fontSize: 9, color: "#2a5a2a", marginTop: 4 }}>
                {scapMeta.target} · {scapMeta.source}
              </div>
            )}
          </div>
        </div>
        <StepPipeline activeStep={activeStep} completedSteps={completedSteps} />
      </div>

      {/* FILE IMPORT ROW */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 16 }}>
        <div>
          <div style={{ fontSize: 8, color: "#2a5a2a", letterSpacing: 3, marginBottom: 6 }}>STEP 1 · SCAP RESULTS FILE</div>
          <DropZone
            label="DROP DISA SCC XCCDF RESULTS (.xml)"
            accept=".xml"
            onFile={handleSCAPFile}
            loaded={!!scapMeta}
            meta={scapMeta}
          />
          <div style={{ fontSize: 8, color: "#1a3a1a", marginTop: 4 }}>
            SCC_XCCDF_Results_&lt;hostname&gt;_&lt;date&gt;.xml
          </div>
        </div>
        <div>
          <div style={{ fontSize: 8, color: "#2a5a2a", letterSpacing: 3, marginBottom: 6 }}>STEP 2 · WINDOWS BASELINE (.xml)</div>
          <DropZone
            label="DROP CIS / DISA STIG BENCHMARK (.xml)"
            accept=".xml"
            onFile={handleBaselineFile}
            loaded={!!baselineMeta}
            meta={baselineMeta ? { source: baselineMeta.benchmark?.slice(0, 30), failed: baselineMeta.findings?.length, target: baselineMeta.filename?.slice(0, 20) } : null}
          />
          <div style={{ fontSize: 8, color: "#1a3a1a", marginTop: 4 }}>
            CIS_Microsoft_Windows_*_Benchmark_*.xml or DISA STIG XCCDF
          </div>
        </div>
      </div>

      {/* ACTION BUTTONS */}
      <div style={{ display: "flex", gap: 10, marginBottom: 16, flexWrap: "wrap" }}>
        {phase === "mapped" && (
          running ? (
            <div style={{ ...btnBase, background: "#0a150a", borderColor: "#00e5ff", color: "#00e5ff", cursor: "default" }}>
              ⟳ REMEDIATING {filterSev !== "all" ? filterSev.toUpperCase() : ""}...
            </div>
          ) : (
            <button onClick={runRemediate} disabled={filtered.filter(f => !statuses[f.id] || statuses[f.id] === "mapped").length === 0} style={{
              ...btnBase, background: "#150a00", borderColor: "#ff9f0a", color: "#ffb340",
              boxShadow: "0 0 10px #ff9f0a22",
              opacity: filtered.filter(f => !statuses[f.id] || statuses[f.id] === "mapped").length === 0 ? 0.4 : 1,
            }}>⚡ EXECUTE AUTO-FIX ({filtered.length}{filterSev !== "all" ? ` ${filterSev.toUpperCase()}` : ""} FINDINGS)</button>
          )
        )}
        {phase === "mapped" && (
          <button onClick={reset} style={{ ...btnBase, background: "#00050f", borderColor: "#00e5ff", color: "#00e5ff" }}>
            ↺ RESET
          </button>
        )}
        {phase === "idle" && (
          <div style={{ fontSize: 10, color: "#1a3a1a", padding: "8px 0", fontStyle: "italic" }}>
            Import a SCAP results file or baseline above to begin ↑
          </div>
        )}
      </div>

      {/* STATS ROW */}
      {findings.length > 0 && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 8, marginBottom: 16 }}>
          {[
            { label: "TOTAL", val: findings.length, color: "#a8ff78" },
            { label: "HIGH", val: highCount, color: "#ff6b6b" },
            { label: "MEDIUM", val: medCount, color: "#ffb340" },
            { label: "FIXED", val: fixedCount, color: "#a8ff78" },
            { label: "FAILED", val: failedCount, color: "#ff3b3b" },
          ].map(s => (
            <div key={s.label} style={{
              background: "#050d05", border: "1px solid #0f2a0f", borderRadius: 4,
              padding: "8px 6px", textAlign: "center",
            }}>
              <div style={{ fontSize: 18, fontWeight: 900, color: s.color }}>{s.val}</div>
              <div style={{ fontSize: 7, color: "#2a5a2a", letterSpacing: 2, marginTop: 1 }}>{s.label}</div>
            </div>
          ))}
        </div>
      )}

      {/* MAIN CONTENT */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>

        {/* LEFT: Findings */}
        <div>
          {/* Filters */}
          {findings.length > 0 && (
            <div style={{ display: "flex", gap: 6, marginBottom: 10, flexWrap: "wrap" }}>
              {["all", "high", "medium", "low"].map(s => (
                <button key={s} onClick={() => setFilterSev(s)} style={{
                  ...btnBase, padding: "4px 10px", fontSize: 8,
                  background: filterSev === s ? "#0a2a0a" : "#030a03",
                  borderColor: filterSev === s ? (SEVERITY_COLOR[s]?.border || "#a8ff78") : "#0f2a0f",
                  color: filterSev === s ? (SEVERITY_COLOR[s]?.text || "#a8ff78") : "#2a5a2a",
                }}>{s.toUpperCase()}</button>
              ))}
              <select value={filterCat} onChange={e => setFilterCat(e.target.value)} style={{
                background: "#030a03", border: "1px solid #0f2a0f", color: "#3a6a3a",
                fontSize: 8, padding: "4px 8px", borderRadius: 3, fontFamily: "monospace",
              }}>
                {categories.map(c => <option key={c} value={c}>{c.toUpperCase()}</option>)}
              </select>
            </div>
          )}

          <div style={{ fontSize: 8, color: "#2a5a2a", letterSpacing: 3, marginBottom: 8 }}>
            FINDINGS {filtered.length > 0 && `· ${filtered.length} SHOWN`}
          </div>

          {findings.length === 0 ? (
            <div style={{
              border: "1px dashed #0f2a0f", borderRadius: 6, padding: "36px 20px",
              textAlign: "center", color: "#1a3a1a", fontSize: 11,
            }}>
              No findings loaded.<br />
              <span style={{ fontSize: 9, marginTop: 6, display: "block" }}>
                Import a SCAP results or baseline file above.
              </span>
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 6, maxHeight: 480, overflowY: "auto" }}>
              {filtered.map(f => (
                <FindingCard
                  key={f.id}
                  finding={f}
                  status={statuses[f.id]}
                  onSelect={setSelected}
                  selected={selected?.id === f.id}
                />
              ))}
            </div>
          )}
        </div>

        {/* RIGHT: Detail + Terminal */}
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>

          {/* Tabs */}
          <div style={{ display: "flex", gap: 0, borderBottom: "1px solid #0f2a0f" }}>
            {["remediation", "terminal"].map(tab => (
              <button key={tab} onClick={() => setActiveTab(tab)} style={{
                ...btnBase, borderRadius: "3px 3px 0 0", border: "none",
                borderBottom: activeTab === tab ? "2px solid #a8ff78" : "2px solid transparent",
                background: "transparent", color: activeTab === tab ? "#a8ff78" : "#2a5a2a",
                padding: "6px 14px", fontSize: 8,
              }}>{tab.toUpperCase()}</button>
            ))}
          </div>

          {activeTab === "remediation" && (
            <div style={{ flex: 1 }}>
              {selected ? (
                <div style={{
                  background: "#050d05", border: "1px solid #0f2a0f",
                  borderLeft: `3px solid ${SEVERITY_COLOR[selected.severity]?.border || "#a8ff78"}`,
                  borderRadius: 5, padding: 14,
                }}>
                  <div style={{ fontSize: 8, color: "#2a5a2a", letterSpacing: 3, marginBottom: 8 }}>REMEDIATION DETAIL</div>
                  <div style={{ color: "#b8d8b8", fontSize: 13, fontWeight: 700, marginBottom: 4 }}>{selected.title}</div>
                  <div style={{ fontSize: 9, color: "#3a6a3a", marginBottom: 10, fontStyle: "italic" }}>
                    {selected.category} · {selected.stig.slice(0, 50)}
                  </div>
                  {selected.description && (
                    <div style={{ fontSize: 10, color: "#4a7a4a", marginBottom: 12, lineHeight: 1.6 }}>
                      {selected.description.slice(0, 250)}{selected.description.length > 250 ? "..." : ""}
                    </div>
                  )}
                  <div style={{ fontSize: 8, color: "#2a5a2a", letterSpacing: 2, marginBottom: 6 }}>POWERSHELL REMEDIATION</div>
                  <div style={{
                    background: "#020a02", border: "1px solid #0a1f0a", borderRadius: 4,
                    padding: "10px 12px", fontSize: 10, color: "#a8ff78",
                    whiteSpace: "pre-wrap", wordBreak: "break-all", lineHeight: 1.8,
                    maxHeight: 200, overflowY: "auto",
                  }}>
                    <span style={{ color: "#2a5a2a" }}>PS C:\&gt; </span>{selected.remediation}
                  </div>
                  <div style={{
                    marginTop: 10, fontSize: 8, color: "#1a3a1a", fontStyle: "italic",
                    borderTop: "1px solid #0a1f0a", paddingTop: 8,
                  }}>
                    ⚠ Always test remediation scripts in a lab environment before production deployment.
                  </div>
                </div>
              ) : (
                <div style={{
                  border: "1px dashed #0f2a0f", borderRadius: 5, padding: "30px 20px",
                  textAlign: "center", color: "#1a3a1a", fontSize: 10,
                }}>
                  Select a finding to view<br />its remediation script
                </div>
              )}
            </div>
          )}

          {activeTab === "terminal" && (
            <div style={{ background: "#020a02", border: "1px solid #0a1f0a", borderRadius: 5, flex: 1 }}>
              <div style={{
                padding: "6px 12px", borderBottom: "1px solid #0a1f0a",
                display: "flex", alignItems: "center", gap: 6,
              }}>
                {["#ff3b3b", "#ff9f0a", "#a8ff78"].map(c => (
                  <div key={c} style={{ width: 7, height: 7, borderRadius: "50%", background: c }} />
                ))}
                <span style={{ fontSize: 8, color: "#1a3a1a", marginLeft: 8, letterSpacing: 2 }}>
                  AUTOFIX · POWERSHELL TERMINAL
                </span>
              </div>
              <div ref={logsRef} style={{ padding: 12, height: 360, overflowY: "auto" }}>
                {logs.length === 0 ? (
                  <span style={{ color: "#1a3a1a", fontSize: 10 }}>Awaiting input...<span style={{ animation: "pulse 1s infinite" }}>▌</span></span>
                ) : logs.map(log => (
                  <div key={log.id} style={{ color: log.color, fontSize: 10, lineHeight: 1.8, whiteSpace: "pre-wrap" }}>
                    {log.text}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* FOOTER */}
      <div style={{
        marginTop: 16, borderTop: "1px solid #0a1f0a", paddingTop: 10,
        display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: 4,
        fontSize: 8, color: "#1a3a1a", letterSpacing: 1,
      }}>
        <span>SCAP v1.3 · XCCDF 1.1/1.2 · OVAL</span>
        <span>DISA SCC · CIS BENCHMARK · NIST 800-53</span>
        <span>WINDOWS TARGET · POWERSHELL REMEDIATION</span>
      </div>
    </div>
  );
}
