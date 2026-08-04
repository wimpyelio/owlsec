type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
type OwaspCategory =
  | "LLM01" | "LLM02" | "LLM03" | "LLM04" | "LLM05"
  | "LLM06" | "LLM07" | "LLM08" | "LLM09" | "LLM10";

interface Finding {
  id: string;
  severity: Severity;
  score: number;
  category: OwaspCategory;
  category_name: string;
  title: string;
  description_security: string;
  description_plain: string;
  evidence: string;
  evidence_location: string;
  remediation: string;
}

type CoverageStatus = "Assessed" | "Insufficient Input" | "Not Applicable";
interface CoverageEntry { code: string; name: string; status: CoverageStatus; note?: string; }

interface ScanReport {
  scan_id: string;
  timestamp: string;
  artifact_hash: string;
  inputs_provided: string[];
  executive_summary: string;
  aggregate: { highest: Severity; counts: Record<Severity, number> };
  coverage: CoverageEntry[];
  findings: Finding[];
  ruleset_version: string;
}

export interface ReviewerEdit { severity?: Severity; dismissed?: boolean; note: string; }

export function toMarkdown(report: ScanReport, edits: Record<string, ReviewerEdit>, mode: "security"|"plain", clientName?: string): string {
  const lines: string[] = [];
  lines.push("# OWASP AI Security Scan Report");
  if (clientName) lines.push(`\n**Client / Target:** ${clientName}`);
  lines.push("\n> Static triage report. This does NOT confirm exploitability or replace a pentest.");
  lines.push("\n## 1. Scan Metadata");
  lines.push("| Key | Value |\n|---|---|");
  lines.push("| Scan ID | `" + report.scan_id + "` |\n| Timestamp | " + report.timestamp + " |\n| Artifact SHA-256 | `" + report.artifact_hash + "` |\n| Ruleset | " + report.ruleset_version + " |\n| Inputs provided | " + report.inputs_provided.join(", ") + " |");
  lines.push("\n## 2. Executive Summary\n\n" + report.executive_summary);
  lines.push("\n## 3. Aggregate Risk Score\n\n**Highest severity present:** " + report.aggregate.highest + "\n");
  lines.push("| Severity | Count |\n|---|---|");
  (["CRITICAL","HIGH","MEDIUM","LOW","INFO"] as Severity[]).forEach(s => lines.push("| " + s + " | " + (report.aggregate.counts[s]??0) + " |"));
  lines.push("\n## 4. OWASP Coverage Map\n| Code | Category | Status | Note |\n|---|---|---|---|");
  for (const c of report.coverage) lines.push("| " + c.code + " | " + c.name + " | " + c.status + " | " + (c.note??"") + " |");
  lines.push("\n## 5. Findings");
  const active = report.findings.filter((f: Finding) => !edits[f.id]?.dismissed);
  if (!active.length) lines.push("\n_No active findings._");
  for (const f of active) {
    const e = edits[f.id]; const sev = e?.severity??f.severity; const overridden = e?.severity && e.severity!==f.severity;
    const desc = mode==="plain" ? f.description_plain : f.description_security;
    lines.push("\n### [" + sev + "] " + f.category + " \u2014 " + f.title);
    if (overridden) lines.push("> \u26a0\ufe0f Reviewer changed severity from **" + f.severity + "** to **" + sev + "**.");
    lines.push("- **Description:** " + desc + "\n- **Evidence** (" + f.evidence_location + "):\n\n  ```\n  " + f.evidence.replace(/\n/g,"\n  ") + "\n  ```");
    lines.push("- **Remediation:** " + f.remediation);
    if (e?.note) lines.push("- **Reviewer note:** " + e.note);
  }
  const dismissed = report.findings.filter((f: Finding) => edits[f.id]?.dismissed);
  if (dismissed.length) {
    lines.push("\n## 6. Dismissed Findings (Reviewer Overrides)");
    for (const f of dismissed) {
      lines.push("\n### ~~[" + f.severity + "] " + f.category + " \u2014 " + f.title + "~~");
      lines.push("- **Original evidence:** " + f.evidence_location + "\n- **Reviewer justification:** " + (edits[f.id].note || "(none provided)"));
    }
  }
  return lines.join("\n");
}

export function downloadMarkdown(md: string, filename: string) {
  const blob = new Blob([md], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob); const a = document.createElement("a");
  a.href = url; a.download = filename; a.click(); URL.revokeObjectURL(url);
}

export function severityBadgeClass(sev: Severity): string {
  switch (sev) {
    case "CRITICAL": return "bg-sev-critical text-white border-sev-critical/60";
    case "HIGH": return "bg-sev-high/90 text-black border-sev-high/60";
    case "MEDIUM": return "bg-sev-medium/90 text-black border-sev-medium/60";
    case "LOW": return "bg-sev-low/80 text-black border-sev-low/60";
    case "INFO": return "bg-sev-info/60 text-white border-sev-info/60";
  }
}