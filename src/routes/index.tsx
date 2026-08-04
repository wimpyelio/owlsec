import { useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Upload,
  Loader2,
  Download,
  Copy,
  FileWarning,
  X,
  Info,
  Check,
  ChevronDown,
  ChevronRight,
  Sparkles,
  Clock,
  Hash,
  Zap,
  History,
  ArrowRight,
  Sun,
  Moon,
} from "lucide-react";
import { useTheme } from "@/hooks/use-theme";
import { OwlSecLogo } from "@/components/owlsec-logo";
import { DEMO_ARTIFACTS } from "@/lib/demo-artifacts";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast, Toaster } from "sonner";
import {
  downloadMarkdown,
  severityBadgeClass,
  toMarkdown,
  type ReviewerEdit,
} from "@/lib/report-utils";

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
type OwaspCategory =
  "LLM01" | "LLM02" | "LLM03" | "LLM04" | "LLM05" | "LLM06" | "LLM07" | "LLM08" | "LLM09" | "LLM10";

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
interface CoverageEntry {
  code: string;
  name: string;
  status: CoverageStatus;
  note?: string;
}

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

type CodeFile = { name: string; content: string };
type RecentScan = { id: string; timestamp: string; hash: string; highest: Severity; total: number };

const RECENT_KEY = "owlsec.recent.v2"; // bump when RecentScan shape changes

function parseRecentScans(raw: string): RecentScan[] {
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (r): r is RecentScan =>
        r != null &&
        typeof r === "object" &&
        typeof r.id === "string" &&
        typeof r.timestamp === "string" &&
        typeof r.hash === "string" &&
        typeof r.highest === "string" &&
        typeof r.total === "number",
    );
  } catch {
    return [];
  }
}
const SEV_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const STAGES = [
  { key: "validate", label: "Validating artifacts" },
  { key: "analyze", label: "Static analysis · OWASP mapping" },
  { key: "score", label: "Scoring findings (temperature 0)" },
  { key: "render", label: "Rendering report" },
] as const;

export function ScannerPage() {
  const [systemPrompt, setSystemPrompt] = useState("");
  const [toolConfig, setToolConfig] = useState("");
  const [architecture, setArchitecture] = useState("");
  const [codeFiles, setCodeFiles] = useState<CodeFile[]>([]);
  const [loading, setLoading] = useState(false);
  const [stageIdx, setStageIdx] = useState(0);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [mode, setMode] = useState<"security" | "plain">("security");
  const [edits, setEdits] = useState<Record<string, ReviewerEdit>>({});
  const [filter, setFilter] = useState<Severity | "ALL">("ALL");
  const [clientName, setClientName] = useState("");
  const [recent, setRecent] = useState<RecentScan[]>([]);
  const lastDemoIdx = useRef<number>(-1);

  useEffect(() => {
    try {
      const raw = localStorage.getItem(RECENT_KEY);
      if (raw) setRecent(parseRecentScans(raw));
    } catch {
      /* ignore */
    }
  }, []);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter" && !loading && !report) {
        e.preventDefault();
        onScan();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [systemPrompt, toolConfig, architecture, codeFiles, loading, report]);

  const promptOver = systemPrompt.length > 20000;
  const configValid = useMemo(() => {
    if (!toolConfig.trim()) return { ok: true as const };
    try {
      JSON.parse(toolConfig);
      return { ok: true as const };
    } catch (e) {
      const m = (e as Error).message;
      const line = /line (\d+)/.exec(m)?.[1];
      return {
        ok: false as const,
        msg: line ? `Invalid JSON at line ${line}: ${m}` : `Invalid JSON: ${m}`,
      };
    }
  }, [toolConfig]);

  async function handleFiles(list: FileList | null) {
    if (!list) return;
    const next: CodeFile[] = [...codeFiles];
    for (const f of Array.from(list)) {
      if (next.length >= 5) {
        toast.error("Max 5 code files");
        break;
      }
      if (f.size > 200 * 1024) {
        toast.error(`${f.name} exceeds 200KB`);
        continue;
      }
      const content = await f.text();
      next.push({ name: f.name, content });
    }
    setCodeFiles(next);
  }

  async function onScan() {
    setError(null);
    if (!systemPrompt.trim()) {
      setError("System prompt is required.");
      return;
    }
    if (promptOver) {
      setError("System prompt exceeds 20,000 characters.");
      return;
    }
    if (!configValid.ok) {
      setError(configValid.msg);
      return;
    }
    setLoading(true);
    setStageIdx(0);
    const stageTimer = setInterval(() => {
      setStageIdx((i) => Math.min(i + 1, STAGES.length - 1));
    }, 1400);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          system_prompt: systemPrompt,
          tool_config: toolConfig || undefined,
          architecture: architecture || undefined,
          code_files: codeFiles.length ? codeFiles : undefined,
        }),
      });
      if (!res.ok) {
        const txt = await res.text();
        throw new Error(txt || `HTTP ${res.status}`);
      }
      const result = await res.json();
      setReport(result);
      setEdits({});
      const entry: RecentScan = {
        id: result.scan_id,
        timestamp: result.timestamp,
        hash: result.artifact_hash.slice(0, 12),
        highest: result.aggregate.highest,
        total: result.findings.length,
      };
      const nextRecent = [entry, ...recent.filter((r) => r.id !== entry.id)].slice(0, 5);
      setRecent(nextRecent);
      try {
        localStorage.setItem(RECENT_KEY, JSON.stringify(nextRecent));
      } catch {
        /* ignore */
      }
      toast.success(`Scan complete · ${result.findings.length} findings`);
    } catch (e) {
      const msg = (e as Error).message ?? "Scan failed";
      setError(msg);
      toast.error(msg);
    } finally {
      clearInterval(stageTimer);
      setLoading(false);
    }
  }

  function loadDemo() {
    let idx = Math.floor(Math.random() * DEMO_ARTIFACTS.length);
    if (DEMO_ARTIFACTS.length > 1 && idx === lastDemoIdx.current)
      idx = (idx + 1) % DEMO_ARTIFACTS.length;
    lastDemoIdx.current = idx;
    const d = DEMO_ARTIFACTS[idx];
    setSystemPrompt(d.systemPrompt);
    setToolConfig(d.toolConfig);
    setArchitecture(d.architecture);
    setCodeFiles(d.codeFiles);
    toast.success(`Loaded demo · ${d.label}`);
  }

  const { theme, toggle } = useTheme();

  return (
    <div className="relative min-h-screen">
      <Toaster theme={theme} position="top-right" richColors />
      <TopBar theme={theme} onToggleTheme={toggle} />
      <main
        id="main-content"
        tabIndex={-1}
        className="mx-auto max-w-6xl px-4 py-8 sm:px-6 sm:py-10 focus:outline-none"
      >
        {!report && !loading && (
          <LandingView
            systemPrompt={systemPrompt}
            setSystemPrompt={setSystemPrompt}
            toolConfig={toolConfig}
            setToolConfig={setToolConfig}
            architecture={architecture}
            setArchitecture={setArchitecture}
            codeFiles={codeFiles}
            setCodeFiles={setCodeFiles}
            handleFiles={handleFiles}
            configValid={configValid}
            promptOver={promptOver}
            error={error}
            onScan={onScan}
            loadDemo={loadDemo}
            recent={recent}
          />
        )}
        {loading && <ScanProgress stageIdx={stageIdx} />}
        {report && !loading && (
          <ReportView
            report={report}
            edits={edits}
            setEdits={setEdits}
            mode={mode}
            setMode={setMode}
            filter={filter}
            setFilter={setFilter}
            clientName={clientName}
            setClientName={setClientName}
            onNew={() => setReport(null)}
          />
        )}
      </main>
      <footer className="mx-auto mt-16 max-w-6xl px-6 pb-10 text-xs text-muted-foreground">
        Triage tool — not a substitute for dynamic red-teaming or a pentest. Artifacts are hashed;
        raw content is never persisted.
      </footer>
    </div>
  );
}

function TopBar({ theme, onToggleTheme }: { theme: "light" | "dark"; onToggleTheme: () => void }) {
  return (
    <header className="sticky top-0 z-30 border-b border-border/60 bg-background/75 backdrop-blur-xl">
      <div className="mx-auto grid max-w-6xl grid-cols-[minmax(0,1fr)_auto] items-center gap-3 px-4 py-3 sm:px-6">
        <a href="/" className="flex min-w-0 items-center gap-3 rounded-md" aria-label="OwlSec home">
          <div className="relative flex h-10 w-10 shrink-0 items-center justify-center rounded-md border border-border bg-card p-1 shadow-sm">
            <OwlSecLogo />
            <span className="absolute -right-0.5 -top-0.5 h-1.5 w-1.5 animate-pulse rounded-full bg-primary" />
          </div>
          <div className="min-w-0 leading-tight">
            <h1 className="truncate font-serif text-lg tracking-tight">
              Owl<span className="text-primary">Sec</span>
            </h1>
            <p className="truncate font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground">
              OWASP · LLM Top 10 · Static Triage
            </p>
          </div>
        </a>
        <div className="flex shrink-0 items-center gap-2 text-xs text-muted-foreground sm:gap-3">
          <span className="hidden items-center gap-1.5 md:flex">
            <span className="h-1.5 w-1.5 rounded-full bg-primary" /> Ruleset v1
          </span>
          <a
            href="https://genai.owasp.org/llm-top-10/"
            target="_blank"
            rel="noreferrer"
            className="hidden hover:text-foreground md:inline"
          >
            OWASP LLM Top 10 ↗
          </a>
          <button
            onClick={onToggleTheme}
            aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
            className="flex h-9 w-9 items-center justify-center rounded-md border border-border bg-card transition hover:bg-muted"
          >
            {theme === "dark" ? (
              <Sun className="h-4 w-4 text-primary" />
            ) : (
              <Moon className="h-4 w-4 text-primary" />
            )}
          </button>
        </div>
      </div>
    </header>
  );
}

function LandingView(props: {
  systemPrompt: string;
  setSystemPrompt: (v: string) => void;
  toolConfig: string;
  setToolConfig: (v: string) => void;
  architecture: string;
  setArchitecture: (v: string) => void;
  codeFiles: CodeFile[];
  setCodeFiles: (v: CodeFile[]) => void;
  handleFiles: (l: FileList | null) => void;
  configValid: { ok: true } | { ok: false; msg: string };
  promptOver: boolean;
  error: string | null;
  onScan: () => void;
  loadDemo: () => void;
  recent: RecentScan[];
}) {
  const {
    systemPrompt,
    setSystemPrompt,
    toolConfig,
    setToolConfig,
    architecture,
    setArchitecture,
    codeFiles,
    setCodeFiles,
    handleFiles,
    configValid,
    promptOver,
    error,
    onScan,
    loadDemo,
    recent,
  } = props;
  return (
    <div className="space-y-10">
      <section className="relative overflow-hidden rounded-2xl border border-border/60 bg-card px-6 py-12 sm:px-10 sm:py-16">
        <div className="dot-bg pointer-events-none absolute inset-0 opacity-70" />
        <div className="pointer-events-none absolute -right-24 -top-24 h-72 w-72 rounded-full bg-primary/10 blur-3xl" />
        <div className="relative">
          <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-border bg-background/60 px-3 py-1 font-mono text-[10px] uppercase tracking-[0.18em] text-muted-foreground">
            <span className="h-1.5 w-1.5 rounded-full bg-primary" /> Deterministic · temperature 0
          </div>
          <h2 className="max-w-3xl font-serif text-4xl leading-[1.05] tracking-tight sm:text-5xl">
            The first hour of AI security triage, <em className="italic text-primary">automated</em>
            .
          </h2>
          <p className="mt-3 max-w-2xl text-sm text-muted-foreground sm:text-base">
            Paste a system prompt, agent config, or a few files. OwlSec returns a scored,
            evidence-backed report mapped to the OWASP LLM Top 10 (2025) — the kind you'd defend to
            a peer.
          </p>
          <div className="mt-6 flex flex-wrap gap-3 text-xs text-muted-foreground">
            <Stat icon={<Clock className="h-3.5 w-3.5" />} label="≤ 3 min p50" />
            <Stat icon={<Hash className="h-3.5 w-3.5" />} label="Hashed, never persisted" />
            <Stat icon={<Zap className="h-3.5 w-3.5" />} label="9 OWASP categories" />
          </div>
        </div>
      </section>
      <div className="grid gap-6 lg:grid-cols-[1.5fr_1fr]">
        <Card className="border-border/60">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Upload className="h-4 w-4 text-primary" />
              New scan
            </CardTitle>
            <CardDescription>
              System prompt is required. Optional inputs unlock deeper coverage — the report tells
              you exactly which categories couldn't be assessed.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-5">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label
                  htmlFor="sp"
                  className="text-xs uppercase tracking-wider text-muted-foreground"
                >
                  System prompt <span className="text-destructive">*</span>
                </Label>
                <span
                  className={`text-xs tabular-nums ${promptOver ? "text-destructive" : "text-muted-foreground"}`}
                >
                  {systemPrompt.length.toLocaleString()} / 20,000
                </span>
              </div>
              <Textarea
                id="sp"
                value={systemPrompt}
                onChange={(e) => setSystemPrompt(e.target.value)}
                rows={8}
                placeholder="You are a helpful assistant with access to..."
                className="font-mono text-xs"
              />
            </div>
            <details className="group rounded-md border border-border/60 bg-muted/20">
              <summary className="flex cursor-pointer items-center justify-between px-3 py-2 text-xs text-muted-foreground hover:text-foreground">
                <span className="flex items-center gap-2">
                  <ChevronRight className="h-3.5 w-3.5 transition group-open:rotate-90" />
                  Optional inputs
                  <OptionalBadges
                    hasConfig={!!toolConfig.trim()}
                    hasArch={!!architecture.trim()}
                    files={codeFiles.length}
                  />
                </span>
              </summary>
              <div className="space-y-4 border-t border-border/60 p-3">
                <div className="space-y-2">
                  <Label htmlFor="tc" className="text-xs">
                    Tool / agent config (JSON)
                  </Label>
                  <Textarea
                    id="tc"
                    value={toolConfig}
                    onChange={(e) => setToolConfig(e.target.value)}
                    rows={5}
                    placeholder={`{ "tools": [ { "name": "search_web", "permission_scope": "read" } ] }`}
                    className="font-mono text-xs"
                  />
                  {!configValid.ok && <p className="text-xs text-destructive">{configValid.msg}</p>}
                </div>
                <div className="space-y-2">
                  <Label htmlFor="arch" className="text-xs">
                    Architecture description
                  </Label>
                  <Textarea
                    id="arch"
                    value={architecture}
                    onChange={(e) => setArchitecture(e.target.value)}
                    rows={3}
                    maxLength={2000}
                    placeholder="Describe RAG pipeline, fine-tuning data sources, tenant model..."
                  />
                </div>
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <Label className="text-xs">Code files (Python / JS / TS · up to 5)</Label>
                    <label className="cursor-pointer rounded text-xs text-primary hover:underline focus-within:outline focus-within:outline-2 focus-within:outline-offset-2 focus-within:outline-ring">
                      <input
                        type="file"
                        multiple
                        accept=".py,.js,.ts,.tsx,.jsx,.mjs,.txt"
                        className="sr-only"
                        aria-label="Add code files"
                        onChange={(e) => handleFiles(e.target.files)}
                      />
                      + Add files
                    </label>
                  </div>
                  {codeFiles.length > 0 && (
                    <ul className="space-y-1 rounded-md border border-border/60 bg-muted/30 p-2 text-xs">
                      {codeFiles.map((f, i) => (
                        <li key={i} className="flex items-center justify-between">
                          <span className="font-mono">{f.name}</span>
                          <span className="text-muted-foreground">
                            {(f.content.length / 1024).toFixed(1)} KB
                            <button
                              onClick={() => setCodeFiles(codeFiles.filter((_, j) => j !== i))}
                              aria-label={`Remove file ${f.name}`}
                              className="ml-3 rounded text-destructive hover:text-destructive/80"
                            >
                              remove
                            </button>
                          </span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            </details>
            {error && (
              <div className="flex items-start gap-2 rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}
            <div className="flex flex-wrap items-center gap-2">
              <Button onClick={onScan} size="lg" className="min-w-44 shadow-lg shadow-primary/20">
                <ShieldAlert className="mr-2 h-4 w-4" /> Run scan
                <ArrowRight className="ml-1 h-3.5 w-3.5" />
              </Button>
              <Button variant="secondary" onClick={loadDemo}>
                <Sparkles className="mr-2 h-3.5 w-3.5" /> Load demo artifact
              </Button>
              <span className="ml-auto text-[11px] text-muted-foreground">
                <kbd className="rounded border border-border bg-muted/40 px-1.5 py-0.5 font-mono text-[10px]">
                  Ctrl
                </kbd>{" "}
                +{" "}
                <kbd className="rounded border border-border bg-muted/40 px-1.5 py-0.5 font-mono text-[10px]">
                  Enter
                </kbd>{" "}
                to scan
              </span>
            </div>
          </CardContent>
        </Card>
        <div className="space-y-4">
          <CoverageCard />
          {recent.length > 0 && <RecentScansCard items={recent} />}
        </div>
      </div>
    </div>
  );
}

function OptionalBadges({
  hasConfig,
  hasArch,
  files,
}: {
  hasConfig: boolean;
  hasArch: boolean;
  files: number;
}) {
  const active = [hasConfig && "config", hasArch && "arch", files > 0 && `${files} files`].filter(
    Boolean,
  );
  if (!active.length) return null;
  return (
    <span className="ml-1 rounded-full bg-primary/15 px-2 py-0.5 text-[10px] text-primary">
      {active.join(" · ")}
    </span>
  );
}
function Stat({ icon, label }: { icon: React.ReactNode; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-border/60 bg-card/60 px-2.5 py-1">
      {icon} {label}
    </span>
  );
}
function CoverageCard() {
  const items: [string, string][] = [
    ["LLM01", "Prompt Injection"],
    ["LLM02", "Sensitive Info Disclosure"],
    ["LLM03", "Supply Chain"],
    ["LLM04", "Data & Model Poisoning"],
    ["LLM05", "Improper Output Handling"],
    ["LLM06", "Excessive Agency"],
    ["LLM07", "System Prompt Leakage"],
    ["LLM08", "Vector & Embedding"],
    ["LLM09", "Misinformation"],
    ["LLM10", "Unbounded Consumption"],
  ];
  return (
    <Card className="border-border/60">
      <CardHeader>
        <CardTitle className="text-sm">Coverage</CardTitle>
        <CardDescription className="text-xs">
          All 10 OWASP LLM categories. LLM09 (Misinformation) is assessed heuristically from the
          system prompt — it can't catch factual errors in live outputs.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ul className="space-y-1 text-xs">
          {items.map(([c, n]) => (
            <li key={c} className="flex items-center justify-between text-muted-foreground">
              <span>
                <span className="font-mono text-primary">{c}</span>{" "}
                <span className="text-foreground">{n}</span>
              </span>
              <ShieldCheck className="h-3.5 w-3.5 text-primary/70" />
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
function RecentScansCard({ items }: { items: RecentScan[] }) {
  return (
    <Card className="border-border/60">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-sm">
          <History className="h-3.5 w-3.5 text-primary" />
          Recent scans
        </CardTitle>
        <CardDescription className="text-xs">Stored locally in your browser only.</CardDescription>
      </CardHeader>
      <CardContent>
        <ul className="space-y-1 text-xs">
          {items.map((r) => (
            <li
              key={r.id}
              className="flex items-center justify-between rounded-md border border-border/40 bg-muted/20 px-2 py-1.5"
            >
              <span className="flex items-center gap-2">
                <Badge className={`${severityBadgeClass(r.highest)} text-[10px]`}>
                  {r.highest}
                </Badge>
                <span className="font-mono text-muted-foreground">{r.hash}</span>
              </span>
              <span className="text-muted-foreground">
                {r.total} findings ·{" "}
                {new Date(r.timestamp).toLocaleTimeString([], {
                  hour: "2-digit",
                  minute: "2-digit",
                })}
              </span>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
function ScanProgress({ stageIdx }: { stageIdx: number }) {
  return (
    <div className="mx-auto max-w-xl py-16">
      <Card className="border-border/60 bg-card/60">
        <CardContent className="space-y-6 py-10">
          <div className="flex flex-col items-center gap-3">
            <div className="relative h-16 w-16">
              <div className="absolute inset-0 animate-ping rounded-full bg-primary/20" />
              <div className="relative flex h-full w-full items-center justify-center rounded-full bg-primary/15 ring-1 ring-primary/40">
                <Loader2 className="h-6 w-6 animate-spin text-primary" />
              </div>
            </div>
            <div className="text-center">
              <div className="text-sm font-medium">Analyzing artifacts</div>
              <div className="text-xs text-muted-foreground">
                Deterministic scoring · this usually takes 20–90 seconds
              </div>
            </div>
          </div>
          <ol className="space-y-2">
            {STAGES.map((s, i) => {
              const done = i < stageIdx;
              const active = i === stageIdx;
              return (
                <li
                  key={s.key}
                  className={`flex items-center gap-3 rounded-md border px-3 py-2 text-xs transition ${active ? "border-primary/50 bg-primary/10 text-foreground" : done ? "border-border/40 text-muted-foreground" : "border-border/30 text-muted-foreground/60"}`}
                >
                  <span
                    className={`flex h-5 w-5 items-center justify-center rounded-full text-[10px] ${done ? "bg-primary/20 text-primary" : active ? "bg-primary/30 text-primary" : "bg-muted text-muted-foreground"}`}
                  >
                    {done ? <Check className="h-3 w-3" /> : i + 1}
                  </span>
                  {s.label}
                  {active && <Loader2 className="ml-auto h-3 w-3 animate-spin text-primary" />}
                </li>
              );
            })}
          </ol>
        </CardContent>
      </Card>
    </div>
  );
}

function ReportView({
  report,
  edits,
  setEdits,
  mode,
  setMode,
  filter,
  setFilter,
  clientName,
  setClientName,
  onNew,
}: {
  report: ScanReport;
  edits: Record<string, ReviewerEdit>;
  setEdits: (v: Record<string, ReviewerEdit>) => void;
  mode: "security" | "plain";
  setMode: (m: "security" | "plain") => void;
  filter: Severity | "ALL";
  setFilter: (s: Severity | "ALL") => void;
  clientName: string;
  setClientName: (v: string) => void;
  onNew: () => void;
}) {
  const shown = report.findings.filter((f) => filter === "ALL" || f.severity === filter);
  const grouped = useMemo(() => {
    const g: Record<Severity, typeof shown> = {
      CRITICAL: [],
      HIGH: [],
      MEDIUM: [],
      LOW: [],
      INFO: [],
    };
    for (const f of shown) g[f.severity].push(f);
    return g;
  }, [shown]);
  function exportMd() {
    const md = toMarkdown(report, edits, mode, clientName || undefined);
    downloadMarkdown(md, `owlsec-scan-${report.scan_id.slice(0, 8)}.md`);
  }
  async function copyMd() {
    const md = toMarkdown(report, edits, mode, clientName || undefined);
    await navigator.clipboard.writeText(md);
    toast.success("Report copied to clipboard");
  }
  return (
    <div className="space-y-6">
      <div
        className="sticky top-14 z-20 -mx-4 border-b border-border/60 bg-background/85 px-4 py-3 backdrop-blur-xl sm:-mx-6 sm:px-6"
        role="toolbar"
        aria-label="Report actions"
      >
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <button
              onClick={onNew}
              aria-label="Start a new scan"
              className="rounded text-xs text-muted-foreground hover:text-foreground"
            >
              ← New scan
            </button>
            <span className="text-xs text-muted-foreground">
              {new Date(report.timestamp).toLocaleString()}
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center gap-2 rounded-md border border-border/60 bg-card/60 px-3 py-1.5 text-xs">
              <Switch
                id="mode"
                checked={mode === "plain"}
                onCheckedChange={(v) => setMode(v ? "plain" : "security")}
              />
              <Label htmlFor="mode" className="cursor-pointer">
                {mode === "plain" ? "Plain" : "Security"}
              </Label>
            </div>
            <Button size="sm" variant="secondary" onClick={copyMd}>
              <Copy className="mr-1.5 h-3.5 w-3.5" /> Copy
            </Button>
            <Button size="sm" onClick={exportMd}>
              <Download className="mr-1.5 h-3.5 w-3.5" /> Markdown
            </Button>
          </div>
        </div>
      </div>
      <section className="grid gap-4 lg:grid-cols-[280px_1fr]">
        <RiskGauge report={report} />
        <div className="space-y-4">
          <Card className="border-border/60">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm text-muted-foreground">Executive summary</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm leading-relaxed">{report.executive_summary}</p>
            </CardContent>
          </Card>
          <div
            className="grid grid-cols-5 gap-2"
            role="group"
            aria-label="Filter findings by severity"
          >
            {SEV_ORDER.map((s) => {
              const count = report.aggregate.counts[s] ?? 0;
              const active = filter === s;
              return (
                <button
                  key={s}
                  onClick={() => setFilter(active ? "ALL" : s)}
                  aria-pressed={active}
                  aria-label={`${count} ${s.toLowerCase()} findings${active ? ", filter active" : ""}`}
                  className={`rounded-md border p-3 text-center transition ${active ? "border-primary/60 bg-primary/10" : "border-border/60 bg-card/40 hover:border-border"}`}
                >
                  <div
                    className={`text-xl font-semibold tabular-nums ${count > 0 ? "text-foreground" : "text-muted-foreground/50"}`}
                  >
                    {count}
                  </div>
                  <div className="mt-0.5 text-[10px] uppercase tracking-wider text-muted-foreground">
                    {s}
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      </section>
      <Tabs defaultValue="findings">
        <TabsList>
          <TabsTrigger value="findings">Findings ({report.findings.length})</TabsTrigger>
          <TabsTrigger value="coverage">Coverage</TabsTrigger>
          <TabsTrigger value="metadata">Metadata</TabsTrigger>
        </TabsList>
        <TabsContent value="findings" className="space-y-6">
          {filter !== "ALL" && (
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              Filtered to <Badge className={severityBadgeClass(filter)}>{filter}</Badge>
              <button onClick={() => setFilter("ALL")} className="text-primary hover:underline">
                clear
              </button>
            </div>
          )}
          {shown.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <ShieldCheck className="mx-auto mb-2 h-8 w-8 text-primary" />
                <div className="text-sm">No findings match this filter.</div>
                {report.findings.length === 0 && (
                  <div className="mt-1 text-xs text-muted-foreground">
                    Nothing detected — remember, coverage depends on what you submitted.
                  </div>
                )}
              </CardContent>
            </Card>
          ) : (
            SEV_ORDER.map((sev) =>
              grouped[sev].length ? (
                <FindingsGroup
                  key={sev}
                  severity={sev}
                  findings={grouped[sev]}
                  edits={edits}
                  setEdits={setEdits}
                  mode={mode}
                />
              ) : null,
            )
          )}
        </TabsContent>
        <TabsContent value="coverage">
          <CoverageTable report={report} />
        </TabsContent>
        <TabsContent value="metadata">
          <MetadataView report={report} clientName={clientName} setClientName={setClientName} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function RiskGauge({ report }: { report: ScanReport }) {
  const highest = report.aggregate.highest;
  const colorMap: Record<Severity, string> = {
    CRITICAL: "var(--sev-critical)",
    HIGH: "var(--sev-high)",
    MEDIUM: "var(--sev-medium)",
    LOW: "var(--sev-low)",
    INFO: "var(--sev-info)",
  };
  const stroke = colorMap[highest];
  const circumference = 2 * Math.PI * 46;
  // Use actual per-finding scores from the model rather than a bucketed constant.
  // Average across all findings; if none, show 5 as a baseline.
  const score =
    report.findings.length === 0
      ? 5
      : Math.round(report.findings.reduce((sum, f) => sum + f.score, 0) / report.findings.length);
  const offset = circumference * (1 - score / 100);
  return (
    <Card
      className={`relative overflow-hidden border-border/60 ${highest === "CRITICAL" ? "glow-critical" : ""}`}
    >
      <CardContent className="flex flex-col items-center gap-3 py-6">
        <div className="relative h-40 w-40">
          <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
            <circle
              cx="50"
              cy="50"
              r="46"
              fill="none"
              stroke="oklch(1 0 0 / 0.06)"
              strokeWidth="6"
            />
            <circle
              cx="50"
              cy="50"
              r="46"
              fill="none"
              stroke={stroke}
              strokeWidth="6"
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={offset}
              style={{ transition: "stroke-dashoffset 800ms ease-out" }}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <div className="text-4xl font-semibold tabular-nums">{score}</div>
            <div className="text-[10px] uppercase tracking-widest text-muted-foreground">
              risk score
            </div>
          </div>
        </div>
        <Badge className={`${severityBadgeClass(highest)} px-3 py-1 text-xs`}>{highest}</Badge>
        <div className="text-center text-xs text-muted-foreground">
          {report.findings.length} finding{report.findings.length === 1 ? "" : "s"} across{" "}
          {new Set(report.findings.map((f) => f.category)).size} categories
        </div>
      </CardContent>
    </Card>
  );
}

function FindingsGroup({
  severity,
  findings,
  edits,
  setEdits,
  mode,
}: {
  severity: Severity;
  findings: ScanReport["findings"];
  edits: Record<string, ReviewerEdit>;
  setEdits: (v: Record<string, ReviewerEdit>) => void;
  mode: "security" | "plain";
}) {
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 pt-2">
        <Badge className={severityBadgeClass(severity)}>{severity}</Badge>
        <span className="text-xs text-muted-foreground">
          {findings.length} finding{findings.length === 1 ? "" : "s"}
        </span>
        <div className="ml-2 h-px flex-1 bg-border/60" />
      </div>
      {findings.map((f) => (
        <FindingCard
          key={f.id}
          f={f}
          edit={edits[f.id]}
          onChange={(e) => setEdits({ ...edits, [f.id]: e })}
          mode={mode}
        />
      ))}
    </div>
  );
}

function FindingCard({
  f,
  edit,
  onChange,
  mode,
}: {
  f: ScanReport["findings"][number];
  edit?: ReviewerEdit;
  onChange: (e: ReviewerEdit) => void;
  mode: "security" | "plain";
}) {
  const [open, setOpen] = useState(f.severity === "CRITICAL" || f.severity === "HIGH");
  const effectiveSev = edit?.severity ?? f.severity;
  const dismissed = !!edit?.dismissed;
  const overridden = edit?.severity && edit.severity !== f.severity;
  async function copyEvidence() {
    await navigator.clipboard.writeText(f.evidence);
    toast.success("Evidence copied");
  }
  return (
    <Card
      className={`overflow-hidden border-border/60 transition ${dismissed ? "opacity-50" : "hover:border-border"} ${effectiveSev === "CRITICAL" && !dismissed ? "border-l-4 border-l-sev-critical" : ""}`}
    >
      <button
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        aria-controls={`finding-body-${f.id}`}
        aria-label={`${open ? "Collapse" : "Expand"} finding: ${f.title}`}
        className="flex w-full items-start justify-between gap-3 px-4 py-3 text-left transition hover:bg-muted/20"
      >
        <div className="flex-1 space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <Badge className={severityBadgeClass(effectiveSev)}>{effectiveSev}</Badge>
            {overridden && <span className="text-[10px] text-accent">↳ from {f.severity}</span>}
            <Badge variant="outline" className="font-mono text-[10px]">
              {f.category}
            </Badge>
            <span className="text-[11px] text-muted-foreground">{f.category_name}</span>
            <span className="ml-auto font-mono text-[10px] text-muted-foreground">
              score {f.score}
            </span>
          </div>
          <div className="text-sm font-medium">{f.title}</div>
        </div>
        <ChevronDown
          aria-hidden="true"
          className={`mt-1 h-4 w-4 shrink-0 text-muted-foreground transition ${open ? "rotate-180" : ""}`}
        />
      </button>
      {open && (
        <div
          id={`finding-body-${f.id}`}
          role="region"
          aria-label={`Details for ${f.title}`}
          className="space-y-4 border-t border-border/60 px-4 py-4 text-sm"
        >
          <p>{mode === "plain" ? f.description_plain : f.description_security}</p>
          <div>
            <div className="mb-1.5 flex items-center justify-between">
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
                Evidence · <span className="font-mono">{f.evidence_location}</span>
              </div>
              <button
                onClick={copyEvidence}
                aria-label="Copy evidence to clipboard"
                className="rounded text-[11px] text-muted-foreground hover:text-primary"
              >
                <Copy aria-hidden="true" className="mr-1 inline h-3 w-3" /> copy
              </button>
            </div>
            <pre className="max-h-48 overflow-auto rounded-md border border-border/60 bg-background/60 p-3 text-xs">
              {f.evidence}
            </pre>
          </div>
          <div>
            <div className="mb-1 text-[10px] uppercase tracking-wider text-muted-foreground">
              Remediation
            </div>
            <p className="text-sm">{f.remediation}</p>
          </div>
          <div className="flex flex-wrap items-center gap-2 border-t border-border/40 pt-3">
            <span className="text-[11px] text-muted-foreground">Reviewer override:</span>
            <Select
              value={effectiveSev}
              onValueChange={(v) =>
                onChange({ ...(edit ?? { note: "" }), severity: v as Severity })
              }
            >
              <SelectTrigger className="h-7 w-28 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {SEV_ORDER.map((s) => (
                  <SelectItem key={s} value={s}>
                    {s}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button
              size="sm"
              variant={dismissed ? "secondary" : "ghost"}
              onClick={() => onChange({ ...(edit ?? { note: "" }), dismissed: !dismissed })}
            >
              {dismissed ? (
                "Restore"
              ) : (
                <>
                  <X className="mr-1 h-3.5 w-3.5" /> Dismiss
                </>
              )}
            </Button>
            {(overridden || dismissed) && (
              <Input
                value={edit?.note ?? ""}
                onChange={(e) => onChange({ ...(edit ?? {}), note: e.target.value })}
                placeholder="Justification (required)"
                className="h-7 flex-1 text-xs"
              />
            )}
          </div>
        </div>
      )}
    </Card>
  );
}

function CoverageTable({ report }: { report: ScanReport }) {
  return (
    <Card className="border-border/60">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <FileWarning className="h-4 w-4 text-accent" />
          OWASP LLM Top 10 (2025) — coverage map
        </CardTitle>
        <CardDescription>
          "Insufficient Input" means the artifact needed to check this category wasn't provided.
        </CardDescription>
      </CardHeader>
      <CardContent className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="text-left text-xs uppercase tracking-wider text-muted-foreground">
            <tr>
              <th className="pb-2">Code</th>
              <th className="pb-2">Category</th>
              <th className="pb-2">Status</th>
              <th className="pb-2">Note</th>
            </tr>
          </thead>
          <tbody>
            {report.coverage.map((c) => (
              <tr key={c.code} className="border-t border-border/40">
                <td className="py-2 font-mono text-primary">{c.code}</td>
                <td className="py-2">{c.name}</td>
                <td className="py-2">
                  <Badge
                    variant="outline"
                    className={
                      c.status === "Assessed"
                        ? "border-primary/50 text-primary"
                        : c.status === "Insufficient Input"
                          ? "border-accent/60 text-accent"
                          : "border-border text-muted-foreground"
                    }
                  >
                    {c.status}
                  </Badge>
                </td>
                <td className="py-2 text-xs text-muted-foreground">{c.note}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </CardContent>
    </Card>
  );
}

function MetadataView({
  report,
  clientName,
  setClientName,
}: {
  report: ScanReport;
  clientName: string;
  setClientName: (v: string) => void;
}) {
  const hashRef = useRef<HTMLDivElement>(null);
  return (
    <Card className="border-border/60">
      <CardHeader>
        <CardTitle className="text-base">Scan metadata</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4 text-sm">
        <div className="grid grid-cols-[140px_1fr] gap-y-2 font-mono text-xs">
          <div className="text-muted-foreground">Scan ID</div>
          <div>{report.scan_id}</div>
          <div className="text-muted-foreground">Timestamp</div>
          <div>{report.timestamp}</div>
          <div className="text-muted-foreground">SHA-256</div>
          <div ref={hashRef} className="break-all">
            {report.artifact_hash}
          </div>
          <div className="text-muted-foreground">Ruleset</div>
          <div>{report.ruleset_version}</div>
          <div className="text-muted-foreground">Inputs</div>
          <div>{report.inputs_provided.join(", ")}</div>
        </div>
        <div className="space-y-2 border-t border-border/40 pt-4">
          <Label htmlFor="client" className="text-xs">
            Client / target name (appears on Markdown export cover)
          </Label>
          <Input
            id="client"
            value={clientName}
            onChange={(e) => setClientName(e.target.value)}
            placeholder="Acme Bank — Copilot review"
          />
        </div>
        <p className="flex items-start gap-2 rounded-md border border-border/60 bg-muted/20 p-3 text-xs text-muted-foreground">
          <Info className="mt-0.5 h-3.5 w-3.5 shrink-0 text-primary" />
          Only the SHA-256 hash of your submission is included in this metadata. Raw artifact
          content is never persisted or logged.
        </p>
      </CardContent>
    </Card>
  );
}
