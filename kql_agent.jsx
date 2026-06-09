import { useState, useRef, useEffect } from "react";

const SYSTEM_PROMPT = `You are an expert Microsoft Sentinel SOC analyst and KQL (Kusto Query Language) specialist. Your job is to convert natural language security investigation requests into optimized, production-ready KQL queries for Microsoft Sentinel.

Available tables: SigninLogs, SecurityEvent, DeviceEvents, DeviceProcessEvents, DeviceNetworkEvents, CommonSecurityLog, AuditLogs, OfficeActivity, IdentityInfo

Rules for every response — you MUST return ONLY valid JSON, no markdown fences, no extra text:
{
  "kql": "<the complete KQL query>",
  "explanation": "<plain-English explanation of what the query does, 2-4 sentences>",
  "optimizations": ["<optimization note 1>", "<optimization note 2>"],
  "mitre": { "tactic": "<MITRE ATT&CK tactic>", "technique": "<technique ID and name>" },
  "alternatives": ["<alternative hunting query description 1>", "<alternative hunting query description 2>"],
  "severity": "low|medium|high|critical",
  "tables": ["<table1>", "<table2>"]
}

KQL best practices to always follow:
- Apply time filters first (where TimeGenerated > ago(Xh/d))
- Use project to select only needed columns
- Use summarize before where for aggregations
- Prefer has over contains for string matching
- Use let for reusable variables
- Add // comments for complex logic
- Always order results meaningfully

MITRE ATT&CK mappings for common scenarios:
- Failed logins → Initial Access / T1078 Valid Accounts
- Brute force → Credential Access / T1110 Brute Force
- PowerShell → Execution / T1059.001 PowerShell
- Lateral movement → Lateral Movement / T1021
- Data exfiltration → Exfiltration / T1041
- Privilege escalation → Privilege Escalation / T1078.003
- Ransomware → Impact / T1486 Data Encrypted for Impact
- Insider threat → Collection / T1074

Respond ONLY with the JSON object.`;

const EXAMPLE_QUERIES = [
  "Show failed login attempts from the last 24 hours",
  "Find PowerShell executions on endpoints in the last 7 days",
  "List users with more than 10 failed authentication attempts",
  "Detect brute force attacks against Azure AD accounts",
  "Find suspicious network connections to rare external IPs",
  "Show privilege escalation events in the last 48 hours",
  "Detect potential ransomware file activity",
  "Find lateral movement via RDP in the last week",
];

const SEVERITY_CONFIG = {
  low: { color: "#3B6D11", bg: "#EAF3DE", label: "Low" },
  medium: { color: "#854F0B", bg: "#FAEEDA", label: "Medium" },
  high: { color: "#993C1D", bg: "#FAECE7", label: "High" },
  critical: { color: "#A32D2D", bg: "#FCEBEB", label: "Critical" },
};

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  return (
    <button onClick={copy} style={{ background: "none", border: "0.5px solid var(--color-border-secondary)", borderRadius: 6, padding: "4px 10px", cursor: "pointer", fontSize: 12, color: "var(--color-text-secondary)", display: "flex", alignItems: "center", gap: 4 }}>
      <i className={`ti ${copied ? "ti-check" : "ti-copy"}`} style={{ fontSize: 13 }} aria-hidden="true" />
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

function KQLBlock({ kql }) {
  return (
    <div style={{ background: "var(--color-background-secondary)", border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", overflow: "hidden", marginBottom: 12 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 12px", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
        <span style={{ fontSize: 12, color: "var(--color-text-secondary)", fontFamily: "var(--font-mono)" }}>KQL Query</span>
        <CopyButton text={kql} />
      </div>
      <pre style={{ margin: 0, padding: "12px 14px", fontFamily: "var(--font-mono)", fontSize: 13, lineHeight: 1.6, overflowX: "auto", color: "var(--color-text-primary)", whiteSpace: "pre-wrap", wordBreak: "break-word" }}>{kql}</pre>
    </div>
  );
}

function ResultCard({ result }) {
  const sev = SEVERITY_CONFIG[result.severity] || SEVERITY_CONFIG.medium;
  return (
    <div style={{ border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-lg)", overflow: "hidden", marginTop: 12 }}>
      <div style={{ padding: "10px 14px", borderBottom: "0.5px solid var(--color-border-tertiary)", display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <span style={{ fontSize: 12, fontWeight: 500, padding: "3px 10px", borderRadius: 20, background: sev.bg, color: sev.color }}>{sev.label} severity</span>
        {result.mitre && (
          <span style={{ fontSize: 12, padding: "3px 10px", borderRadius: 20, background: "var(--color-background-info)", color: "var(--color-text-info)", border: "0.5px solid var(--color-border-info)" }}>
            {result.mitre.tactic} · {result.mitre.technique}
          </span>
        )}
        {result.tables?.map(t => (
          <span key={t} style={{ fontSize: 11, padding: "2px 8px", borderRadius: 20, background: "var(--color-background-secondary)", color: "var(--color-text-secondary)", border: "0.5px solid var(--color-border-tertiary)" }}>{t}</span>
        ))}
      </div>
      <div style={{ padding: "14px" }}>
        <KQLBlock kql={result.kql} />
        <p style={{ fontSize: 14, lineHeight: 1.7, color: "var(--color-text-secondary)", margin: "0 0 14px" }}>{result.explanation}</p>
        {result.optimizations?.length > 0 && (
          <div style={{ marginBottom: 14 }}>
            <p style={{ fontSize: 12, fontWeight: 500, color: "var(--color-text-secondary)", margin: "0 0 6px", textTransform: "uppercase", letterSpacing: "0.05em" }}>Optimizations applied</p>
            <ul style={{ margin: 0, padding: "0 0 0 16px" }}>
              {result.optimizations.map((o, i) => (
                <li key={i} style={{ fontSize: 13, color: "var(--color-text-secondary)", marginBottom: 3, lineHeight: 1.5 }}>{o}</li>
              ))}
            </ul>
          </div>
        )}
        {result.alternatives?.length > 0 && (
          <div>
            <p style={{ fontSize: 12, fontWeight: 500, color: "var(--color-text-secondary)", margin: "0 0 6px", textTransform: "uppercase", letterSpacing: "0.05em" }}>Alternative hunting queries</p>
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {result.alternatives.map((a, i) => (
                <div key={i} style={{ display: "flex", gap: 8, alignItems: "flex-start", padding: "8px 10px", background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", cursor: "pointer" }}
                  onClick={() => window.sendPromptFn && window.sendPromptFn(a)}>
                  <i className="ti ti-bulb" style={{ fontSize: 14, color: "var(--color-text-secondary)", marginTop: 1, flexShrink: 0 }} aria-hidden="true" />
                  <span style={{ fontSize: 13, color: "var(--color-text-secondary)", lineHeight: 1.5 }}>{a}</span>
                  <i className="ti ti-arrow-right" style={{ fontSize: 13, color: "var(--color-text-secondary)", marginTop: 1, flexShrink: 0, marginLeft: "auto" }} aria-hidden="true" />
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function Message({ msg }) {
  if (msg.role === "user") {
    return (
      <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 16 }}>
        <div style={{ maxWidth: "80%", background: "var(--color-background-info)", border: "0.5px solid var(--color-border-info)", borderRadius: "var(--border-radius-lg)", padding: "10px 14px", fontSize: 14, lineHeight: 1.6, color: "var(--color-text-info)" }}>
          {msg.content}
        </div>
      </div>
    );
  }
  if (msg.role === "error") {
    return (
      <div style={{ marginBottom: 16, padding: "10px 14px", background: "var(--color-background-danger)", border: "0.5px solid var(--color-border-danger)", borderRadius: "var(--border-radius-md)", fontSize: 14, color: "var(--color-text-danger)" }}>
        <i className="ti ti-alert-circle" style={{ marginRight: 6 }} aria-hidden="true" />
        {msg.content}
      </div>
    );
  }
  return (
    <div style={{ marginBottom: 20 }}>
      <div style={{ display: "flex", gap: 8, marginBottom: 6, alignItems: "center" }}>
        <div style={{ width: 24, height: 24, borderRadius: "50%", background: "var(--color-background-secondary)", border: "0.5px solid var(--color-border-secondary)", display: "flex", alignItems: "center", justifyContent: "center" }}>
          <i className="ti ti-shield-check" style={{ fontSize: 13, color: "var(--color-text-secondary)" }} aria-hidden="true" />
        </div>
        <span style={{ fontSize: 12, color: "var(--color-text-secondary)" }}>KQL Agent</span>
      </div>
      {msg.loading ? (
        <div style={{ display: "flex", gap: 5, padding: "10px 0" }}>
          {[0,1,2].map(i => (
            <div key={i} style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--color-text-secondary)", animation: `pulse 1.2s ease-in-out ${i * 0.2}s infinite` }} />
          ))}
        </div>
      ) : msg.result ? (
        <ResultCard result={msg.result} />
      ) : (
        <div style={{ fontSize: 14, lineHeight: 1.7, color: "var(--color-text-secondary)" }}>{msg.content}</div>
      )}
    </div>
  );
}

export default function KQLAgent() {
  const [messages, setMessages] = useState([
    {
      role: "assistant",
      content: "Hello! I'm your KQL Query Generator for Microsoft Sentinel. Describe any security investigation scenario in plain English and I'll generate an optimized KQL query with MITRE ATT&CK mapping and performance notes."
    }
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState([]);
  const bottomRef = useRef(null);
  const textareaRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  window.sendPromptFn = (text) => {
    setInput(text);
    setTimeout(() => textareaRef.current?.focus(), 100);
  };

  const sendQuery = async (queryText) => {
    const q = queryText || input.trim();
    if (!q || loading) return;
    setInput("");

    const userMsg = { role: "user", content: q };
    const loadingMsg = { role: "assistant", loading: true };
    setMessages(prev => [...prev, userMsg, loadingMsg]);
    setLoading(true);

    const newHistory = [...history, { role: "user", content: q }];

    try {
      const resp = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 1000,
          system: SYSTEM_PROMPT,
          messages: newHistory
        })
      });
      const data = await resp.json();
      const raw = data.content?.map(b => b.text || "").join("") || "";
      const clean = raw.replace(/```json|```/g, "").trim();
      let result;
      try {
        result = JSON.parse(clean);
      } catch {
        throw new Error("Could not parse response. Please try again.");
      }

      const assistantReply = { role: "assistant", content: raw };
      setHistory([...newHistory, assistantReply]);

      setMessages(prev => {
        const next = [...prev];
        next[next.length - 1] = { role: "assistant", result };
        return next;
      });
    } catch (err) {
      setMessages(prev => {
        const next = [...prev];
        next[next.length - 1] = { role: "error", content: err.message || "Something went wrong." };
        return next;
      });
    } finally {
      setLoading(false);
    }
  };

  const handleKey = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendQuery();
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100vh", maxHeight: 700, fontFamily: "var(--font-sans)" }}>
      <style>{`
        @keyframes pulse { 0%,100%{opacity:0.3;transform:scale(0.8)} 50%{opacity:1;transform:scale(1)} }
        ::-webkit-scrollbar{width:4px} ::-webkit-scrollbar-track{background:transparent} ::-webkit-scrollbar-thumb{background:var(--color-border-secondary);border-radius:2px}
      `}</style>

      <div style={{ padding: "12px 16px", borderBottom: "0.5px solid var(--color-border-tertiary)", display: "flex", alignItems: "center", gap: 10 }}>
        <div style={{ width: 32, height: 32, borderRadius: "var(--border-radius-md)", background: "var(--color-background-secondary)", border: "0.5px solid var(--color-border-secondary)", display: "flex", alignItems: "center", justifyContent: "center" }}>
          <i className="ti ti-terminal-2" style={{ fontSize: 16, color: "var(--color-text-secondary)" }} aria-hidden="true" />
        </div>
        <div>
          <p style={{ margin: 0, fontWeight: 500, fontSize: 14, color: "var(--color-text-primary)" }}>KQL Query Generator</p>
          <p style={{ margin: 0, fontSize: 12, color: "var(--color-text-secondary)" }}>Microsoft Sentinel · AI-powered SOC assistant</p>
        </div>
        <div style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
          {["SigninLogs", "SecurityEvent", "DeviceEvents"].map(t => (
            <span key={t} style={{ fontSize: 10, padding: "2px 7px", background: "var(--color-background-secondary)", color: "var(--color-text-secondary)", borderRadius: 10, border: "0.5px solid var(--color-border-tertiary)" }}>{t}</span>
          ))}
          <span style={{ fontSize: 10, padding: "2px 7px", background: "var(--color-background-secondary)", color: "var(--color-text-secondary)", borderRadius: 10, border: "0.5px solid var(--color-border-tertiary)" }}>+5 more</span>
        </div>
      </div>

      <div style={{ flex: 1, overflowY: "auto", padding: "16px" }}>
        {messages.map((msg, i) => <Message key={i} msg={msg} />)}
        <div ref={bottomRef} />
      </div>

      {messages.length <= 1 && (
        <div style={{ padding: "0 16px 12px" }}>
          <p style={{ fontSize: 12, color: "var(--color-text-secondary)", margin: "0 0 8px" }}>Try an example</p>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {EXAMPLE_QUERIES.slice(0, 4).map((q, i) => (
              <button key={i} onClick={() => sendQuery(q)} style={{ fontSize: 12, padding: "5px 10px", background: "var(--color-background-secondary)", border: "0.5px solid var(--color-border-secondary)", borderRadius: "var(--border-radius-md)", cursor: "pointer", color: "var(--color-text-secondary)", textAlign: "left", lineHeight: 1.4 }}>
                {q}
              </button>
            ))}
          </div>
        </div>
      )}

      <div style={{ padding: "10px 16px 14px", borderTop: "0.5px solid var(--color-border-tertiary)" }}>
        <div style={{ display: "flex", gap: 8, alignItems: "flex-end", background: "var(--color-background-secondary)", border: "0.5px solid var(--color-border-secondary)", borderRadius: "var(--border-radius-lg)", padding: "8px 10px" }}>
          <textarea
            ref={textareaRef}
            value={input}
            onChange={e => { setInput(e.target.value); e.target.style.height = "auto"; e.target.style.height = Math.min(e.target.scrollHeight, 120) + "px"; }}
            onKeyDown={handleKey}
            placeholder="Describe a security investigation scenario…"
            rows={1}
            style={{ flex: 1, border: "none", background: "transparent", resize: "none", fontSize: 14, lineHeight: 1.6, color: "var(--color-text-primary)", outline: "none", fontFamily: "var(--font-sans)", overflowY: "hidden" }}
          />
          <button onClick={() => sendQuery()} disabled={loading || !input.trim()} style={{ width: 32, height: 32, borderRadius: "var(--border-radius-md)", background: input.trim() && !loading ? "var(--color-text-primary)" : "var(--color-background-secondary)", border: "0.5px solid var(--color-border-secondary)", cursor: input.trim() && !loading ? "pointer" : "default", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, transition: "background 0.15s" }}>
            <i className="ti ti-arrow-up" style={{ fontSize: 15, color: input.trim() && !loading ? "var(--color-background-primary)" : "var(--color-text-secondary)" }} aria-hidden="true" />
          </button>
        </div>
        <p style={{ margin: "6px 0 0", fontSize: 11, color: "var(--color-text-secondary)", textAlign: "center" }}>Shift+Enter for new line · Enter to send</p>
      </div>
    </div>
  );
}
