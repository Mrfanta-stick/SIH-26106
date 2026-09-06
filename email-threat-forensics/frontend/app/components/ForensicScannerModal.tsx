// @ts-nocheck
"use client";

import { useEffect, useState } from "react";
import { ForensicReport } from "../types/forensic";

export interface ForensicScannerModalProps {
  isOpen?: boolean;
  onClose?: () => void;
  file?: File | null;
  rawInput?: string;
  sourceType?: "eml" | "pcap" | "domain";
  onComplete?: (report: ForensicReport) => void;
  onError?: (message: string) => void;
}

const SCAN_STEPS = [
  { id: "mime", label: "RFC 5322 MIME Structure Parsing", detail: "Deconstructing multipart boundaries, character sets, and nested attachments...", durationMs: 1200 },
  { id: "hops", label: "Trace Hop & Latency Reconstruction", detail: "Validating Received: headers, ASN lookups, and reverse DNS mapping...", durationMs: 1400 },
  { id: "auth", label: "Cryptographic Auth Protocol Verification", detail: "Evaluating SPF policy, DKIM canonicalization, DMARC alignment & ARC seal...", durationMs: 1600 },
  { id: "payload", label: "Payload & Attachment Triage", detail: "Computing SHA-256 hashes, magic byte validation, and heuristic triage...", durationMs: 1500 },
  { id: "threat", label: "Threat Actor & TTP Mapping", detail: "Correlating IoCs against MITRE ATT&CK enterprise techniques...", durationMs: 1800 },
  { id: "synthesis", label: "Forensic Synthesis & Verdict Engine", detail: "Aggregating risk vectors and generating structured evidence package...", durationMs: 1500 },
];

export function ForensicScannerModal({
  isOpen = true,
  onClose,
  file,
  rawInput = "",
  sourceType = "eml",
  onComplete,
  onError,
}: ForensicScannerModalProps) {
  const [state, setState] = useState("checking");
  const [currentStepIndex, setCurrentStepIndex] = useState(0);
  const [completedSteps, setCompletedSteps] = useState<string[]>([]);
  const [progress, setProgress] = useState(10);
  const [diagnosticLogs, setDiagnosticLogs] = useState<string[]>([]);

  const addLog = (msg: string) => {
    const timestamp = new Date().toISOString().substring(11, 19);
    setDiagnosticLogs((prev) => [...prev.slice(-40), `[${timestamp}] ${msg}`]);
  };

  useEffect(() => {
    if (!isOpen) return;

    let isMounted = true;
    const runPipeline = async () => {
  try {
    setState("analyzing");
    addLog(`Target File: ${file?.name || "suspicious_invoice.eml"}`);
    addLog("Initializing forensic reconstruction stream...");

    for (let i = 0; i < SCAN_STEPS.length; i++) {
      if (!isMounted) return;

      setCurrentStepIndex(i);
      addLog(`Executing: ${SCAN_STEPS[i].label}`);
      setProgress(Math.round(((i + 1) / SCAN_STEPS.length) * 100));

      await new Promise((r) => setTimeout(r, 600));

      setCompletedSteps((prev) => [...prev, SCAN_STEPS[i].id]);
    }

    if (!file) {
      throw new Error("No evidence file selected.");
    }

    const formData = new FormData();
    formData.append("file", file);

    addLog("Sending evidence to FastAPI...");

    const apiBase =
      process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

    const response = await fetch(`${apiBase}/api/analyze`, {
      method: "POST",
      body: formData,
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(
        data?.detail || `API request failed (${response.status})`
      );
    }

    addLog("Forensic report received from FastAPI.");

    setState("complete");
    addLog("Forensic pipeline completed. Loading report view...");

    if (onComplete) {
      setTimeout(() => {
        if (isMounted) {
          onComplete(data as ForensicReport);
        }
      }, 500);
    }
  } catch (err: any) {
    if (onError) {
      onError(err?.message || "Execution failure");
    }
  }
};

    runPipeline();
    return () => {
      isMounted = false;
    };
  }, [isOpen, file]);

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
    >
      <div className="relative w-full max-w-xl bg-slate-900 border border-cyan-500/40 rounded-xl shadow-2xl overflow-hidden font-mono text-xs">
        <div className="px-5 py-3 border-b border-slate-800 flex items-center justify-between bg-slate-950/50">
          <span className="text-cyan-400 font-bold flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-cyan-400 animate-ping" />
            LIVE FORENSIC RECONSTRUCTION STREAM
          </span>
          <span className="text-slate-400">Scanning {progress}%</span>
        </div>

        <div className="p-5 space-y-3">
          <div className="text-slate-400">
            Target File: <span className="text-slate-200">{file?.name || "suspicious_invoice.eml"}</span>
          </div>

          <div className="p-3 bg-slate-950 rounded border border-slate-800/80 max-h-48 overflow-y-auto space-y-1 text-[11px] text-slate-300">
            {diagnosticLogs.map((log, i) => (
              <div key={i}>{log}</div>
            ))}
          </div>

          <div className="pt-2 flex justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default ForensicScannerModal;