"use client";

import { useEffect, useState } from "react";
import { API_BASE, ForensicReport, formatApiError } from "../types/forensic";

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
  { id: "mime", label: "RFC 5322 MIME Structure Parsing", detail: "Deconstructing multipart boundaries, character sets, and nested attachments..." },
  { id: "hops", label: "Trace Hop & Latency Reconstruction", detail: "Validating Received: headers, ASN lookups, and reverse DNS mapping..." },
  { id: "auth", label: "Cryptographic Auth Protocol Verification", detail: "Evaluating SPF policy, DKIM canonicalization, DMARC alignment & ARC seal..." },
  { id: "payload", label: "Payload & Attachment Triage", detail: "Computing SHA-256 hashes, magic byte validation, and heuristic triage..." },
  { id: "threat", label: "URL Extraction & Intent Scoring", detail: "Detecting hidden text, href mismatches, and composite risk..." },
  { id: "synthesis", label: "Custody Ledger & Report Synthesis", detail: "Anchoring chain-of-custody hashes and assembling MasterForensicReport..." },
];

export function ForensicScannerModal({
  isOpen = true,
  onClose,
  file,
  onComplete,
  onError,
}: ForensicScannerModalProps) {
  const [currentStepIndex, setCurrentStepIndex] = useState(0);
  const [progress, setProgress] = useState(8);
  const [diagnosticLogs, setDiagnosticLogs] = useState<string[]>([]);
  const [failure, setFailure] = useState<string | null>(null);

  const addLog = (msg: string) => {
    const timestamp = new Date().toISOString().substring(11, 19);
    setDiagnosticLogs((prev) => [...prev.slice(-40), `[${timestamp}] ${msg}`]);
  };

  useEffect(() => {
    if (!isOpen) return;

    let isMounted = true;
    const abortController = new AbortController();
    const runPipeline = async () => {
      try {
        setFailure(null);
        addLog(`Target File: ${file?.name || "unnamed evidence"}`);
        addLog(`POST ${API_BASE}/api/analyze`);

        for (let i = 0; i < SCAN_STEPS.length; i++) {
          if (!isMounted) return;
          setCurrentStepIndex(i);
          addLog(`Executing: ${SCAN_STEPS[i].label}`);
          setProgress(Math.round(((i + 1) / (SCAN_STEPS.length + 1)) * 100));
          await new Promise((r) => setTimeout(r, 350));
        }

        if (!file) {
          throw new Error("No evidence file selected.");
        }

        const formData = new FormData();
        formData.append("file", file);

        addLog("Sending evidence to FastAPI /api/analyze...");

        const response = await fetch(`${API_BASE}/api/analyze`, {
          method: "POST",
          body: formData,
          signal: abortController.signal,
        });

        let payload: unknown = null;
        try {
          payload = await response.json();
        } catch {
          throw new Error(`API returned a non-JSON response (${response.status})`);
        }

        if (!response.ok) {
          throw new Error(formatApiError(payload, response.status));
        }

        addLog("MasterForensicReport received from FastAPI.");
        setProgress(100);

        if (onComplete) {
          setTimeout(() => {
            if (isMounted) onComplete(payload as ForensicReport);
          }, 400);
        }
      } catch (err: unknown) {
        if (err instanceof DOMException && err.name === "AbortError") return;
        const message =
          err instanceof Error ? err.message : "Could not connect to the analysis server.";
        addLog(`ERROR: ${message}`);
        setFailure(message);
        onError?.(message);
      }
    };

    runPipeline();
    return () => {
      isMounted = false;
      abortController.abort();
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
          <span className="text-slate-400">
            {failure ? "FAILED" : `Scanning ${progress}%`}
          </span>
        </div>

        <div className="p-5 space-y-3">
          <div className="text-slate-400">
            Target File: <span className="text-slate-200">{file?.name || "no file selected"}</span>
          </div>
          <div className="text-slate-500">
            Step: <span className="text-slate-300">{SCAN_STEPS[currentStepIndex]?.label}</span>
          </div>

          <div className="p-3 bg-slate-950 rounded border border-slate-800/80 max-h-48 overflow-y-auto space-y-1 text-[11px] text-slate-300">
            {diagnosticLogs.map((log, i) => (
              <div key={i}>{log}</div>
            ))}
          </div>

          {failure && (
            <div className="p-3 rounded border border-rose-800/60 bg-rose-950/40 text-rose-200 text-[11px]">
              {failure}
            </div>
          )}

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
