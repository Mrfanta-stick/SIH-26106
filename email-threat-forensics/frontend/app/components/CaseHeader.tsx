"use client";

import { useState } from "react";
import { ForensicReport } from "../types/forensic";

export interface CaseHeaderProps {
  report?: ForensicReport | null;
  caseId?: string;
  timestamp?: string;
  classification?: string;
  onOpenDossier?: () => void;
  onExportReport?: () => void;
  onReset?: () => void;
}

export function CaseHeader(props: CaseHeaderProps) {
  const {
    report,
    caseId = report?.case_id || "NO CASE LOADED",
    timestamp = report?.evidence?.ingestion_timestamp || "—",
    classification = report?.evidence?.filename || "CONFIDENTIAL // TLP:AMBER",
    onOpenDossier,
    onExportReport,
    onReset,
  } = props;

  const [copied, setCopied] = useState(false);

  const handleCopyId = () => {
    navigator.clipboard.writeText(caseId);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <header className="w-full bg-slate-900/80 border-b border-slate-800 backdrop-blur-md sticky top-0 z-40 px-6 py-3.5">
      <div className="max-w-7xl mx-auto flex flex-col sm:flex-row sm:items-center justify-between gap-4 font-mono">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-cyan-950/60 border border-cyan-500/30 text-cyan-400">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400">INCIDENT ID:</span>
              <span className="text-sm font-bold text-slate-100">{caseId}</span>
              <button
                type="button"
                onClick={handleCopyId}
                aria-label="Copy Case ID"
                className="text-slate-400 hover:text-cyan-400 p-1"
              >
                {copied ? <span className="text-[10px] text-emerald-400">COPIED</span> : "📋"}
              </button>
            </div>
            <div className="text-[11px] text-slate-500 flex items-center gap-3">
              <span suppressHydrationWarning>{timestamp}</span>
              <span>|</span>
              <span className="text-amber-400 truncate max-w-[280px]">{classification}</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs">
          {onOpenDossier && (
            <button
              type="button"
              onClick={onOpenDossier}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded transition-colors"
            >
              DOSSIER
            </button>
          )}
          {onExportReport && (
            <button
              type="button"
              onClick={onExportReport}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded transition-colors"
            >
              EXPORT
            </button>
          )}
          {onReset && (
            <button
              type="button"
              onClick={onReset}
              className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-400 rounded border border-slate-700 transition-colors"
            >
              🔄
            </button>
          )}
        </div>
      </div>
    </header>
  );
}

export default CaseHeader;
