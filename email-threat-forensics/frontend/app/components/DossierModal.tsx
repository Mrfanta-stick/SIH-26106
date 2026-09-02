// @ts-nocheck
"use client";

import { useEffect } from "react";
import { ForensicReport } from "../types/forensic";

export interface DossierModalProps {
  isOpen?: boolean;
  onClose?: () => void;
  report?: ForensicReport | null;
}

export function DossierModal({
  isOpen = true,
  onClose,
  report,
}: DossierModalProps) {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && onClose) onClose();
    };
    if (isOpen) window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md"
      role="dialog"
      aria-modal="true"
    >
      <div className="relative w-full max-w-3xl max-h-[85vh] flex flex-col bg-slate-900 border border-slate-700 rounded-xl shadow-2xl overflow-hidden font-mono">
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between shrink-0 bg-slate-950/60">
          <div className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-full bg-cyan-400" />
            <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
              ISO/IEC 27037 DIGITAL EVIDENCE DOSSIER
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close dossier"
            className="p-1 text-slate-400 hover:text-white border border-slate-700 rounded bg-slate-800 transition-colors"
          >
            ✕
          </button>
        </div>

        <div className="p-6 overflow-y-auto space-y-4 text-xs">
          <div className="p-4 rounded bg-slate-950 border border-slate-800 text-emerald-400 select-all whitespace-pre-wrap">
            {JSON.stringify(report || {}, null, 2)}
          </div>
        </div>

        <div className="px-6 py-3 border-t border-slate-800 bg-slate-950/50 flex justify-between items-center text-xs">
          <button
            type="button"
            onClick={() => window.print()}
            className="px-3 py-1 bg-cyan-950 border border-cyan-700 text-cyan-300 rounded hover:bg-cyan-900 transition-colors"
          >
            Print / Save PDF
          </button>
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
  );
}

export default DossierModal;