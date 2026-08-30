'use client';

import React, { useState } from 'react';
import { ShieldAlert, FileCode2, Clock, Hash, Copy, Check, Fingerprint, Tag } from 'lucide-react';
import { ForensicReport } from '../types/forensic';

interface CaseHeaderProps {
  report: ForensicReport;
}

export const CaseHeader: React.FC<CaseHeaderProps> = ({ report }) => {
  const [copied, setCopied] = useState(false);

  const handleCopyHash = () => {
    navigator.clipboard.writeText(report.evidence.sha256);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <header className="rounded-2xl bg-[#12151c]/60 backdrop-blur-xl border border-white/10 p-6 shadow-2xl shadow-black/60 mb-6 relative overflow-hidden">
      {/* Ambient background glow corner */}
      <div className="absolute top-0 right-0 w-64 h-64 bg-rose-500/5 rounded-full blur-3xl pointer-events-none" />

      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6 relative z-10">
        
        {/* Case ID, Classification & MITRE ATT&CK */}
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-3">
            <div className="p-2.5 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 shadow-inner">
              <ShieldAlert className="w-6 h-6 animate-pulse" />
            </div>
            <h1 className="text-2xl font-extrabold tracking-tight text-white font-mono">
              {report.case_id}
            </h1>
            <span className="px-3 py-1 text-[11px] font-semibold uppercase tracking-wider rounded-full bg-rose-500/15 text-rose-400 border border-rose-500/30 shadow-[0_0_15px_-3px_rgba(244,63,94,0.3)]">
              {report.threat_intent.primary_intent.replace(/_/g, ' ')}
            </span>
            <span className="inline-flex items-center gap-1.5 px-3 py-1 text-[11px] font-mono rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <Fingerprint className="w-3.5 h-3.5" />
              INTEGRITY VERIFIED
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2 pt-0.5">
            <span className="text-xs text-slate-400 font-medium mr-1">ATT&CK:</span>
            <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-md bg-amber-500/10 border border-amber-500/20 text-amber-300 text-[10px] font-mono">
              <Tag className="w-3 h-3 text-amber-400" />
              Attribution pending
            </span>
            <span className="text-xs text-slate-400 pl-2">
              Cluster: <span className="font-mono text-cyan-300 bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-500/20">{report.graph_topology.campaign_cluster_id}</span>
            </span>
          </div>
        </div>

        {/* Evidence Metadata & Copyable SHA-256 Card */}
        <div className="bg-[#08090c]/80 p-4 rounded-xl border border-white/10 flex flex-col gap-2.5 text-xs font-mono shadow-inner lg:min-w-[380px]">
          <div className="flex items-center justify-between text-slate-300">
            <div className="flex items-center gap-2">
              <FileCode2 className="w-4 h-4 text-cyan-400 shrink-0" />
              <span className="text-[11px] truncate max-w-[200px]" title={report.evidence.filename}>
                {report.evidence.filename}
              </span>
            </div>
            <div className="flex items-center gap-1.5 text-slate-400 text-[11px]">
              <Clock className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span>{new Date(report.evidence.ingestion_timestamp).toUTCString().slice(17, 25)} UTC</span>
            </div>
          </div>

          {/* Interactive Hash Bar */}
          <div className="pt-2 border-t border-white/5 flex items-center justify-between gap-2">
            <div className="flex items-center gap-1.5 truncate text-slate-400">
              <Hash className="w-3.5 h-3.5 text-amber-400 shrink-0" />
              <span className="text-[11px] truncate text-slate-300" title={report.evidence.sha256}>
                {report.evidence.sha256}
              </span>
            </div>
            <button
              onClick={handleCopyHash}
              className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white border border-white/5 transition-all shrink-0"
              title="Copy SHA-256 Hash"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>
        </div>

      </div>
    </header>
  );
};