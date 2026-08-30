'use client';

import React from 'react';
import { Crosshair, AlertTriangle, CheckCircle2, Clock3, ShieldAlert } from 'lucide-react';
import { ForensicReport } from '../types/forensic';

interface MitreMatrixProps {
  report?: ForensicReport;
}

export const MitreMatrix: React.FC<MitreMatrixProps> = ({ report }) => {
  const pending = report ? 'Stage 3–5 are not yet implemented by the uploaded backend.' : 'No report loaded.';
  const urlCount = report?.threat_intent.suspicious_urls.filter((url) => url.is_mismatch).length ?? 0;
  const attachmentCount = report?.attachment_forensics.length ?? 0;
  const authFailures = report ? [report.protocol_forensics.spf, report.protocol_forensics.dkim, report.protocol_forensics.dmarc].filter((value) => value !== 'PASS').length : 0;

  return (
    <div className="rounded-2xl bg-[#12151c]/60 backdrop-blur-xl border border-white/10 p-6 shadow-2xl shadow-black/60 mb-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-5">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400"><Crosshair className="w-5 h-5" /></div>
          <div><h2 className="text-sm font-bold tracking-tight uppercase text-white font-mono">MITRE ATT&CK Mapping</h2><p className="text-xs text-slate-400">Backend-supported evidence signals and pipeline coverage</p></div>
        </div>
        <span className="px-3 py-1 text-[11px] font-mono rounded-full bg-amber-500/10 text-amber-300 border border-amber-500/25">Attribution pending</span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-5">
        <div className="p-4 rounded-xl bg-[#08090c]/80 border border-white/5 space-y-2"><div className="flex items-center gap-2 text-purple-300"><ShieldAlert className="w-4 h-4" /><span className="text-[10px] font-bold uppercase">Authentication</span></div><div className="text-xl font-bold text-white">{authFailures}</div><p className="text-[10px] text-slate-500">non-PASS SPF/DKIM/DMARC results</p></div>
        <div className="p-4 rounded-xl bg-[#08090c]/80 border border-white/5 space-y-2"><div className="flex items-center gap-2 text-amber-300"><AlertTriangle className="w-4 h-4" /><span className="text-[10px] font-bold uppercase">URL Signals</span></div><div className="text-xl font-bold text-white">{urlCount}</div><p className="text-[10px] text-slate-500">destination / anchor mismatches</p></div>
        <div className="p-4 rounded-xl bg-[#08090c]/80 border border-white/5 space-y-2"><div className="flex items-center gap-2 text-cyan-300"><CheckCircle2 className="w-4 h-4" /><span className="text-[10px] font-bold uppercase">Attachments</span></div><div className="text-xl font-bold text-white">{attachmentCount}</div><p className="text-[10px] text-slate-500">records returned by static extraction</p></div>
      </div>

      <div className="p-4 rounded-xl bg-[#08090c]/90 border border-purple-500/20 font-mono text-xs">
        <div className="flex items-center gap-2 text-amber-300 font-bold"><Clock3 className="w-3.5 h-3.5" /> ATT&CK attribution unavailable from current backend</div>
        <p className="mt-2 text-slate-400 leading-relaxed">{pending} The frontend intentionally does not invent technique IDs or confidence values; once those stages are added, this panel can consume them directly from the same report contract.</p>
      </div>
    </div>
  );
};
