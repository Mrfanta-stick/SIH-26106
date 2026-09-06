'use client';

import React from 'react';
import { Bot, Sparkles } from 'lucide-react';
import { ForensicReport } from '../types/forensic';

interface AiVerdictProps {
  report: ForensicReport;
}

export const AiVerdict: React.FC<AiVerdictProps> = ({ report }) => {
  const score = report.threat_intent.risk_score;
  const intent = report.threat_intent.primary_intent.replace(/_/g, ' ');
  const severity = score >= 80 ? 'HIGH RISK' : score >= 50 ? 'ELEVATED RISK' : 'LOW RISK';
  const severityClass = score >= 80 ? 'bg-rose-500/20 text-rose-300 border-rose-500/30' : score >= 50 ? 'bg-amber-500/20 text-amber-300 border-amber-500/30' : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30';
  const authFailed = [report.protocol_forensics.spf, report.protocol_forensics.dkim, report.protocol_forensics.dmarc].filter(v => v !== 'PASS').length;
  const attachmentCount = report.attachment_forensics.length;
  const mismatchCount = report.threat_intent.suspicious_urls.filter(u => u.is_mismatch).length;

  return (
    <div className="rounded-2xl bg-gradient-to-r from-rose-950/30 via-[#12151c]/80 to-purple-950/20 backdrop-blur-xl border border-rose-500/30 p-6 shadow-2xl shadow-rose-950/30 relative overflow-hidden">
      <div className="absolute -top-12 -right-12 w-48 h-48 bg-rose-500/10 rounded-full blur-3xl pointer-events-none" />
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pb-4 border-b border-white/5">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-rose-500/15 border border-rose-500/30 text-rose-400 shadow-inner"><Bot className="w-5 h-5" /></div>
          <div><div className="flex items-center gap-2"><h2 className="text-sm font-bold tracking-tight uppercase text-white font-mono">Backend Forensic Verdict</h2><span className={`px-2 py-0.5 rounded-full text-[9px] font-mono font-bold uppercase border ${severityClass}`}>{severity}</span></div><p className="text-xs text-slate-400">Live values returned by the FastAPI analysis endpoint</p></div>
        </div>
        <div className="flex items-center gap-2 text-[11px] font-mono text-slate-300 bg-[#08090c]/80 px-3 py-1.5 rounded-xl border border-white/5"><Sparkles className="w-3.5 h-3.5 text-cyan-400" /><span>Risk Score: <strong className="text-cyan-400">{score}/100</strong></span></div>
      </div>
      <div className="mt-4 space-y-3">
        <p className="text-xs text-slate-200 leading-relaxed font-sans">This case is currently classified as <strong className="text-purple-300 font-semibold">{intent}</strong>. The backend reports <strong className="text-rose-400">{authFailed}</strong> authentication control(s) not passing, <strong className="text-amber-400">{mismatchCount}</strong> suspicious URL mismatch(es), and <strong className="text-cyan-300">{attachmentCount}</strong> attachment(s).</p>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2">
          <div className="p-3 rounded-xl bg-[#08090c]/60 border border-white/5 text-xs space-y-1"><span className="text-[10px] uppercase font-mono text-slate-400 block">Intent</span><span className="text-purple-300 font-semibold">{intent}</span></div>
          <div className="p-3 rounded-xl bg-[#08090c]/60 border border-white/5 text-xs space-y-1"><span className="text-[10px] uppercase font-mono text-slate-400 block">Authentication</span><span className={authFailed ? 'text-rose-400 font-semibold' : 'text-emerald-400 font-semibold'}>{authFailed ? `${authFailed} non-pass result(s)` : 'All controls PASS'}</span></div>
          <div className="p-3 rounded-xl bg-[#08090c]/60 border border-white/5 text-xs space-y-1"><span className="text-[10px] uppercase font-mono text-slate-400 block">Pipeline Scope</span><span className="text-cyan-300 font-semibold">Stage 1–3 HTML active</span></div>
        </div>
      </div>
    </div>
  );
};
