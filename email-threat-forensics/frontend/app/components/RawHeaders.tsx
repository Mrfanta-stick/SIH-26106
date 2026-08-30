'use client';

import React, { useMemo, useState } from 'react';
import { Code, Copy, Check, ChevronDown, ChevronUp } from 'lucide-react';
import { ForensicReport } from '../types/forensic';

interface RawHeadersProps { report: ForensicReport; }

export const RawHeaders: React.FC<RawHeadersProps> = ({ report }) => {
  const [isOpen, setIsOpen] = useState(true);
  const [copied, setCopied] = useState(false);

  const parsedTelemetry = useMemo(() => `From-Domain: ${report.protocol_forensics.domain_alignment.from_domain || 'N/A'}\nReturn-Path-Domain: ${report.protocol_forensics.domain_alignment.return_path_domain || 'N/A'}\nReply-To-Domain: ${report.protocol_forensics.domain_alignment.reply_to_domain || 'N/A'}\nDomain-Alignment: ${report.protocol_forensics.domain_alignment.is_aligned ? 'ALIGNED' : 'MISALIGNED'}\n\nSPF: ${report.protocol_forensics.spf}\nDKIM: ${report.protocol_forensics.dkim}\nDMARC: ${report.protocol_forensics.dmarc}\n\nOrigin-IP: ${report.origin_network.ip}\nASN: ${report.origin_network.asn}\nCountry: ${report.origin_network.country}\nCity: ${report.origin_network.city}`, [report]);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(parsedTelemetry);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="rounded-2xl bg-[#12151c]/60 backdrop-blur-xl border border-white/10 p-6 shadow-2xl shadow-black/60">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2.5"><div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400"><Code className="w-5 h-5" /></div><div><h2 className="text-sm font-bold tracking-tight uppercase text-white">Parsed Header Telemetry</h2><p className="text-xs text-slate-400">Authentication and address fields returned by the backend</p></div></div>
        <div className="flex items-center gap-2"><button onClick={handleCopy} className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-white/5 hover:bg-white/10 text-slate-300 text-xs font-mono border border-white/10 transition-all">{copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}<span>{copied ? 'Copied' : 'Copy Telemetry'}</span></button><button onClick={() => setIsOpen(!isOpen)} className="p-1.5 rounded-xl bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white border border-white/10 transition-all">{isOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}</button></div>
      </div>
      {isOpen && <div className="mt-4 p-4 rounded-xl bg-[#08090c]/90 border border-white/10 overflow-x-auto text-[11px] font-mono text-slate-300 leading-relaxed max-h-[300px] select-text"><pre>{parsedTelemetry}</pre></div>}
    </div>
  );
};
