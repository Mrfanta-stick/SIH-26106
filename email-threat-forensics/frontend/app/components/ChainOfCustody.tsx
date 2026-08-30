import React from 'react';
import { History, ShieldCheck, User, Link as LinkIcon, Cpu } from 'lucide-react';
import { ForensicReport } from '../types/forensic';

interface ChainOfCustodyProps {
  report: ForensicReport;
}

export const ChainOfCustody: React.FC<ChainOfCustodyProps> = ({ report }) => {
  return (
    <div className="rounded-2xl bg-[#12151c]/60 backdrop-blur-xl border border-white/10 p-6 shadow-2xl shadow-black/60 mb-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-6">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-xl bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
            <History className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-bold tracking-tight uppercase text-white">
              Evidentiary Chain of Custody Ledger
            </h2>
            <p className="text-xs text-slate-400">Tamper-evident audit trail & cryptographic verification</p>
          </div>
        </div>
        <span className="inline-flex items-center gap-1.5 text-[11px] font-mono px-3 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/25">
          <ShieldCheck className="w-3.5 h-3.5" />
          Cryptographically Verified
        </span>
      </div>

      {/* Connected Timeline Container */}
      <div className="relative pl-6 space-y-6 before:absolute before:left-[19px] before:top-3 before:bottom-3 before:w-[2px] before:bg-gradient-to-b before:from-indigo-500 before:via-cyan-500 before:to-emerald-500/40">
        {report.chain_of_custody.map((entry) => (
          <div key={entry.sequence} className="relative group">
            
            {/* Glowing Timeline Dot */}
            <div className="absolute -left-[30px] top-4 w-4 h-4 rounded-full bg-[#08090c] border-2 border-indigo-400 shadow-[0_0_10px_rgba(99,102,241,0.5)] group-hover:border-cyan-400 group-hover:shadow-[0_0_12px_rgba(6,182,212,0.8)] transition-all duration-300" />

            {/* Entry Card */}
            <div className="p-4 rounded-xl bg-[#08090c]/70 border border-white/5 group-hover:border-white/20 transition-all duration-300 space-y-3 shadow-lg">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-2.5">
                  <span className="px-2 py-0.5 rounded-md bg-indigo-500/15 border border-indigo-500/30 text-indigo-300 text-[11px] font-mono font-bold">
                    BLOCK #{entry.sequence}
                  </span>
                  <span className="text-xs font-bold font-mono text-white tracking-wide uppercase">
                    {entry.action.replace(/_/g, ' ')}
                  </span>
                </div>
                <div className="flex items-center gap-3 text-xs text-slate-400">
                  <div className="flex items-center gap-1.5">
                    <User className="w-3.5 h-3.5 text-slate-400" />
                    <span className="font-mono text-slate-200">{entry.actor}</span>
                  </div>
                  <span>•</span>
                  <span className="text-slate-400">{new Date(entry.timestamp).toUTCString()}</span>
                </div>
              </div>

              {/* Hash Verification Strip */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] font-mono pt-2.5 border-t border-white/5">
                <div className="text-slate-400 truncate flex items-center gap-1.5">
                  <span className="text-slate-500">PREV:</span>
                  <span className="text-slate-300 bg-white/5 px-1.5 py-0.5 rounded border border-white/5">{entry.prev_hash}</span>
                </div>
                <div className="text-slate-400 truncate flex items-center gap-1.5">
                  <LinkIcon className="w-3 h-3 text-emerald-400 shrink-0" />
                  <span className="text-slate-500">HASH:</span>
                  <span className="text-emerald-400 font-semibold bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/20">{entry.entry_hash}</span>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};