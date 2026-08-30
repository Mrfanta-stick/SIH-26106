'use client';

import React from 'react';
import { FileWarning, ShieldAlert, Link2 } from 'lucide-react';
import { ForensicReport } from '../types/forensic';

interface AttachmentTriageProps {
  report: ForensicReport;
}

export const AttachmentTriage: React.FC<AttachmentTriageProps> = ({ report }) => {
  const { attachment_forensics, threat_intent } = report;

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
      
      {/* 1. Attachment Forensics & Hex Dissector */}
      <div className="rounded-2xl bg-[#12151c]/60 backdrop-blur-xl border border-white/10 p-6 shadow-2xl shadow-black/60 flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between mb-5">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400">
                <FileWarning className="w-5 h-5" />
              </div>
              <div>
                <h2 className="text-sm font-bold tracking-tight uppercase text-white font-mono">
                  Static Attachment Triage
                </h2>
                <p className="text-xs text-slate-400">MAPI payload extraction & signature detection</p>
              </div>
            </div>

            <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase bg-rose-500/20 text-rose-300 border border-rose-500/30">
              {attachment_forensics.length} ATTACHMENT{attachment_forensics.length === 1 ? '' : 'S'}
            </span>
          </div>

          <div className="space-y-3">
            {attachment_forensics.length > 0 ? (
              attachment_forensics.map((att, idx) => (
                <div 
                  key={idx} 
                  className="p-4 rounded-xl bg-[#08090c]/80 border border-rose-500/30 text-xs font-mono space-y-3 shadow-lg"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-slate-100 font-bold tracking-wide">{att.filename}</span>
                    </div>
                    <span className="px-2.5 py-0.5 rounded-full text-[10px] uppercase font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30 animate-pulse">
                      {att.risk.replace(/_/g, ' ')}
                    </span>
                  </div>

                  <div className="p-2.5 rounded-lg bg-white/5 border border-white/5 text-[11px] space-y-1">
                    <div className="text-slate-400 flex justify-between">
                      <span>Magic Header:</span>
                      <span className="text-amber-300 font-semibold">{att.detected_magic}</span>
                    </div>
                    <div className="text-slate-400 flex justify-between">
                      <span>MIME Type Mask:</span>
                      <span className="text-slate-300">{att.detected_magic}</span>
                    </div>
                  </div>

                  <div className="p-2.5 rounded-lg bg-cyan-500/5 border border-cyan-500/20 text-cyan-200/80 text-[10px] leading-relaxed">
                    Byte-level hex inspection is not included in the current API response. This panel displays only the attachment metadata returned by the backend.
                  </div>
                </div>
              ))
            ) : (
              <div className="text-xs text-slate-500 font-mono py-8 text-center bg-[#08090c]/40 rounded-xl border border-white/5">
                No static attachments detected in payload.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 2. Deceptive URL Analysis */}
      <div className="rounded-2xl bg-[#12151c]/60 backdrop-blur-xl border border-white/10 p-6 shadow-2xl shadow-black/60 flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between mb-5">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-400">
                <Link2 className="w-5 h-5" />
              </div>
              <div>
                <h2 className="text-sm font-bold tracking-tight uppercase text-white font-mono">
                  URL Discrepancy Analysis
                </h2>
                <p className="text-xs text-slate-400">Homoglyphs, masked links & deceptive routing</p>
              </div>
            </div>

            <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase bg-amber-500/20 text-amber-300 border border-amber-500/30">
              {threat_intent.suspicious_urls.length} MISMATCH{threat_intent.suspicious_urls.length === 1 ? '' : 'ES'}
            </span>
          </div>

          <div className="space-y-3">
            {threat_intent.suspicious_urls.map((url, idx) => (
              <div 
                key={idx} 
                className="p-4 rounded-xl bg-[#08090c]/80 border border-amber-500/30 text-xs font-mono space-y-3 shadow-lg"
              >
                <div className="space-y-2">
                  <div className="p-2.5 rounded-lg bg-white/5 border border-white/5 space-y-1.5 text-[11px]">
                    <div className="flex items-center justify-between text-slate-400">
                      <span>Visible Anchor:</span>
                      <span className="text-slate-100 font-semibold">{url.anchor_text}</span>
                    </div>
                    <div className="flex items-center justify-between text-slate-400">
                      <span>Destination IP/URI:</span>
                      <span className="text-rose-400 font-bold truncate max-w-[200px]">{url.destination}</span>
                    </div>
                  </div>
                </div>

                {url.is_mismatch && (
                  <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/25 text-rose-300 text-[11px] flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 shrink-0 text-rose-400" />
                    <span>Domain Masking Detected: Link points to unauthorized IP pool.</span>
                  </div>
                )}
              </div>
            ))}
            {threat_intent.suspicious_urls.length === 0 && (
              <div className="text-xs text-slate-500 font-mono py-8 text-center bg-[#08090c]/40 rounded-xl border border-white/5">No suspicious URL mismatches were returned by the backend.</div>
            )}
          </div>
        </div>
      </div>

    </div>
  );
};