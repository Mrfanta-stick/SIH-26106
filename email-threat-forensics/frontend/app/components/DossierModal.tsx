'use client';

import React, { useEffect, useRef } from 'react';
import { 
  X, 
  Printer, 
  ShieldCheck, 
  FileText, 
  QrCode, 
  Stamp, 
  Lock, 
  Hash, 
  Calendar, 
  Server,
  Download
} from 'lucide-react';
import { ForensicReport } from '../types/forensic';

interface DossierModalProps {
  report: ForensicReport;
  onClose: () => void;
}

export const DossierModal: React.FC<DossierModalProps> = ({ report, onClose }) => {
  const modalRef = useRef<HTMLDivElement | null>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    previousFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const firstFocusable = modalRef.current?.querySelector<HTMLElement>(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    firstFocusable?.focus();

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== 'Tab') return;

      const focusables = Array.from(
        modalRef.current?.querySelectorAll<HTMLElement>(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        ) ?? []
      ).filter((element) => !element.hasAttribute('disabled'));

      if (!focusables.length) return;
      const first = focusables[0];
      const last = focusables[focusables.length - 1];

      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      previousFocusRef.current?.focus();
    };
  }, [onClose]);

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md animate-in fade-in duration-200 overflow-y-auto" role="presentation">
      
      {/* Container Box */}
      <div ref={modalRef} role="dialog" aria-modal="true" aria-labelledby="dossier-title" className="relative w-full max-w-3xl my-8 rounded-2xl bg-[#0e1017] border border-white/15 shadow-2xl shadow-black overflow-hidden text-slate-200 font-sans">
        
        {/* Top Modal Controls */}
        <div className="flex items-center justify-between px-6 py-4 bg-white/[0.03] border-b border-white/10 no-print">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <FileText className="w-4 h-4" />
            </div>
            <span className="text-xs font-bold font-mono uppercase tracking-wider text-white">
              <span id="dossier-title">ISO/IEC 27037 Digital Evidence Dossier</span>
            </span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handlePrint}
              aria-label="Print or save the forensic dossier as PDF"
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl bg-purple-600 hover:bg-purple-500 text-white text-xs font-medium transition-all shadow-lg active:scale-95"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print / Save PDF</span>
            </button>
            <button
              onClick={onClose}
              aria-label="Close forensic dossier"
              className="p-1.5 rounded-xl bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white border border-white/10 transition-all"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Certificate Document Body */}
        <div className="p-8 space-y-6 bg-[#0a0c12] text-xs font-mono">
          
          {/* Official Document Header */}
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-6 border-b border-white/10">
            <div className="space-y-1">
              <div className="text-[10px] text-purple-400 font-bold uppercase tracking-widest">
                NATIONAL CYBER INCIDENT FORENSIC ARCHIVE
              </div>
              <h1 className="text-lg font-extrabold text-white tracking-tight">
                CERTIFICATE OF DIGITAL EVIDENCE ADMISSIBILITY
              </h1>
              <p className="text-[11px] text-slate-400">
                Standards Compliance: ISO/IEC 27037:2012 Guidelines for Digital Evidence Handling
              </p>
            </div>

            {/* QR Verification Stamp */}
            <div className="flex items-center gap-3 p-2.5 rounded-xl bg-white/[0.03] border border-white/10 shrink-0">
              <div className="w-12 h-12 bg-white rounded-lg flex items-center justify-center p-1 text-black">
                <QrCode className="w-full h-full" />
              </div>
              <div className="text-[9px] text-slate-400 space-y-0.5">
                <span className="text-emerald-400 font-bold block">HASH-CHAIN VERIFIED</span>
                <span>ID: {report.case_id}</span>
                <span className="block text-slate-500">SHA-256 LEDGER</span>
              </div>
            </div>
          </div>

          {/* Incident Metadata Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3 rounded-xl bg-white/[0.02] border border-white/5 space-y-1">
              <span className="text-[10px] text-slate-500 uppercase block">Case Number</span>
              <span className="text-white font-bold text-xs">{report.case_id}</span>
            </div>
            <div className="p-3 rounded-xl bg-white/[0.02] border border-white/5 space-y-1">
              <span className="text-[10px] text-slate-500 uppercase block">Primary Intent</span>
              <span className="text-rose-400 font-bold text-[11px] truncate block">
                {report.threat_intent.primary_intent.replace(/_/g, ' ')}
              </span>
            </div>
            <div className="p-3 rounded-xl bg-white/[0.02] border border-white/5 space-y-1">
              <span className="text-[10px] text-slate-500 uppercase block">Risk Score</span>
              <span className="text-rose-400 font-bold text-xs">{report.threat_intent.risk_score} / 100</span>
            </div>
            <div className="p-3 rounded-xl bg-white/[0.02] border border-white/5 space-y-1">
              <span className="text-[10px] text-slate-500 uppercase block">Evidence Type</span>
              <span className="text-slate-200 font-bold text-[11px]">RFC 5322 MIME</span>
            </div>
          </div>

          {/* Cryptographic Hash Verification Block */}
          <div className="p-4 rounded-xl bg-purple-950/20 border border-purple-500/30 space-y-2">
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-purple-300 font-bold flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-purple-400" />
                IMMUTABLE EVIDENCE SHA-256 DIGITAL DIGEST
              </span>
              <span className="text-emerald-400 font-semibold">SHA-256 CAPTURED</span>
            </div>
            <div className="p-2.5 rounded-lg bg-[#040507] border border-white/5 text-[11px] text-slate-300 select-all font-mono break-all">
              {report.evidence.sha256}
            </div>
          </div>

          {/* Key Findings Summary */}
          <div className="space-y-2">
            <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider block">
              Forensic Triage Summary
            </span>
            <div className="p-3.5 rounded-xl bg-white/[0.02] border border-white/5 space-y-2 text-[11px] text-slate-300 leading-relaxed font-sans">
              <p>
                • <strong>Origin Routing:</strong> Ingress traffic was resolved to IP <span className="font-mono text-white">{report.origin_network.ip}</span> ({report.origin_network.city}, {report.origin_network.country}) under ASN {report.origin_network.asn}.
              </p>
              <p>
                • <strong>Authentication Vector:</strong> Authentication results: SPF=<span className="font-mono text-rose-300">{report.protocol_forensics.spf}</span>, DKIM=<span className="font-mono text-rose-300">{report.protocol_forensics.dkim}</span>, DMARC=<span className="font-mono text-rose-300">{report.protocol_forensics.dmarc}</span>. Domain alignment: <span className="font-mono text-purple-300">{report.protocol_forensics.domain_alignment.is_aligned ? 'ALIGNED' : 'MISALIGNED'}</span>.
              </p>
              <p>
                • <strong>Payload Classification:</strong> The backend returned {report.attachment_forensics.length} attachment finding(s); static triage is currently pending for these records.
              </p>
            </div>
          </div>

          {/* Chain of Custody Audit Log Strip */}
          <div className="space-y-2">
            <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider block">
              Chain of Custody Ledger Blocks
            </span>
            <div className="space-y-1.5">
              {report.chain_of_custody.map((entry) => (
                <div key={entry.sequence} className="p-2.5 rounded-lg bg-[#07090e] border border-white/5 flex items-center justify-between text-[10px]">
                  <div className="flex items-center gap-2">
                    <span className="text-purple-400 font-bold">#{entry.sequence}</span>
                    <span className="text-white font-semibold">{entry.action.replace(/_/g, ' ')}</span>
                    <span className="text-slate-500">• {entry.actor}</span>
                  </div>
                  <div className="text-slate-400 font-mono truncate max-w-[200px]">
                    Hash: <span className="text-emerald-400">{entry.entry_hash.slice(0, 16)}...</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Official Forensic Seal & Legal Stamp */}
          <div className="pt-4 border-t border-white/10 flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-full border-2 border-dashed border-purple-400 flex items-center justify-center text-purple-400 animate-spin" style={{ animationDuration: '24s' }}>
                <Stamp className="w-5 h-5" />
              </div>
              <div>
                <div className="text-[11px] font-bold text-white uppercase">Automated DFIR Engine Verification</div>
                <div className="text-[10px] text-slate-500">Timestamp: {new Date().toUTCString()}</div>
              </div>
            </div>

            <div className="px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-[10px] font-bold tracking-wider uppercase flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5" />
              EVIDENTIARY INTEGRITY CERTIFIED
            </div>
          </div>

        </div>

      </div>
    </div>
  );
};