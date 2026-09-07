'use client';

import React, { useMemo } from 'react';
import { Crosshair, ShieldAlert, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { ForensicReport } from '../types/forensic';

interface MitreMatrixProps {
  report?: ForensicReport;
}

interface TechniqueHit {
  id: string;
  name: string;
  tactic: string;
  evidence: string;
}

function deriveTechniques(report?: ForensicReport): TechniqueHit[] {
  if (!report) return [];

  const hits: TechniqueHit[] = [];
  const authFailures = [report.protocol_forensics.spf, report.protocol_forensics.dkim, report.protocol_forensics.dmarc]
    .filter((value) => value !== 'PASS');
  const mismatches = report.threat_intent.suspicious_urls.filter((url) => url.is_mismatch);
  const riskyAttachments = report.attachment_forensics.filter((att) => {
    const risk = (att.risk || '').toUpperCase();
    return risk && risk !== 'BENIGN' && risk !== 'CLEAN' && risk !== 'UNKNOWN';
  });
  const intent = report.threat_intent.primary_intent.toUpperCase();

  if (authFailures.length > 0 || !report.protocol_forensics.domain_alignment.is_aligned) {
    hits.push({
      id: 'T1566',
      name: 'Phishing',
      tactic: 'Initial Access',
      evidence: `${authFailures.length || 0} auth non-PASS result(s); alignment ${report.protocol_forensics.domain_alignment.is_aligned ? 'aligned' : 'misaligned'}`,
    });
    hits.push({
      id: 'T1036',
      name: 'Masquerading',
      tactic: 'Defense Evasion',
      evidence: `From ${report.protocol_forensics.domain_alignment.from_domain} vs Return-Path ${report.protocol_forensics.domain_alignment.return_path_domain}`,
    });
  }

  if (mismatches.length > 0) {
    hits.push({
      id: 'T1566.002',
      name: 'Spearphishing Link',
      tactic: 'Initial Access',
      evidence: `${mismatches.length} anchor/destination mismatch(es)`,
    });
    hits.push({
      id: 'T1204.001',
      name: 'User Execution: Malicious Link',
      tactic: 'Execution',
      evidence: mismatches[0]?.destination || 'mismatched href present',
    });
  }

  if (report.attachment_forensics.length > 0) {
    hits.push({
      id: 'T1566.001',
      name: 'Spearphishing Attachment',
      tactic: 'Initial Access',
      evidence: `${report.attachment_forensics.length} attachment(s); ${riskyAttachments.length} elevated-risk`,
    });
  }

  if (riskyAttachments.length > 0) {
    hits.push({
      id: 'T1204.002',
      name: 'User Execution: Malicious File',
      tactic: 'Execution',
      evidence: riskyAttachments.map((att) => `${att.filename} (${att.risk})`).join('; '),
    });
  }

  if (report.origin_network.typosquat_target) {
    hits.push({
      id: 'T1583.001',
      name: 'Acquire Infrastructure: Domains',
      tactic: 'Resource Development',
      evidence: `Typosquat of ${report.origin_network.typosquat_target} (edit distance ${report.origin_network.edit_distance ?? 'n/a'})`,
    });
  }

  if (report.origin_network.is_datacenter || report.origin_network.is_vpn_tor) {
    hits.push({
      id: 'T1583.003',
      name: 'Acquire Infrastructure: Virtual Private Server',
      tactic: 'Resource Development',
      evidence: `${report.origin_network.org} ${report.origin_network.asn}${report.origin_network.is_vpn_tor ? ' (VPN/Tor)' : ' (datacenter)'}`,
    });
  }

  if (report.threat_intent.flagged_coercion_cues.length > 0) {
    hits.push({
      id: 'T1027',
      name: 'Obfuscated Files or Information',
      tactic: 'Defense Evasion',
      evidence: `${report.threat_intent.flagged_coercion_cues.length} hidden/coercion cue(s)`,
    });
  }

  if (intent.includes('CREDENTIAL')) {
    hits.push({
      id: 'T1598.003',
      name: 'Phishing for Information: Spearphishing Link',
      tactic: 'Reconnaissance',
      evidence: `Intent ${report.threat_intent.primary_intent}`,
    });
  }

  if (intent.includes('BEC') || intent.includes('FRAUD') || intent.includes('PAYROLL') || intent.includes('EXTORT')) {
    hits.push({
      id: 'T1657',
      name: 'Financial Theft',
      tactic: 'Impact',
      evidence: `Intent ${report.threat_intent.primary_intent} (risk ${report.threat_intent.risk_score}/100)`,
    });
  }

  if (hits.length === 0) {
    hits.push({
      id: 'T1566',
      name: 'Phishing',
      tactic: 'Initial Access',
      evidence: `Case classified ${report.threat_intent.primary_intent} with risk ${report.threat_intent.risk_score}/100`,
    });
  }

  return hits;
}

export const MitreMatrix: React.FC<MitreMatrixProps> = ({ report }) => {
  const techniques = useMemo(() => deriveTechniques(report), [report]);
  const urlCount = report?.threat_intent.suspicious_urls.filter((url) => url.is_mismatch).length ?? 0;
  const attachmentCount = report?.attachment_forensics.length ?? 0;
  const authFailures = report ? [report.protocol_forensics.spf, report.protocol_forensics.dkim, report.protocol_forensics.dmarc].filter((value) => value !== 'PASS').length : 0;
  const cluster = report?.graph_topology?.campaign_cluster_id;

  return (
    <div className="rounded-2xl bg-[#12151c]/60 backdrop-blur-xl border border-white/10 p-6 shadow-2xl shadow-black/60 mb-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-5">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400"><Crosshair className="w-5 h-5" /></div>
          <div>
            <h2 className="text-sm font-bold tracking-tight uppercase text-white font-mono">MITRE ATTACK Mapping</h2>
            <p className="text-xs text-slate-400">Techniques inferred from the live forensic report</p>
          </div>
        </div>
        <span className="px-3 py-1 text-[11px] font-mono rounded-full bg-emerald-500/10 text-emerald-300 border border-emerald-500/25">
          {cluster ? `Cluster ${cluster}` : `${techniques.length} technique hit${techniques.length === 1 ? '' : 's'}`}
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-5">
        <div className="p-4 rounded-xl bg-[#08090c]/80 border border-white/5 space-y-2"><div className="flex items-center gap-2 text-purple-300"><ShieldAlert className="w-4 h-4" /><span className="text-[10px] font-bold uppercase">Authentication</span></div><div className="text-xl font-bold text-white">{authFailures}</div><p className="text-[10px] text-slate-500">non-PASS SPF/DKIM/DMARC results</p></div>
        <div className="p-4 rounded-xl bg-[#08090c]/80 border border-white/5 space-y-2"><div className="flex items-center gap-2 text-amber-300"><AlertTriangle className="w-4 h-4" /><span className="text-[10px] font-bold uppercase">URL Signals</span></div><div className="text-xl font-bold text-white">{urlCount}</div><p className="text-[10px] text-slate-500">destination / anchor mismatches</p></div>
        <div className="p-4 rounded-xl bg-[#08090c]/80 border border-white/5 space-y-2"><div className="flex items-center gap-2 text-cyan-300"><CheckCircle2 className="w-4 h-4" /><span className="text-[10px] font-bold uppercase">Attachments</span></div><div className="text-xl font-bold text-white">{attachmentCount}</div><p className="text-[10px] text-slate-500">records returned by static extraction</p></div>
      </div>

      <div className="space-y-2">
        {techniques.map((tech) => (
          <div key={`${tech.id}-${tech.name}`} className="p-3 rounded-xl bg-[#08090c]/90 border border-purple-500/20 font-mono text-xs">
            <div className="flex flex-wrap items-center gap-2">
              <span className="px-2 py-0.5 rounded bg-purple-500/15 border border-purple-500/30 text-purple-200 font-bold">{tech.id}</span>
              <span className="text-white font-semibold">{tech.name}</span>
              <span className="text-slate-500">·</span>
              <span className="text-cyan-300">{tech.tactic}</span>
            </div>
            <p className="mt-1.5 text-slate-400 leading-relaxed">{tech.evidence}</p>
          </div>
        ))}
      </div>
    </div>
  );
};
