import React from 'react';
import { AlertTriangle, CheckCircle2, XCircle, ShieldCheck } from 'lucide-react';
import { ForensicReport } from '../types/forensic';

interface ThreatGaugesProps {
  report: ForensicReport;
}

export const ThreatGauges: React.FC<ThreatGaugesProps> = ({ report }) => {
  const { threat_intent, protocol_forensics } = report;
  const score = threat_intent.risk_score;
  const severity = score >= 80 ? 'HIGH SEVERITY' : score >= 50 ? 'ELEVATED SEVERITY' : 'LOW SEVERITY';
  const severityClass = score >= 80 ? 'text-rose-400' : score >= 50 ? 'text-amber-400' : 'text-emerald-400';

  // SVG Circular Gauge calculations
  const radius = 42;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  const renderBadge = (label: string, status: 'PASS' | 'FAIL') => {
    const isPass = status === 'PASS';
    return (
      <div className={`flex items-center justify-between px-3 py-2 rounded-xl border transition-all ${
        isPass 
          ? 'bg-emerald-500/10 border-emerald-500/25 text-emerald-400' 
          : 'bg-rose-500/10 border-rose-500/25 text-rose-400'
      }`}>
        <span className="text-[11px] font-mono font-bold tracking-wider">{label}</span>
        <div className="flex items-center gap-1.5 text-xs font-semibold">
          {isPass ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
          <span className="text-[11px]">{status}</span>
        </div>
      </div>
    );
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
      
      {/* 1. Neon Radial Risk Score Gauge */}
      <div className="rounded-2xl bg-[#12151c]/60 backdrop-blur-xl border border-white/10 p-6 shadow-2xl shadow-black/60 flex flex-col items-center justify-center text-center relative overflow-hidden">
        {/* Subtle Ambient Radial Glow */}
        <div className="absolute w-32 h-32 bg-rose-500/10 rounded-full blur-[40px] pointer-events-none" />

        <span className="text-[11px] uppercase font-semibold text-slate-400 tracking-wider mb-2">
          Composite Threat Score
        </span>

        {/* SVG Circular Meter */}
        <div className="relative flex items-center justify-center my-2">
          <svg className="w-32 h-32 -rotate-90 transform" viewBox="0 0 100 100">
            {/* Background Track Ring */}
            <circle
              cx="50"
              cy="50"
              r={radius}
              stroke="currentColor"
              strokeWidth="7"
              className="text-white/5"
              fill="transparent"
            />
            {/* Active Gradient Arc */}
            <circle
              cx="50"
              cy="50"
              r={radius}
              stroke="url(#threatGradient)"
              strokeWidth="7"
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              fill="transparent"
              className="transition-all duration-1000 ease-out"
            />
            <defs>
              <linearGradient id="threatGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#f43f5e" />
                <stop offset="100%" stopColor="#fb7185" />
              </linearGradient>
            </defs>
          </svg>

          {/* Centered Score Display */}
          <div className="absolute flex flex-col items-center justify-center">
            <span className="text-3xl font-extrabold tracking-tight text-white drop-shadow-[0_0_12px_rgba(244,63,94,0.5)]">
              {score}
            </span>
            <span className="text-[10px] uppercase font-semibold text-slate-400">/ 100</span>
          </div>
        </div>

        <div className="mt-2 text-xs text-slate-400 font-medium">
          Level: <span className={`${severityClass} font-bold tracking-wide`}>{severity}</span>
        </div>
      </div>

      {/* 2. Urgency & Coercion Flags */}
      <div className="rounded-2xl bg-[#12151c]/60 backdrop-blur-xl border border-white/10 p-6 shadow-2xl shadow-black/60 flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between mb-4">
            <span className="text-[11px] uppercase font-semibold text-slate-400 tracking-wider">
              Urgency & Coercion Index
            </span>
            <div className="p-1.5 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          
          {/* Urgency Progress Bar */}
          <div className="mb-5">
            <div className="flex justify-between text-xs font-medium text-slate-300 mb-2">
              <span>Urgency Level</span>
              <span className="text-amber-400 font-semibold">{Math.round(threat_intent.urgency_score * 100)}%</span>
            </div>
            <div className="w-full bg-[#08090c]/80 h-2.5 rounded-full overflow-hidden border border-white/5">
              <div 
                className="bg-gradient-to-r from-amber-500 to-orange-400 h-full rounded-full transition-all duration-700" 
                style={{ width: `${threat_intent.urgency_score * 100}%` }}
              />
            </div>
          </div>

          {/* Flagged Coercion Cues */}
          <div className="space-y-2">
            <span className="text-[11px] font-medium text-slate-400 block">Flagged Linguistic Cues:</span>
            <div className="flex flex-wrap gap-1.5">
              {threat_intent.flagged_coercion_cues.map((cue, idx) => (
                <span 
                  key={idx} 
                  className="px-2.5 py-1 text-[11px] font-mono rounded-lg bg-rose-500/10 text-rose-300 border border-rose-500/20"
                >
                  "{cue}"
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* 3. Authentication & Protocol Forensics */}
      <div className="rounded-2xl bg-[#12151c]/60 backdrop-blur-xl border border-white/10 p-6 shadow-2xl shadow-black/60 flex flex-col justify-between gap-4">
        <div>
          <div className="flex items-center justify-between mb-4">
            <span className="text-[11px] uppercase font-semibold text-slate-400 tracking-wider">
              Protocol Forensics
            </span>
            <div className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <ShieldCheck className="w-4 h-4" />
            </div>
          </div>

          <div className="grid grid-cols-3 gap-2 mb-4">
            {renderBadge('SPF', protocol_forensics.spf)}
            {renderBadge('DKIM', protocol_forensics.dkim)}
            {renderBadge('DMARC', protocol_forensics.dmarc)}
          </div>
        </div>

        <div className="bg-[#08090c]/70 p-3.5 rounded-xl border border-white/5 text-[11px] font-mono space-y-1.5">
          <div className="text-slate-400 flex justify-between">From Domain: <span className="text-slate-200">{protocol_forensics.domain_alignment.from_domain}</span></div>
          <div className="text-slate-400 flex justify-between">Return-Path: <span className="text-rose-400">{protocol_forensics.domain_alignment.return_path_domain}</span></div>
          <div className="pt-2 border-t border-white/5 flex items-center justify-between">
            <span className="text-slate-400">Domain Alignment:</span>
            <span className={protocol_forensics.domain_alignment.is_aligned ? "text-emerald-400 font-bold" : "text-rose-400 font-bold"}>
              {protocol_forensics.domain_alignment.is_aligned ? "ALIGNED" : "MISALIGNED"}
            </span>
          </div>
        </div>
      </div>

    </div>
  );
};