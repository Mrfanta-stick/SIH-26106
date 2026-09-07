"use client";

import { ForensicReport } from "../types/forensic";

export interface ThreatGaugesProps {
  report?: ForensicReport | null;
  threatIntent?: ForensicReport["threat_intent"];
}

export function ThreatGauges({ report, threatIntent }: ThreatGaugesProps) {
  const intent = threatIntent || report?.threat_intent;
  const threatScore = intent?.risk_score ?? 0;
  const urgency = Math.round((intent?.urgency_score ?? 0) * 100);
  const cues = intent?.flagged_coercion_cues ?? [];
  const urls = intent?.suspicious_urls ?? [];

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4 backdrop-blur-sm font-mono">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-amber-400 animate-pulse" />
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
            Social Engineering & Threat Intent Gauges
          </h3>
        </div>
        <span className="text-[10px] text-slate-500">
          {intent?.primary_intent?.replace(/_/g, " ") || "NO INTENT"}
        </span>
      </div>

      <div className="space-y-3 text-xs">
        <div>
          <div className="flex justify-between mb-1">
            <span className="text-slate-300">Composite Threat Score</span>
            <span className="text-rose-400 font-bold">{threatScore}/100</span>
          </div>
          <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
            <div className="h-full bg-rose-500 transition-all duration-500" style={{ width: `${threatScore}%` }} />
          </div>
        </div>

        <div>
          <div className="flex justify-between mb-1">
            <span className="text-slate-300">Urgency & Coercion Index</span>
            <span className="text-amber-400 font-bold">{urgency}%</span>
          </div>
          <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
            <div className="h-full bg-amber-500 transition-all duration-500" style={{ width: `${urgency}%` }} />
          </div>
        </div>
      </div>

      {cues.length > 0 && (
        <div className="pt-2 border-t border-slate-800 space-y-1.5">
          <div className="text-[10px] uppercase text-slate-500">Flagged coercion / obfuscation cues</div>
          {cues.map((cue, idx) => (
            <div key={`${cue}-${idx}`} className="text-[11px] text-amber-200 bg-amber-950/20 border border-amber-800/40 rounded px-2 py-1">
              {cue}
            </div>
          ))}
        </div>
      )}

      {urls.length > 0 && (
        <div className="pt-2 border-t border-slate-800 space-y-1.5">
          <div className="text-[10px] uppercase text-slate-500">Suspicious URLs</div>
          {urls.map((url, idx) => (
            <div key={`${url.destination}-${idx}`} className="text-[11px] text-slate-300 bg-slate-950/50 border border-slate-800 rounded px-2 py-1">
              <span className={url.is_mismatch ? "text-rose-300" : "text-slate-300"}>
                {url.anchor_text}
              </span>
              <span className="text-slate-500"> → </span>
              <span className="text-cyan-300 break-all">{url.destination}</span>
              {url.domain && <span className="text-slate-500"> ({url.domain})</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default ThreatGauges;
