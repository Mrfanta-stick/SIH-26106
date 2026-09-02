// @ts-nocheck
"use client";

import { ForensicReport } from "../types/forensic";

export interface ThreatGaugesProps {
  report?: ForensicReport | any;
  threatIntent?: any;
}

export function ThreatGauges({ report, threatIntent }: ThreatGaugesProps) {
  const intent = threatIntent || report?.threat_intent || {};
  const threatScore = intent.threat_score ?? 92;
  const urgency = intent.urgency_score ?? 85;

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4 backdrop-blur-sm font-mono">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-amber-400 animate-pulse" />
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
            Social Engineering & Threat Intent Gauges
          </h3>
        </div>
        <span className="text-[10px] text-slate-500">NLP COGNITIVE ANALYSIS</span>
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
    </div>
  );
}

export default ThreatGauges;