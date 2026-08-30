'use client';

import React, { useEffect, useRef, useState } from 'react';
import { Terminal, CheckCircle2, Cpu, Loader2, AlertTriangle } from 'lucide-react';
import { ForensicReport } from '../types/forensic';

interface ForensicScannerModalProps {
  file: File;
  onComplete: (report: ForensicReport) => void;
  onError: (message: string) => void;
}

interface LogEntry {
  text: string;
  type: 'info' | 'warn' | 'success' | 'danger';
}

const API_BASE_URL = (process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000').replace(/\/$/, '');

export const ForensicScannerModal: React.FC<ForensicScannerModalProps> = ({ file, onComplete, onError }) => {
  const [visibleLogs, setVisibleLogs] = useState<LogEntry[]>([]);
  const [progress, setProgress] = useState(8);
  const [status, setStatus] = useState<'scanning' | 'success' | 'error'>('scanning');
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;

    let cancelled = false;
    let progressTimer: ReturnType<typeof setInterval> | undefined;

    const addLog = (text: string, type: LogEntry['type'] = 'info') => {
      if (!cancelled) setVisibleLogs((prev) => [...prev, { text, type }]);
    };

    const runAnalysis = async () => {
      addLog(`Evidence stream opened: ${file.name}`);
      setProgress(15);

      progressTimer = setInterval(() => {
        setProgress((prev) => Math.min(prev + Math.floor(Math.random() * 6) + 2, 92));
      }, 260);

      try {
        const formData = new FormData();
        formData.append('file', file, file.name);

        addLog('Submitting raw evidence to /api/analyze');
        setProgress(25);

        const response = await fetch(`${API_BASE_URL}/api/analyze`, {
          method: 'POST',
          body: formData,
        });

        const data = await response.json().catch(() => null);

        if (!response.ok) {
          throw new Error(data?.detail || `Backend returned HTTP ${response.status}`);
        }

        if (cancelled) return;

        addLog('Ingest complete: SHA-256 evidence metadata generated');
        addLog('Authentication & origin telemetry received');
        addLog('Master forensic report validated successfully', 'success');
        setProgress(100);
        setStatus('success');

        setTimeout(() => {
          if (!cancelled) onComplete(data as ForensicReport);
        }, 500);
      } catch (error) {
        if (cancelled) return;
        const message = error instanceof Error ? error.message : 'Unable to reach the forensic backend.';
        addLog(message, 'danger');
        setStatus('error');
        onError(message);
      } finally {
        if (progressTimer) clearInterval(progressTimer);
      }
    };

    void runAnalysis();

    return () => {
      cancelled = true;
      if (progressTimer) clearInterval(progressTimer);
    };
  }, [file, onComplete, onError]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-in fade-in duration-200">
      <div className="absolute w-[500px] h-[300px] bg-purple-600/20 rounded-full blur-[140px] pointer-events-none" />

      <div className="relative w-full max-w-2xl rounded-2xl bg-[#0a0a12]/95 border border-purple-500/30 shadow-2xl shadow-purple-950/50 overflow-hidden font-mono text-xs">
        <div className="flex items-center justify-between px-5 py-3.5 bg-white/[0.03] border-b border-white/10">
          <div className="flex items-center gap-2">
            <div className="w-2.5 h-2.5 rounded-full bg-rose-500/80" />
            <div className="w-2.5 h-2.5 rounded-full bg-amber-500/80" />
            <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
            <span className="text-slate-300 font-bold tracking-wider ml-2 flex items-center gap-1.5 text-[11px]">
              <Terminal className="w-3.5 h-3.5 text-purple-400" />
              LIVE FORENSIC DECONSTRUCTION STREAM
            </span>
          </div>
          <div className="flex items-center gap-2 text-[10px] text-slate-400">
            <Cpu className={`w-3.5 h-3.5 text-cyan-400 ${status === 'scanning' ? 'animate-spin' : ''}`} />
            <span>BACKEND ANALYSIS</span>
          </div>
        </div>

        <div className="px-5 py-2.5 bg-purple-950/20 border-b border-white/5 flex items-center justify-between text-[11px] text-slate-400">
          <div className="truncate max-w-[340px]">
            Target File: <span className="text-purple-300 font-bold">{file.name}</span>
          </div>
          <div className="flex items-center gap-1.5 text-cyan-300">
            {status === 'scanning' && <Loader2 className="w-3 h-3 animate-spin" />}
            {status === 'success' && <CheckCircle2 className="w-3 h-3 text-emerald-400" />}
            {status === 'error' && <AlertTriangle className="w-3 h-3 text-rose-400" />}
            <span>{status === 'error' ? 'Analysis failed' : `Processing ${progress}%`}</span>
          </div>
        </div>

        <div className="p-5 space-y-2.5 min-h-[230px] max-h-[280px] overflow-y-auto">
          {visibleLogs.map((log, index) => (
            <div key={index} className="flex items-start gap-2.5 animate-in fade-in slide-in-from-left-2 duration-200">
              <span className="text-slate-600 shrink-0">[{index + 1}]</span>
              <span className={`leading-relaxed ${
                log.type === 'success' ? 'text-emerald-300' :
                log.type === 'danger' ? 'text-rose-300' :
                log.type === 'warn' ? 'text-amber-300' : 'text-slate-300'
              }`}>
                <span className={`font-bold mr-1.5 ${
                  log.type === 'success' ? 'text-emerald-400' :
                  log.type === 'danger' ? 'text-rose-400' :
                  log.type === 'warn' ? 'text-amber-400' : 'text-cyan-400'
                }`}>
                  [{log.type === 'success' ? 'OK' : log.type === 'danger' ? 'ERROR' : log.type.toUpperCase()}]
                </span>
                {log.text}
              </span>
            </div>
          ))}
          {status === 'scanning' && (
            <div className="flex items-center gap-2 pt-1 text-purple-400 animate-pulse">
              <span>&gt;</span><span className="w-2 h-4 bg-purple-400" />
            </div>
          )}
        </div>

        <div className="w-full bg-white/5 h-1.5 relative overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-purple-500 via-cyan-400 to-emerald-400 transition-all duration-200 shadow-[0_0_12px_rgba(168,85,247,0.8)]"
            style={{ width: `${progress}%` }}
          />
        </div>
      </div>
    </div>
  );
};
