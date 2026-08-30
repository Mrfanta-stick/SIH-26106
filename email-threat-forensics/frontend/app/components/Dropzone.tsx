'use client';

import React, { useState } from 'react';
import { UploadCloud, FileCheck, Loader2 } from 'lucide-react';

interface DropzoneProps {
  onAnalyze?: () => void;
}

export const Dropzone: React.FC<DropzoneProps> = ({ onAnalyze }) => {
  const [isDragging, setIsDragging] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);

  const handleSimulateUpload = (name: string) => {
    setFileName(name);
    setAnalyzing(true);
    // Simulate pipeline analysis timing
    setTimeout(() => {
      setAnalyzing(false);
      if (onAnalyze) onAnalyze();
    }, 1500);
  };

  return (
    <div className="rounded-2xl bg-[#12151c]/60 backdrop-blur-xl border border-white/10 p-5 shadow-2xl shadow-black/60">
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setIsDragging(true);
        }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setIsDragging(false);
          const file = e.dataTransfer.files[0];
          if (file) handleSimulateUpload(file.name);
        }}
        onClick={() => handleSimulateUpload('suspicious_invoice.eml')}
        className={`group relative border border-dashed rounded-xl p-8 flex flex-col items-center justify-center cursor-pointer transition-all duration-300 ${
          isDragging 
            ? 'border-emerald-400 bg-emerald-500/10 shadow-lg shadow-emerald-500/10' 
            : 'border-white/10 bg-[#08090c]/50 hover:border-emerald-500/40 hover:bg-[#08090c]/80 hover:shadow-lg hover:shadow-emerald-950/20'
        }`}
      >
        {analyzing ? (
          <div className="flex flex-col items-center space-y-3 py-2">
            <div className="p-3 bg-emerald-500/10 rounded-2xl border border-emerald-500/20 shadow-inner">
              <Loader2 className="w-7 h-7 text-emerald-400 animate-spin" />
            </div>
            <div className="text-center">
              <p className="text-xs font-semibold text-white tracking-tight">Running 5-Stage Forensics Engine...</p>
              <p className="text-[11px] text-slate-400 font-medium mt-1 tracking-tight">
                Hashing SHA-256 • Tracing MTAs • Classifying NLP Intent
              </p>
            </div>
          </div>
        ) : (
          <div className="flex flex-col items-center space-y-3 text-center">
            <div className="p-3.5 bg-white/[0.03] group-hover:bg-emerald-500/10 rounded-2xl border border-white/10 group-hover:border-emerald-500/30 transition-all duration-300 shadow-sm">
              <UploadCloud className="w-6 h-6 text-slate-400 group-hover:text-emerald-400 transition-colors" />
            </div>
            <div>
              <div className="text-xs font-medium text-slate-200">
                <span className="text-emerald-400 font-semibold hover:underline">Click to upload</span> or drag and drop raw evidence
              </div>
              <p className="text-[11px] text-slate-400 mt-1">
                Supports RFC 5322 <span className="text-slate-300 font-mono">.eml</span> and MAPI <span className="text-slate-300 font-mono">.msg</span> payloads
              </p>
            </div>
            {fileName && (
              <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-[11px] font-medium text-emerald-400">
                <FileCheck className="w-3.5 h-3.5" />
                <span>Loaded: {fileName}</span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};