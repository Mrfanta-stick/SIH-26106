'use client';

import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  ShieldCheck, UploadCloud, ChevronRight, Download, ArrowRight,
  Terminal, Network, Fingerprint, Binary, AlertCircle, FileCheck
} from 'lucide-react';
import { ForensicReport } from './types/forensic';
import { CaseHeader } from './components/CaseHeader';
import { ThreatGauges } from './components/ThreatGauges';
import { ThreatMap } from './components/ThreatMap';
import { HopGraph } from './components/HopGraph';
import { AttachmentTriage } from './components/AttachmentTriage';
import { ChainOfCustody } from './components/ChainOfCustody';
import { AiVerdict } from './components/AiVerdict';
import { RawHeaders } from './components/RawHeaders';
import { ForensicScannerModal } from './components/ForensicScannerModal';
import { MitreMatrix } from './components/MitreMatrix';
import { DossierModal } from './components/DossierModal';
import { mockForensicReport } from './data/mockReport';
import { API_BASE, formatApiError } from './types/forensic';

function CyberTelemetryBackground() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);
    const gridSize = 60;
    const packetCount = 14;
    const packets = Array.from({ length: packetCount }, () => ({
      x: Math.floor((Math.random() * width) / gridSize) * gridSize,
      y: Math.floor((Math.random() * height) / gridSize) * gridSize,
      length: Math.random() * 24 + 10,
      speed: Math.random() * 1.5 + 0.8,
      isHorizontal: Math.random() > 0.5,
      color: Math.random() > 0.5 ? '#a855f7' : '#06b6d4',
    }));

    const handleResize = () => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };
    window.addEventListener('resize', handleResize);

    const render = () => {
      ctx.clearRect(0, 0, width, height);
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.02)';
      ctx.lineWidth = 1;
      for (let x = 0; x < width; x += gridSize) {
        ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, height); ctx.stroke();
      }
      for (let y = 0; y < height; y += gridSize) {
        ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(width, y); ctx.stroke();
      }
      for (const p of packets) {
        if (p.isHorizontal) {
          p.x += p.speed;
          if (p.x > width + p.length) { p.x = -p.length; p.y = Math.floor((Math.random() * height) / gridSize) * gridSize; }
          const grad = ctx.createLinearGradient(p.x - p.length, p.y, p.x, p.y);
          grad.addColorStop(0, 'rgba(0,0,0,0)'); grad.addColorStop(1, p.color);
          ctx.beginPath(); ctx.moveTo(p.x - p.length, p.y); ctx.lineTo(p.x, p.y); ctx.strokeStyle = grad; ctx.lineWidth = 1.5; ctx.stroke();
        } else {
          p.y += p.speed;
          if (p.y > height + p.length) { p.y = -p.length; p.x = Math.floor((Math.random() * width) / gridSize) * gridSize; }
          const grad = ctx.createLinearGradient(p.x, p.y - p.length, p.x, p.y);
          grad.addColorStop(0, 'rgba(0,0,0,0)'); grad.addColorStop(1, p.color);
          ctx.beginPath(); ctx.moveTo(p.x, p.y - p.length); ctx.lineTo(p.x, p.y); ctx.strokeStyle = grad; ctx.lineWidth = 1.5; ctx.stroke();
        }
      }
      animationFrameId = requestAnimationFrame(render);
    };

    render();
    return () => { window.removeEventListener('resize', handleResize); cancelAnimationFrame(animationFrameId); };
  }, []);

  return <canvas ref={canvasRef} className="fixed inset-0 pointer-events-none z-0 opacity-50" />;
}

type PageView = 'hero' | 'console' | 'ledger';
type TabType = 'triage' | 'network' | 'payload';

export default function ForensicApp() {
  const [report, setReport] = useState<ForensicReport | null>(null);
  const [currentView, setCurrentView] = useState<PageView>('hero');
  const [activeTab, setActiveTab] = useState<TabType>('triage');
  const [isDragging, setIsDragging] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [isDossierOpen, setIsDossierOpen] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isPreview, setIsPreview] = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (typeof window !== 'undefined' && new URLSearchParams(window.location.search).get('preview') === '1') {
      setIsPreview(true);
      setReport(mockForensicReport);
      setCurrentView('console');
    }
  }, []);

  const chooseFile = useCallback((file: File | null) => {
    if (!file) return;
    const valid = /\.(eml|msg)$/i.test(file.name);
    if (!valid) {
      setError('Please upload an .eml or .msg evidence file.');
      return;
    }
    setError(null);
    setSelectedFile(file);
  }, []);

  const startAnalysis = useCallback(() => {
    if (!selectedFile) {
      fileInputRef.current?.click();
      return;
    }
    setError(null);
    setIsScanning(true);
  }, [selectedFile]);

  const handleScanComplete = useCallback((nextReport: ForensicReport) => {
    setReport(nextReport);
    setIsPreview(false);
    setIsScanning(false);
    setCurrentView('console');
    setActiveTab('triage');
  }, []);

  const handleScanClose = useCallback(() => {
    setIsScanning(false);
  }, []);

  const handleScanError = useCallback((message: string) => {
    setError(message);
  }, []);

  const handleDownloadPDF = async () => {
    if (!report) return;
    const filename = `dossier_${report.case_id.slice(0, 8)}.pdf`;
    try {
      let response = await fetch(`${API_BASE}/api/case/${encodeURIComponent(report.case_id)}/export-pdf`);

      if (response.status === 404) {
        response = await fetch(`${API_BASE}/api/export-pdf`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(report),
        });
      }

      if (!response.ok) {
        let payload: unknown = null;
        try {
          payload = await response.json();
        } catch {
          payload = null;
        }
        throw new Error(formatApiError(payload, response.status));
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Export Error:', err);
      setIsDossierOpen(true);
    }
  };

  const resetToHero = () => setCurrentView('hero');

  const riskLabel = report
    ? report.threat_intent.risk_score >= 80 ? 'HIGH RISK' : report.threat_intent.risk_score >= 50 ? 'ELEVATED RISK' : 'LOW RISK'
    : 'NO CASE LOADED';

  return (
    <div className="relative min-h-screen bg-[#07060c] text-white selection:bg-purple-500/30 overflow-x-hidden font-sans">
      {isScanning && selectedFile && (
        <ForensicScannerModal file={selectedFile} onComplete={handleScanComplete} onError={handleScanError}
          onClose={handleScanClose}
        />
      )}

      {isDossierOpen && report && <DossierModal report={report} onClose={() => setIsDossierOpen(false)} />}

      <CyberTelemetryBackground />
      <div className="fixed top-[-140px] left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-gradient-to-b from-purple-700/20 via-indigo-600/10 to-transparent rounded-full blur-[140px] pointer-events-none -z-10" />

      <header className="max-w-5xl mx-auto pt-6 px-4 relative z-20">
        <div className="flex items-center justify-between px-5 py-2.5 rounded-full bg-white/[0.04] backdrop-blur-2xl border border-white/10 shadow-2xl">
          <div onClick={resetToHero} className="flex items-center gap-2.5 cursor-pointer group">
            <div className="w-7 h-7 rounded-full bg-gradient-to-tr from-purple-600 to-indigo-500 flex items-center justify-center shadow-[0_0_12px_rgba(147,51,234,0.6)]">
              <ShieldCheck className="w-3.5 h-3.5 text-white" />
            </div>
            <span className="font-bold text-xs sm:text-sm tracking-tight font-mono text-slate-100 group-hover:text-purple-300 transition-colors">
              SPECTRE<span className="text-purple-400">.DFIR</span>
            </span>
          </div>

          <nav className="flex items-center gap-1">
            <button onClick={resetToHero} className={`px-3.5 py-1.5 rounded-full text-xs font-medium transition-all ${currentView === 'hero' ? 'bg-white/15 text-white border border-white/20' : 'text-slate-400 hover:text-white hover:bg-white/5'}`}>Overview</button>
            <button disabled={!report} onClick={() => report && setCurrentView('console')} className={`px-3.5 py-1.5 rounded-full text-xs font-medium transition-all ${currentView === 'console' ? 'bg-purple-600/30 text-purple-300 border border-purple-500/40 shadow-[0_0_15px_rgba(147,51,234,0.3)]' : 'text-slate-400 hover:text-white hover:bg-white/5 disabled:opacity-40 disabled:cursor-not-allowed'}`}>Forensic Intel</button>
            <button disabled={!report} onClick={() => report && setCurrentView('ledger')} className={`px-3.5 py-1.5 rounded-full text-xs font-medium transition-all ${currentView === 'ledger' ? 'bg-purple-600/30 text-purple-300 border border-purple-500/40' : 'text-slate-400 hover:text-white hover:bg-white/5 disabled:opacity-40 disabled:cursor-not-allowed'}`}>Custody Ledger</button>
          </nav>

          <button disabled={!report} onClick={() => report && setCurrentView('console')} className="hidden sm:flex items-center gap-1.5 px-3.5 py-1.5 rounded-full text-xs font-medium bg-gradient-to-r from-purple-600 to-indigo-600 hover:brightness-110 transition-all shadow-[0_0_15px_rgba(147,51,234,0.4)] disabled:opacity-40 disabled:cursor-not-allowed">
            <span>Live Console</span><ChevronRight className="w-3 h-3" />
          </button>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-4 py-8 relative z-10">
        {isPreview && (
          <div className="mb-6 flex items-center justify-between gap-3 rounded-xl border border-cyan-500/25 bg-cyan-500/10 px-4 py-2.5 text-[11px] font-mono text-cyan-200">
            <span><strong className="text-cyan-300">PREVIEW MODE</strong> — showing bundled forensic sample data. No live backend analysis was performed.</span>
            <span className="text-cyan-400/70 shrink-0">preview=1</span>
          </div>
        )}
        {error && (
          <div role="alert" className="mb-6 flex items-start gap-3 rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-xs text-rose-200">
            <AlertCircle className="w-4 h-4 mt-0.5 text-rose-400 shrink-0" />
            <div><strong className="text-rose-300">Backend / upload error:</strong> {error}</div>
          </div>
        )}

        {currentView === 'hero' && (
          <div className="space-y-12 pt-6">
            <div className="text-center max-w-2xl mx-auto space-y-4">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-purple-500/10 border border-purple-500/25 text-purple-300 text-xs font-medium">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                <span className="uppercase tracking-wider text-[10px] font-mono font-bold">5-STAGE AUTONOMOUS DFIR PIPELINE</span>
              </div>
              <h1 className="text-4xl sm:text-5xl font-extrabold tracking-tight leading-tight text-white">
                Phishing Forensics, <br />
                <span className="bg-gradient-to-r from-purple-400 via-pink-400 to-indigo-400 bg-clip-text text-transparent">Deconstructed in Seconds.</span>
              </h1>
              <p className="text-slate-400 text-xs sm:text-sm leading-relaxed max-w-lg mx-auto">
                Trace transit MTA infrastructure, deconstruct masqueraded binaries, and generate tamper-proof chain-of-custody audit reports.
              </p>
            </div>

            <div className="max-w-xl mx-auto">
              <div
                onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
                onDragLeave={() => setIsDragging(false)}
                onDrop={(e) => { e.preventDefault(); setIsDragging(false); chooseFile(e.dataTransfer.files[0] || null); }}
                onClick={() => fileInputRef.current?.click()}
                className={`relative rounded-2xl bg-[#0e0c18]/90 backdrop-blur-xl border transition-all duration-300 p-5 shadow-2xl cursor-pointer ${isDragging ? 'border-purple-400 bg-purple-950/40 shadow-[0_0_30px_rgba(168,85,247,0.3)]' : 'border-white/15 hover:border-purple-500/40'}`}
              >
                <input ref={fileInputRef} type="file" accept=".eml,.msg,message/rfc822,application/vnd.ms-outlook" className="hidden" onChange={(e) => chooseFile(e.target.files?.[0] || null)} />
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div className="flex items-center gap-3 flex-1">
                    <div className="p-2.5 rounded-xl bg-purple-500/10 border border-purple-500/25 text-purple-300"><UploadCloud className="w-5 h-5" /></div>
                    <div className="text-left">
                      <div className="text-xs font-semibold text-white">Drop raw evidence file</div>
                      <div className="text-[11px] text-slate-400 font-mono">Supports <span className="text-slate-200">.eml</span> and <span className="text-slate-200">.msg</span></div>
                      {selectedFile && <div className="mt-1 inline-flex items-center gap-1 text-[10px] text-emerald-400 font-mono"><FileCheck className="w-3 h-3" />{selectedFile.name}</div>}
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={(e) => { e.stopPropagation(); startAnalysis(); }}
                    disabled={!selectedFile || isScanning}
                    className="flex items-center justify-center gap-1.5 px-4 py-2 rounded-xl bg-white/10 hover:bg-purple-600 border border-white/10 hover:border-purple-400 text-xs font-semibold transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                  >
                    <span>Analyze Evidence</span><ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-4">
              <div className="p-5 rounded-2xl bg-white/[0.02] border border-white/5 space-y-2 hover:border-white/10 transition-colors"><div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 flex items-center justify-center mb-3"><Network className="w-4 h-4" /></div><h3 className="text-xs font-bold font-mono uppercase text-white tracking-wide">Network Reconstruction</h3><p className="text-[11px] text-slate-400 leading-relaxed">Extracts originating infrastructure and enriches it with GeoIP and ASN telemetry.</p></div>
              <div className="p-5 rounded-2xl bg-white/[0.02] border border-white/5 space-y-2 hover:border-white/10 transition-colors"><div className="w-8 h-8 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 flex items-center justify-center mb-3"><Binary className="w-4 h-4" /></div><h3 className="text-xs font-bold font-mono uppercase text-white tracking-wide">Payload Intelligence</h3><p className="text-[11px] text-slate-400 leading-relaxed">Extracts attachments and records MIME/signature information returned by the backend.</p></div>
              <div className="p-5 rounded-2xl bg-white/[0.02] border border-white/5 space-y-2 hover:border-white/10 transition-colors"><div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center mb-3"><Fingerprint className="w-4 h-4" /></div><h3 className="text-xs font-bold font-mono uppercase text-white tracking-wide">Evidence Integrity</h3><p className="text-[11px] text-slate-400 leading-relaxed">Displays the SHA-256 digest and custody record generated during evidence intake.</p></div>
            </div>
          </div>
        )}

        {currentView === 'console' && report && (
          <div className="space-y-6">
            <div className="flex items-center gap-4 px-4 py-2 rounded-xl bg-[#0b0d13]/80 border border-white/5 text-[11px] font-mono overflow-x-auto no-scrollbar shadow-inner text-slate-400">
              <div className="flex items-center gap-1.5 text-cyan-400 shrink-0 font-bold"><Terminal className="w-3.5 h-3.5" /><span>TELEMETRY:</span></div>
              <span className="shrink-0">MTA HOPS: <strong className="text-white">{report.graph_topology?.nodes?.length || '—'}</strong></span><span className="text-slate-600">•</span>
              <span className="shrink-0">RISK: <strong className={report.threat_intent.risk_score >= 50 ? 'text-rose-400' : 'text-emerald-400'}>{report.threat_intent.risk_score}/100</strong></span><span className="text-slate-600">•</span>
              <span className="shrink-0">DKIM: <strong className={report.protocol_forensics.dkim === 'PASS' ? 'text-emerald-400' : 'text-rose-400'}>{report.protocol_forensics.dkim}</strong></span><span className="text-slate-600">•</span>
              <span className="shrink-0">ENTROPY: <strong className="text-amber-400">{report.origin_network?.domain_entropy?.toFixed(2) ?? '0.00'}</strong></span><span className="text-slate-600">•</span>
              <span className="shrink-0">CASE: <strong className="text-emerald-400">{riskLabel}</strong></span>
            </div>

            <CaseHeader report={report} onOpenDossier={() => setIsDossierOpen(true)} onExportReport={handleDownloadPDF} />
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 pb-4">
              <div className="flex flex-wrap gap-2">
                {(['triage', 'network', 'payload'] as TabType[]).map((tab) => <button key={tab} onClick={() => setActiveTab(tab)} className={`px-3.5 py-1.5 rounded-lg text-[11px] font-mono uppercase transition-all ${activeTab === tab ? 'bg-purple-600/20 text-purple-300 border border-purple-500/40' : 'bg-white/[0.03] text-slate-400 border border-white/5 hover:text-white'}`}>{tab}</button>)}
              </div>
              <button onClick={handleDownloadPDF} className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-mono text-slate-300 transition-all"><Download className="w-3.5 h-3.5 text-purple-400" /><span>Export Court Dossier</span></button>
            </div>

            {activeTab === 'triage' && <div className="space-y-6"><AiVerdict report={report} /><ThreatGauges report={report} /><MitreMatrix report={report} /></div>}
            {activeTab === 'network' && <div className="space-y-6"><ThreatMap report={report} /><HopGraph report={report} /></div>}
            {activeTab === 'payload' && <div className="space-y-6"><AttachmentTriage report={report} /><RawHeaders report={report} /></div>}
          </div>
        )}

        {currentView === 'ledger' && report && <div className="space-y-6"><ChainOfCustody report={report} /></div>}
      </main>
    </div>
  );
}