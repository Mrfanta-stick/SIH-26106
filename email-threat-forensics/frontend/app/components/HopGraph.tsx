'use client';

import React, { useState } from 'react';
import { Network, Server, ArrowRight, ShieldAlert, ShieldCheck, Clock, Zap, Cpu } from 'lucide-react';
import { ForensicReport } from '../types/forensic';

interface HopGraphProps {
  report: ForensicReport;
}

export const HopGraph: React.FC<HopGraphProps> = ({ report }) => {
  const [selectedHop, setSelectedHop] = useState<number>(0);

  const backendNodes = report.graph_topology.nodes;
  const backendEdges = report.graph_topology.edges;
  const hopsData = backendNodes.length > 0
    ? backendNodes.map((node, index) => ({
        id: index + 1,
        name: node.label,
        ip: node.type === 'ip' ? node.label : report.origin_network.ip,
        host: node.label,
        asn: node.type === 'asn' ? node.label : report.origin_network.asn,
        location: `${report.origin_network.city}, ${report.origin_network.country}`,
        delay: backendEdges[index - 1]?.latency || (index === 0 ? '0 ms (Origin)' : '—'),
        status: index === 0 ? 'ORIGIN' : node.type.toUpperCase(),
        statusColor: index === 0 ? 'text-rose-400 bg-rose-500/10 border-rose-500/30' : 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30',
        iconColor: index === 0 ? 'from-rose-500 to-red-600 shadow-rose-500/50' : 'from-cyan-500 to-indigo-600 shadow-cyan-500/50',
      }))
    : [{
        id: 1,
        name: 'Origin Network',
        ip: report.origin_network.ip,
        host: report.origin_network.org || 'Unknown network',
        asn: report.origin_network.asn,
        location: `${report.origin_network.city}, ${report.origin_network.country}`,
        delay: '0 ms (Origin)',
        status: 'BACKEND ORIGIN',
        statusColor: 'text-rose-400 bg-rose-500/10 border-rose-500/30',
        iconColor: 'from-rose-500 to-red-600 shadow-rose-500/50',
      }];

  return (
    <div className="rounded-2xl bg-[#12151c]/60 backdrop-blur-xl border border-white/10 p-6 shadow-2xl shadow-black/60 mb-6">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-6">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400">
            <Network className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-bold tracking-tight uppercase text-white font-mono">
              MTA Transit Topology & Laser Hop Tracing
            </h2>
            <p className="text-xs text-slate-400">Received header vector analysis with calculated propagation delay</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="px-3 py-1 text-[11px] font-mono rounded-full bg-purple-500/10 text-purple-300 border border-purple-500/25 flex items-center gap-1.5">
            <Zap className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
            {backendNodes.length || 1} Backend Node{(backendNodes.length || 1) === 1 ? '' : 's'}
          </span>
        </div>
      </div>

      {/* Interactive Laser Vector Pathway */}
      <div className="relative py-8 px-4 bg-[#08090c]/80 rounded-2xl border border-white/5 mb-6 overflow-hidden">
        
        {/* Animated Laser Tracks (SVG Vector Overlay) */}
        <div className="hidden md:block absolute top-[52px] left-[15%] right-[15%] h-1 z-0">
          <svg className="w-full h-12 overflow-visible" preserveAspectRatio="none">
            <defs>
              <linearGradient id="laserGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="#f43f5e" />
                <stop offset="50%" stopColor="#f59e0b" />
                <stop offset="100%" stopColor="#10b981" />
              </linearGradient>
            </defs>

            {/* Base Wire Track */}
            <line 
              x1="0" y1="0" x2="100%" y2="0" 
              stroke="rgba(255, 255, 255, 0.1)" 
              strokeWidth="2" 
              strokeDasharray="6 6" 
            />

            {/* Glowing Laser Conduit */}
            <line 
              x1="0" y1="0" x2="100%" y2="0" 
              stroke="url(#laserGrad)" 
              strokeWidth="2.5" 
              strokeDasharray="18 120"
              className="animate-[dash_3s_linear_infinite]"
            >
              <animate 
                attributeName="stroke-dashoffset" 
                from="200" 
                to="0" 
                dur="2.5s" 
                repeatCount="indefinite" 
              />
            </line>
          </svg>
        </div>

        {/* 3 Node Markers */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 relative z-10">
          {hopsData.map((hop, index) => {
            const isSelected = selectedHop === index;
            return (
              <div
                key={hop.id}
                onClick={() => setSelectedHop(index)}
                className={`p-4 rounded-xl transition-all duration-300 cursor-pointer border flex flex-col items-center text-center relative ${
                  isSelected
                    ? 'bg-white/[0.06] border-purple-500/50 shadow-[0_0_20px_rgba(168,85,247,0.25)] scale-[1.02]'
                    : 'bg-[#0d0c18]/80 border-white/5 hover:border-white/20 hover:bg-white/[0.02]'
                }`}
              >
                {/* Node Orb with Glow */}
                <div className={`w-12 h-12 rounded-2xl bg-gradient-to-tr ${hop.iconColor} flex items-center justify-center text-white shadow-lg mb-3`}>
                  <Server className="w-5 h-5" />
                </div>

                <div className="space-y-1">
                  <div className="flex items-center justify-center gap-1.5">
                    <span className="text-[10px] font-mono font-bold text-slate-400 uppercase">HOP 0{hop.id}</span>
                  </div>
                  <div className="text-xs font-bold text-white font-mono tracking-tight">{hop.name}</div>
                  <div className="text-[11px] font-mono text-purple-300">{hop.ip}</div>
                </div>

                <div className="mt-3 w-full pt-3 border-t border-white/5 flex items-center justify-between text-[10px] font-mono text-slate-400">
                  <span className="flex items-center gap-1">
                    <Clock className="w-3 h-3 text-cyan-400" />
                    {hop.delay}
                  </span>
                  <span className={`px-2 py-0.5 rounded-full border text-[9px] font-bold ${hop.statusColor}`}>
                    {hop.status}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Selected Hop Detailed Inspection Tray */}
      <div className="p-4 rounded-xl bg-[#08090c]/90 border border-white/10 text-xs font-mono">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-white/5">
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <span className="text-white font-bold">NODE TELEMETRY INSPECTOR:</span>
            <span className="text-purple-300 font-semibold">{hopsData[selectedHop].host}</span>
          </div>
          <span className="text-slate-400 text-[11px]">ASN: {hopsData[selectedHop].asn}</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-3 text-[11px]">
          <div>
            <span className="text-slate-500 block mb-0.5">Physical Geolocation:</span>
            <span className="text-slate-200 font-semibold">{hopsData[selectedHop].location}</span>
          </div>
          <div>
            <span className="text-slate-500 block mb-0.5">Hop Cumulative Latency:</span>
            <span className="text-cyan-400 font-semibold">{hopsData[selectedHop].delay}</span>
          </div>
          <div>
            <span className="text-slate-500 block mb-0.5">MTA Trust Classification:</span>
            <span className={selectedHop === 0 ? "text-rose-400 font-bold" : "text-emerald-400 font-bold"}>
              {selectedHop === 0 ? "SUSPICIOUS INGRESS" : "VERIFIED INTERNAL"}
            </span>
          </div>
        </div>
      </div>

    </div>
  );
};