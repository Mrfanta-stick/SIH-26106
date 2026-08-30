'use client';

import React, { useEffect, useState } from 'react';
import dynamic from 'next/dynamic';
import { Globe2, Server, AlertOctagon } from 'lucide-react';
import { ForensicReport } from '../types/forensic';

// Dynamically import Leaflet components to prevent SSR window errors
const MapContainer = dynamic(
  () => import('react-leaflet').then((mod) => mod.MapContainer),
  { ssr: false }
);
const TileLayer = dynamic(
  () => import('react-leaflet').then((mod) => mod.TileLayer),
  { ssr: false }
);
const CircleMarker = dynamic(
  () => import('react-leaflet').then((mod) => mod.CircleMarker),
  { ssr: false }
);
const Popup = dynamic(
  () => import('react-leaflet').then((mod) => mod.Popup),
  { ssr: false }
);

interface ThreatMapProps {
  report: ForensicReport;
}

export const ThreatMap: React.FC<ThreatMapProps> = ({ report }) => {
  const [isMounted, setIsMounted] = useState(false);
  const { origin_network } = report;

  useEffect(() => {
    setIsMounted(true);
  }, []);

  return (
    <div className="rounded-2xl bg-[#12151c]/60 backdrop-blur-xl border border-white/10 p-6 shadow-2xl shadow-black/60 mb-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-5">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
            <Globe2 className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-bold tracking-tight uppercase text-white">
              Origin Geolocation & Infrastructure Telemetry
            </h2>
            <p className="text-xs text-slate-400">Physical routing origin & threat entity ASN</p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {origin_network.is_datacenter && (
            <span className="px-2.5 py-1 text-[11px] font-mono rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/25 flex items-center gap-1.5">
              <Server className="w-3 h-3" /> Datacenter / VPS IP
            </span>
          )}
          {origin_network.is_vpn_tor && (
            <span className="px-2.5 py-1 text-[11px] font-mono rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/25 flex items-center gap-1.5">
              <AlertOctagon className="w-3 h-3" /> VPN / Tor Relay
            </span>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        
        {/* Dark Mode Map View */}
        <div className="lg:col-span-2 h-[280px] bg-[#08090c] rounded-xl border border-white/10 overflow-hidden relative shadow-inner">
          {isMounted ? (
            <MapContainer
              center={[origin_network.latitude, origin_network.longitude]}
              zoom={5}
              style={{ height: '100%', width: '100%', backgroundColor: '#08090c' }}
              scrollWheelZoom={false}
            >
              <TileLayer
                attribution='Sources: Esri, HERE, Garmin, &copy; OpenStreetMap contributors, and the GIS User Community'
                url="https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}"
              />
              <CircleMarker
                center={[origin_network.latitude, origin_network.longitude]}
                radius={8}
                pathOptions={{
                  color: '#fb7185',
                  fillColor: '#f43f5e',
                  fillOpacity: 0.85,
                  weight: 3,
                }}
              >
                <Popup>
                  <div className="text-xs font-mono p-1">
                    <strong className="text-slate-900">{origin_network.ip}</strong><br />
                    <span className="text-slate-700">{origin_network.city}, {origin_network.country}</span><br />
                    <span className="text-slate-500 text-[10px]">{origin_network.org}</span>
                  </div>
                </Popup>
              </CircleMarker>
            </MapContainer>
          ) : (
            <div className="flex items-center justify-center h-full text-xs text-slate-500 font-mono">
              Loading GeoIP map...
            </div>
          )}
        </div>

        {/* IP & Domain Intelligence Data */}
        <div className="bg-[#08090c]/70 p-4 rounded-xl border border-white/5 flex flex-col justify-between text-xs font-mono space-y-3">
          <div>
            <span className="text-slate-400 uppercase tracking-wider text-[10px] font-semibold block mb-1">Origin Network</span>
            <div className="text-white font-bold text-sm tracking-wide">{origin_network.ip}</div>
            <div className="text-slate-400 text-[11px]">{origin_network.city}, {origin_network.country}</div>
          </div>

          <div className="pt-2.5 border-t border-white/5">
            <span className="text-slate-400 uppercase tracking-wider text-[10px] font-semibold block mb-1">ASN Organization</span>
            <div className="text-slate-200 text-[11px] font-medium">{origin_network.asn}</div>
            <div className="text-slate-400 text-[11px] truncate">{origin_network.org}</div>
          </div>

          <div className="pt-2.5 border-t border-white/5 space-y-1.5">
            <div className="flex justify-between items-center text-[11px]">
              <span className="text-slate-400">Entropy Score:</span>
              <span className="text-amber-400 font-bold bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20">{origin_network.domain_entropy}</span>
            </div>
            <div className="flex justify-between items-center text-[11px]">
              <span className="text-slate-400">Typosquat:</span>
              <span className="text-rose-400 font-bold">{origin_network.typosquat_target} <span className="text-slate-500 font-normal">({origin_network.edit_distance})</span></span>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
};