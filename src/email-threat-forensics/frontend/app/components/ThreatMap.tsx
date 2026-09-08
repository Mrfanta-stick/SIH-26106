"use client";

import { useMemo, useState, useEffect } from "react";
import dynamic from "next/dynamic";
import "leaflet/dist/leaflet.css";
import { Globe2, Server, AlertOctagon, MapPin, ChevronDown, ChevronUp } from "lucide-react";
import { ForensicReport } from "../types/forensic";

// Dynamically import Leaflet components to prevent Next.js SSR window errors
const MapContainer = dynamic(
  () => import("react-leaflet").then((mod) => mod.MapContainer),
  { ssr: false }
);
const TileLayer = dynamic(
  () => import("react-leaflet").then((mod) => mod.TileLayer),
  { ssr: false }
);
const CircleMarker = dynamic(
  () => import("react-leaflet").then((mod) => mod.CircleMarker),
  { ssr: false }
);
const Popup = dynamic(
  () => import("react-leaflet").then((mod) => mod.Popup),
  { ssr: false }
);

// Resolve Carto API Key from environment variables
const CARTO_API_KEY = process.env.NEXT_PUBLIC_CARTO_API_KEY?.trim() || "";

// If teammate provides an API key, use Carto; otherwise fallback to Esri Dark Canvas (clean dark mode, zero watermarks)
const TILE_URL = CARTO_API_KEY
  ? `https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png?api_key=${CARTO_API_KEY}`
  : "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}";

const TILE_ATTRIBUTION = CARTO_API_KEY
  ? '&copy; <a href="https://carto.com/">CARTO</a>'
  : '&copy; <a href="https://www.esri.com/">Esri</a>';

export interface GeoHop {
  id?: string;
  ip?: string;
  country?: string;
  city?: string;
  lat?: number;
  lng?: number;
  asn?: string;
  org?: string;
  suspicious?: boolean;
  is_vpn_tor?: boolean;
  is_datacenter?: boolean;
  typosquat_target?: string | null;
}

export interface ThreatMapProps {
  report?: ForensicReport | null;
  hops?: GeoHop[];
}

export function ThreatMap({ report, hops }: ThreatMapProps) {
  const [isMounted, setIsMounted] = useState(false);
  const [showMap, setShowMap] = useState(false);
  const origin = report?.origin_network;

  useEffect(() => {
    setIsMounted(true);
  }, []);

  const activeHops: GeoHop[] = useMemo(() => {
    if (hops?.length) return hops;
    if (!origin?.ip) return [];
    return [
      {
        id: "origin",
        ip: origin.ip,
        country: origin.country,
        city: origin.city,
        lat: origin.latitude,
        lng: origin.longitude,
        asn: origin.asn,
        org: origin.org,
        suspicious: Boolean(origin.is_vpn_tor || origin.is_datacenter),
        is_vpn_tor: origin.is_vpn_tor,
        is_datacenter: origin.is_datacenter,
        typosquat_target: origin.typosquat_target,
      },
    ];
  }, [hops, origin]);

  const [selectedHop, setSelectedHop] = useState<GeoHop | null>(null);

  const mapCenter: [number, number] = useMemo(() => {
    if (origin?.latitude && origin?.longitude && (origin.latitude !== 0 || origin.longitude !== 0)) {
      return [origin.latitude, origin.longitude];
    }
    const hopWithCoords = activeHops.find((h) => h.lat && h.lng && (h.lat !== 0 || h.lng !== 0));
    if (hopWithCoords && hopWithCoords.lat && hopWithCoords.lng) {
      return [hopWithCoords.lat, hopWithCoords.lng];
    }
    return [20.5937, 78.9629];
  }, [origin, activeHops]);

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4 backdrop-blur-sm font-mono">
      {/* Header Bar with Show/Hide Map Button */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <Globe2 className="h-4 w-4 text-cyan-400 animate-pulse" />
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
            Origin Network & Geo-IP Trajectory
          </h3>
        </div>

        <div className="flex items-center gap-2">
          {origin?.is_datacenter && (
            <span className="hidden sm:inline-flex px-2 py-0.5 text-[10px] font-mono rounded bg-rose-500/10 text-rose-400 border border-rose-500/30 items-center gap-1">
              <Server className="w-3 h-3" /> Datacenter IP
            </span>
          )}
          {origin?.is_vpn_tor && (
            <span className="hidden sm:inline-flex px-2 py-0.5 text-[10px] font-mono rounded bg-amber-500/10 text-amber-400 border border-amber-500/30 items-center gap-1">
              <AlertOctagon className="w-3 h-3" /> VPN / Relay
            </span>
          )}

          {/* Toggle Map Button */}
          <button
            type="button"
            onClick={() => setShowMap((prev) => !prev)}
            className="flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-semibold font-mono bg-cyan-500/10 border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/20 hover:border-cyan-400 transition-all shadow-[0_0_12px_rgba(6,182,212,0.2)] active:scale-95"
          >
            <Globe2 className="w-3.5 h-3.5" />
            <span>{showMap ? "HIDE MAP" : "SHOW MAP"}</span>
            {showMap ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      {activeHops.length === 0 ? (
        <div className="py-8 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-lg">
          No origin IP enrichment returned by the backend.
        </div>
      ) : (
        <div className="space-y-4">
          {/* Collapsible Map Section */}
          {showMap ? (
            <div className="h-[290px] w-full rounded-lg border border-cyan-500/30 bg-[#08090c] overflow-hidden relative shadow-inner transition-all duration-300">
              {isMounted ? (
                <MapContainer
                  key={`map-${mapCenter[0]}-${mapCenter[1]}`}
                  center={mapCenter}
                  zoom={3}
                  style={{ height: "100%", width: "100%", backgroundColor: "#08090c" }}
                  scrollWheelZoom={false}
                >
                  <TileLayer
                    attribution={TILE_ATTRIBUTION}
                    url={TILE_URL}
                  />

                  {activeHops.map((hop, idx) => {
                    if (!hop.lat || !hop.lng || (hop.lat === 0 && hop.lng === 0)) return null;

                    const isSuspicious = hop.suspicious;
                    return (
                      <CircleMarker
                        key={hop.id || `marker-${idx}`}
                        center={[hop.lat, hop.lng]}
                        radius={8}
                        pathOptions={{
                          color: isSuspicious ? "#f43f5e" : "#06b6d4",
                          fillColor: isSuspicious ? "#fb7185" : "#22d3ee",
                          fillOpacity: 0.85,
                          weight: 2,
                        }}
                      >
                        <Popup className="text-slate-900 font-mono">
                          <div className="text-xs p-1">
                            <strong className="block text-slate-900 border-b pb-1 mb-1">
                              {hop.ip || "Unknown IP"}
                            </strong>
                            <div>
                              {hop.city ? `${hop.city}, ` : ""}
                              {hop.country || "Unknown Country"}
                            </div>
                            <div className="text-[10px] text-slate-600 mt-1">
                              {hop.org || hop.asn || "No ASN recorded"}
                            </div>
                            {isSuspicious && (
                              <div className="text-[10px] text-rose-600 font-bold mt-1">
                                ⚠ ANOMALOUS HOSTING DETECTED
                              </div>
                            )}
                          </div>
                        </Popup>
                      </CircleMarker>
                    );
                  })}
                </MapContainer>
              ) : (
                <div className="flex items-center justify-center h-full text-xs text-slate-500 font-mono">
                  Initializing dark-mode telemetry map...
                </div>
              )}
            </div>
          ) : (
            <div 
              onClick={() => setShowMap(true)}
              className="p-3.5 rounded-lg border border-dashed border-slate-800 bg-slate-950/40 hover:border-cyan-500/40 hover:bg-cyan-950/10 cursor-pointer flex items-center justify-between text-xs transition-all group"
            >
              <div className="flex items-center gap-2 text-slate-400 group-hover:text-slate-200">
                <Globe2 className="w-4 h-4 text-cyan-400" />
                <span>Geographic map view collapsed to save layout space.</span>
              </div>
              <span className="text-[11px] font-semibold text-cyan-400 underline underline-offset-4 group-hover:text-cyan-300">
                Click to Expand Map →
              </span>
            </div>
          )}

          {/* Node Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {activeHops.map((hop: GeoHop, idx: number) => {
              const nodeKey = hop.id || hop.ip || `hop-${idx}`;
              const isSelected = selectedHop?.ip === hop.ip && Boolean(hop.ip);

              return (
                <div
                  key={nodeKey}
                  onClick={() => setSelectedHop(isSelected ? null : hop)}
                  className={`p-3 rounded-lg border text-xs cursor-pointer transition-all ${
                    hop.suspicious
                      ? "border-rose-500/40 bg-rose-950/20 hover:border-rose-400/60"
                      : "border-slate-800 bg-slate-950/40 hover:border-slate-700"
                  } ${
                    isSelected ? "ring-1 ring-cyan-400 border-cyan-400/80" : ""
                  }`}
                >
                  <div className="flex items-center justify-between gap-1 mb-1.5">
                    <span className="text-[10px] text-slate-500">
                      NODE #{String(idx + 1).padStart(2, "0")}
                    </span>
                    {hop.suspicious && (
                      <span className="text-[9px] px-1.5 py-0.5 bg-rose-950 border border-rose-800 text-rose-300 rounded font-semibold">
                        {hop.is_vpn_tor
                          ? "VPN/TOR"
                          : hop.is_datacenter
                          ? "DATACENTER"
                          : "ANOMALOUS"}
                      </span>
                    )}
                  </div>

                  <div className="font-semibold text-slate-200 truncate flex items-center gap-1.5">
                    <MapPin className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                    <span>{hop.ip || "Unknown IP"}</span>
                  </div>

                  <div className="text-[11px] text-slate-400 mt-1 flex items-center justify-between">
                    <span>
                      {hop.city ? `${hop.city}, ` : ""}
                      {hop.country || "Unknown Origin"}
                    </span>
                    <span className="text-slate-500 text-[10px]">
                      {hop.asn || ""}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Selected Node Details Drawer */}
          {selectedHop && (
            <div className="p-3.5 rounded-lg border border-cyan-500/30 bg-slate-950/80 text-xs text-slate-300 space-y-1.5">
              <div className="text-[10px] uppercase tracking-wider text-cyan-400 font-semibold mb-1">
                Routing Node Telemetry Detail
              </div>
              <div className="grid grid-cols-2 gap-2 text-[11px]">
                <div>
                  <span className="text-slate-500">IP Address:</span>{" "}
                  {selectedHop.ip || "N/A"}
                </div>
                <div>
                  <span className="text-slate-500">Organization / ISP:</span>{" "}
                  {selectedHop.org || selectedHop.asn || "N/A"}
                </div>
                <div>
                  <span className="text-slate-500">Location:</span>{" "}
                  {selectedHop.city ? `${selectedHop.city}, ` : ""}
                  {selectedHop.country || "N/A"}
                </div>
                <div>
                  <span className="text-slate-500">Coordinates:</span>{" "}
                  {typeof selectedHop.lat === "number" &&
                  typeof selectedHop.lng === "number"
                    ? `${selectedHop.lat.toFixed(4)}, ${selectedHop.lng.toFixed(4)}`
                    : "N/A"}
                </div>
                {selectedHop.typosquat_target && (
                  <div className="col-span-2">
                    <span className="text-slate-500">Typosquat target:</span>{" "}
                    {selectedHop.typosquat_target}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default ThreatMap;