"use client";

import { useMemo, useState } from "react";
import { ForensicReport } from "../types/forensic";

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
  const origin = report?.origin_network;
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

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4 backdrop-blur-sm font-mono">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse" />
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
            Origin Network & Geo-IP Trajectory
          </h3>
        </div>
        <span className="text-[10px] text-slate-500">
          ORIGIN NODES: {activeHops.length}
        </span>
      </div>

      {activeHops.length === 0 ? (
        <div className="py-8 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-lg">
          No origin IP enrichment returned by the backend.
        </div>
      ) : (
        <div className="space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {activeHops.map((hop: GeoHop, idx: number) => {
              const nodeKey = hop.id || hop.ip || `hop-${idx}`;
              const isSelected =
                selectedHop?.ip === hop.ip && Boolean(hop.ip);

              return (
                <div
                  key={nodeKey}
                  onClick={() => setSelectedHop(isSelected ? null : hop)}
                  className={`p-3 rounded-lg border text-xs cursor-pointer transition-all ${
                    hop.suspicious
                      ? "border-rose-500/40 bg-rose-950/20 hover:border-rose-400/60"
                      : "border-slate-800 bg-slate-950/40 hover:border-slate-700"
                  } ${
                    isSelected
                      ? "ring-1 ring-cyan-400 border-cyan-400/80"
                      : ""
                  }`}
                >
                  <div className="flex items-center justify-between gap-1 mb-1.5">
                    <span className="text-[10px] text-slate-500">
                      NODE #{String(idx + 1).padStart(2, "0")}
                    </span>
                    {hop.suspicious && (
                      <span className="text-[9px] px-1.5 py-0.2 bg-rose-950 border border-rose-800 text-rose-300 rounded font-semibold">
                        {hop.is_vpn_tor ? "VPN/TOR" : hop.is_datacenter ? "DATACENTER" : "ANOMALOUS"}
                      </span>
                    )}
                  </div>

                  <div className="font-semibold text-slate-200 truncate">
                    {hop.ip || "Unknown IP"}
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
                  {typeof selectedHop.lat === "number" && typeof selectedHop.lng === "number"
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
