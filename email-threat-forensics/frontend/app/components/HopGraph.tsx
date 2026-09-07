"use client";

import { useState } from "react";
import { ForensicReport } from "../types/forensic";

export interface GraphNode {
  id: string;
  label: string;
  type?: string;
  ip?: string;
  suspicious?: boolean;
}

export interface GraphEdge {
  source: string;
  target: string;
  protocol?: string;
  latency?: string;
  latency_ms?: number;
  auth_status?: "pass" | "fail" | "softfail" | "none" | string;
}

export interface HopGraphProps {
  report?: ForensicReport | null;
  nodes?: GraphNode[];
  edges?: GraphEdge[];
}

function normalizeNodeType(type?: string) {
  if (type === "origin" || type === "sender") return "source";
  if (type === "destination") return "destination";
  if (type === "relay" || type === "mta") return "relay";
  return type || "mta";
}

export function HopGraph({ report, nodes, edges }: HopGraphProps) {
  const activeNodes: GraphNode[] = nodes || report?.graph_topology?.nodes || [];
  const activeEdges: GraphEdge[] = edges || report?.graph_topology?.edges || [];
  const clusterId = report?.graph_topology?.campaign_cluster_id;

  const [activeNodeId, setActiveNodeId] = useState<string | null>(null);

  const getNodeColor = (type?: string, suspicious?: boolean) => {
    if (suspicious) return "border-rose-500/60 bg-rose-950/30 text-rose-300";
    switch (normalizeNodeType(type)) {
      case "source":
        return "border-amber-500/60 bg-amber-950/30 text-amber-300";
      case "destination":
        return "border-emerald-500/60 bg-emerald-950/30 text-emerald-300";
      default:
        return "border-cyan-500/40 bg-cyan-950/20 text-cyan-300";
    }
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4 backdrop-blur-sm font-mono">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse" />
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
            MTA Protocol Hop Graph & Relay Flow
          </h3>
        </div>
        <div className="flex items-center gap-2">
          {clusterId && (
            <span className="text-[10px] text-purple-300 border border-purple-700/50 px-2 py-0.5 rounded">
              CLUSTER {clusterId}
            </span>
          )}
          <button
            type="button"
            aria-label="Reset Hop Graph selection"
            onClick={() => setActiveNodeId(null)}
            className="text-[10px] text-slate-400 hover:text-slate-200 border border-slate-700 px-2 py-0.5 rounded bg-slate-800/40 transition-colors"
          >
            RESET
          </button>
        </div>
      </div>

      {activeNodes.length === 0 ? (
        <div className="py-8 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-lg">
          No transport relay topology available.
        </div>
      ) : (
        <div className="space-y-4">
          <div className="flex flex-col gap-2">
            {activeNodes.map((node: GraphNode, idx: number) => {
              const isActive = activeNodeId === node.id;
              const connectedEdge = activeEdges.find((e) => e.source === node.id);

              return (
                <div key={node.id || idx} className="space-y-2">
                  <div
                    onClick={() => setActiveNodeId(isActive ? null : node.id)}
                    className={`p-3 rounded-lg border text-xs cursor-pointer transition-all flex items-center justify-between ${getNodeColor(
                      node.type,
                      node.suspicious
                    )} ${isActive ? "ring-2 ring-cyan-400" : ""}`}
                  >
                    <div className="flex items-center gap-3">
                      <span className="text-[10px] text-slate-500 font-bold">
                        [{String(idx + 1).padStart(2, "0")}]
                      </span>
                      <div>
                        <span className="font-semibold block">{node.label}</span>
                        {node.ip && (
                          <span className="text-[10px] text-slate-400">
                            {node.ip}
                          </span>
                        )}
                      </div>
                    </div>
                    <span className="text-[10px] uppercase font-semibold px-2 py-0.5 rounded border border-slate-700 bg-slate-900/60">
                      {normalizeNodeType(node.type)}
                    </span>
                  </div>

                  {connectedEdge && idx < activeNodes.length - 1 && (
                    <div
                      key={`${connectedEdge.source}-${connectedEdge.target}-${connectedEdge.protocol || idx}`}
                      className="pl-8 py-1 flex items-center gap-2 text-[10px] text-slate-500"
                    >
                      <span className="text-slate-600">│</span>
                      <span>▼</span>
                      <span className="text-slate-400">
                        {connectedEdge.protocol || "SMTP"}
                      </span>
                      {connectedEdge.latency && (
                        <span className="text-slate-500">
                          (+{connectedEdge.latency})
                        </span>
                      )}
                      {typeof connectedEdge.latency_ms === "number" && (
                        <span className="text-slate-500">
                          (+{connectedEdge.latency_ms}ms)
                        </span>
                      )}
                      {connectedEdge.auth_status && (
                        <span
                          className={`px-1 rounded text-[9px] uppercase ${
                            connectedEdge.auth_status === "pass"
                              ? "bg-emerald-950 text-emerald-400 border border-emerald-800"
                              : "bg-rose-950 text-rose-400 border border-rose-800"
                          }`}
                        >
                          {connectedEdge.auth_status}
                        </span>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

export default HopGraph;