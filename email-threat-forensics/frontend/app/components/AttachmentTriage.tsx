"use client";

import { useMemo, useState } from "react";
import { AttachmentReport, ForensicReport } from "../types/forensic";

export interface AttachmentItem {
  filename?: string;
  sha256?: string;
  size_bytes?: number;
  mime_type?: string;
  verdict?: "malicious" | "suspicious" | "clean" | "unknown";
  risk?: string;
  entropy?: number;
  extracted_strings_summary?: string[];
  yara_matches?: string[];
  vt_positives?: number;
  vt_total?: number;
  virustotal_scan?: Record<string, unknown> | null;
}

export interface AttachmentTriageProps {
  report?: ForensicReport | null;
  attachments?: AttachmentItem[];
}

function mapRiskToVerdict(risk?: string): AttachmentItem["verdict"] {
  const value = (risk || "").toLowerCase();
  if (!value) return "unknown";
  if (value.includes("benign") || value === "clean") return "clean";
  if (
    value.includes("malicious") ||
    value.includes("payload") ||
    value.includes("macro") ||
    value.includes("zip_bomb") ||
    value.includes("critical")
  ) {
    return "malicious";
  }
  if (value.includes("unknown")) return "unknown";
  return "suspicious";
}

function mapBackendAttachment(att: AttachmentReport): AttachmentItem {
  const scan = att.virustotal_scan || null;
  const malicious =
    scan && typeof scan.malicious === "number" ? scan.malicious : undefined;
  const total =
    scan && typeof scan.total === "number"
      ? scan.total
      : scan
        ? Object.values(scan).reduce<number>(
            (sum, value) => sum + (typeof value === "number" ? value : 0),
            0
          )
        : undefined;

  return {
    filename: att.filename,
    sha256: att.sha256 || undefined,
    size_bytes: att.size_bytes || undefined,
    mime_type: att.detected_magic,
    risk: att.risk,
    verdict: mapRiskToVerdict(att.risk),
    vt_positives: malicious,
    vt_total: total,
    virustotal_scan: scan,
  };
}

export function AttachmentTriage({ report, attachments }: AttachmentTriageProps) {
  const activeAttachments: AttachmentItem[] = useMemo(() => {
    if (attachments?.length) return attachments;
    return (report?.attachment_forensics || []).map(mapBackendAttachment);
  }, [attachments, report]);

  const [selectedAttachment, setSelectedAttachment] =
    useState<AttachmentItem | null>(null);

  const formatBytes = (bytes?: number) => {
    if (!bytes) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
  };

  const getVerdictBadge = (verdict?: string) => {
    switch (verdict?.toLowerCase()) {
      case "malicious":
        return "bg-rose-950/50 border-rose-600/50 text-rose-300";
      case "suspicious":
        return "bg-amber-950/50 border-amber-600/50 text-amber-300";
      case "clean":
        return "bg-emerald-950/50 border-emerald-600/50 text-emerald-300";
      default:
        return "bg-slate-800 border-slate-700 text-slate-400";
    }
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4 backdrop-blur-sm font-mono">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse" />
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
            Extracted Payload & Attachment Triage
          </h3>
        </div>
        <span className="text-[10px] text-slate-500">
          COUNT: {activeAttachments.length}
        </span>
      </div>

      {activeAttachments.length === 0 ? (
        <div className="py-8 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-lg">
          No MIME binary payload attachments detected in telemetry stream.
        </div>
      ) : (
        <div className="space-y-2.5">
          {activeAttachments.map((att: AttachmentItem, idx: number) => {
            const isSelected =
              selectedAttachment?.sha256 === att.sha256 && Boolean(att.sha256)
                ? true
                : selectedAttachment?.filename === att.filename && !att.sha256;

            return (
              <div
                key={att.filename || att.sha256 || idx}
                onClick={() => setSelectedAttachment(isSelected ? null : att)}
                className={`p-3 rounded-lg border text-xs cursor-pointer transition-all ${
                  isSelected
                    ? "border-cyan-500/50 bg-slate-800/80 ring-1 ring-cyan-500/30"
                    : "border-slate-800/80 bg-slate-950/40 hover:bg-slate-800/40 hover:border-slate-700"
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-slate-500 text-[10px]">
                      [{String(idx + 1).padStart(2, "0")}]
                    </span>
                    <span className="text-slate-200 font-medium truncate">
                      {att.filename || "unnamed_payload.bin"}
                    </span>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <span className="text-[10px] text-slate-400">
                      {formatBytes(att.size_bytes)}
                    </span>
                    <span
                      className={`text-[10px] uppercase px-2 py-0.5 rounded border font-semibold ${getVerdictBadge(
                        att.verdict
                      )}`}
                    >
                      {att.risk || att.verdict || "UNKNOWN"}
                    </span>
                  </div>
                </div>

                {isSelected && (
                  <div className="mt-3 pt-3 border-t border-slate-800 space-y-2 text-[11px] text-slate-400">
                    <div>
                      <span className="text-slate-500">Detected magic / MIME:</span>{" "}
                      <span className="text-slate-300">
                        {att.mime_type || "application/octet-stream"}
                      </span>
                    </div>

                    {att.sha256 && (
                      <div className="break-all">
                        <span className="text-slate-500">SHA-256:</span>{" "}
                        <span className="text-cyan-400/90">{att.sha256}</span>
                      </div>
                    )}

                    {typeof att.vt_positives === "number" && (
                      <div>
                        <span className="text-slate-500">VirusTotal:</span>{" "}
                        <span className="text-amber-300">
                          {att.vt_positives}
                          {typeof att.vt_total === "number" ? ` / ${att.vt_total}` : ""} detections
                        </span>
                      </div>
                    )}

                    {att.virustotal_scan && typeof att.vt_positives !== "number" && (
                      <div className="break-all">
                        <span className="text-slate-500">VirusTotal scan:</span>{" "}
                        <span className="text-slate-300">
                          {JSON.stringify(att.virustotal_scan)}
                        </span>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default AttachmentTriage;
