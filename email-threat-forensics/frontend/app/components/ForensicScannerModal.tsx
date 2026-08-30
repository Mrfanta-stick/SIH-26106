// app/components/ForensicScannerModal.tsx
"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
import type { ForensicReport } from "../types/forensic";

interface ForensicScannerModalProps {
  file: File;
  onComplete: (report: ForensicReport) => void;
  onError: (message: string) => void;
  onClose: () => void;
}

type ScannerState =
  | "checking"
  | "uploading"
  | "processing"
  | "success"
  | "error";

const HARD_TIMEOUT_MS = 30_000;

function isForensicReport(value: unknown): value is ForensicReport {
  if (!value || typeof value !== "object") return false;

  const report = value as Record<string, unknown>;

  // Keep the runtime validation deliberately conservative: require the
  // top-level object and the fields the application actually consumes.
  // Optional forensic stages may be absent while placeholders are used.
  const hasString = (key: string) =>
    typeof report[key] === "string" && String(report[key]).length > 0;

  const hasObject = (key: string) =>
    !!report[key] && typeof report[key] === "object";

  // The backend contract used by the app requires an id/case identifier.
  // Other fields are validated when present so the backend can evolve
  // without making preview/mock reports impossible.
  return (
    (hasString("id") || hasString("caseId") || hasString("case_id")) &&
    (hasObject("metadata") ||
      hasObject("email") ||
      hasObject("summary") ||
      hasObject("verdict") ||
      hasObject("threat"))
  );
}

function getApiBase(): string {
  const configured = process.env.NEXT_PUBLIC_API_URL?.trim();
  return (configured || "http://127.0.0.1:8000").replace(/\/+$/, "");
}

async function fetchWithHardTimeout(
  input: RequestInfo | URL,
  init: RequestInit,
  timeoutMs: number
): Promise<Response> {
  const controller = new AbortController();
  let timeoutId: number | undefined;

  const timeoutPromise = new Promise<never>((_, reject) => {
    timeoutId = window.setTimeout(() => {
      controller.abort("timeout");
      reject(new DOMException("Backend request timed out.", "TimeoutError"));
    }, timeoutMs);
  });

  const requestPromise = fetch(input, {
    ...init,
    signal: controller.signal,
    cache: "no-store",
  });

  try {
    return await Promise.race([requestPromise, timeoutPromise]);
  } finally {
    if (timeoutId !== undefined) window.clearTimeout(timeoutId);
    controller.abort();
  }
}

function ForensicScannerModal({
  file,
  onComplete,
  onError,
  onClose,
}: ForensicScannerModalProps) {
  const [state, setState] = useState<ScannerState>("checking");
  const [progress, setProgress] = useState(5);
  const [errorMessage, setErrorMessage] = useState("");
  const [isRetrying, setIsRetrying] = useState(false);
  const requestIdRef = useRef(0);

  const analyze = useCallback(async () => {
    const requestId = ++requestIdRef.current;
    setState("checking");
    setProgress(8);
    setErrorMessage("");
    setIsRetrying(false);

    const apiUrl = getApiBase();
    const endpoint = `${apiUrl}/api/analyze`;

    // Fast preflight: if the browser is already offline, don't start the
    // forensic progress animation or wait for a fetch timeout.
    if (typeof navigator !== "undefined" && !navigator.onLine) {
      if (requestId !== requestIdRef.current) return;
      setState("error");
      setErrorMessage(
        "You appear to be offline. Connect to the network and retry the analysis."
      );
      return;
    }

    setState("uploading");
    setProgress(18);

    const formData = new FormData();
    formData.append("file", file);

    try {
      // A very short connection probe catches the common local-development
      // case (FastAPI isn't running) quickly. It does not replace the real
      // POST and never treats the probe as a successful analysis.
      try {
        await fetchWithHardTimeout(
          `${apiUrl}/docs`,
          { method: "GET" },
          2_500
        );
      } catch {
        if (requestId !== requestIdRef.current) return;

        setState("error");
        setErrorMessage(
          `Unable to reach the forensic backend at ${apiUrl}. ` +
            "Start the FastAPI service and retry the analysis."
        );
        return;
      }

      setState("processing");
      setProgress(30);

      const progressTimer = window.setInterval(() => {
        setProgress((current) => Math.min(current + 2, 88));
      }, 350);

      let response: Response;
      try {
        response = await fetchWithHardTimeout(
          endpoint,
          {
            method: "POST",
            body: formData,
          },
          HARD_TIMEOUT_MS
        );
      } finally {
        window.clearInterval(progressTimer);
      }

      if (requestId !== requestIdRef.current) return;

      if (!response.ok) {
        let detail = "";
        try {
          const errorBody = await response.json();
          if (errorBody && typeof errorBody.detail === "string") {
            detail = ` ${errorBody.detail}`;
          }
        } catch {
          // The backend may return a non-JSON error page.
        }

        throw new Error(
          `Backend returned HTTP ${response.status}.${detail}`
        );
      }

      const contentType = response.headers.get("content-type") || "";
      if (!contentType.toLowerCase().includes("application/json")) {
        throw new Error(
          "The backend returned a non-JSON response. Check the /api/analyze contract."
        );
      }

      let payload: unknown;
      try {
        payload = await response.json();
      } catch {
        throw new Error("The backend returned invalid JSON.");
      }

      if (!isForensicReport(payload)) {
        throw new Error(
          "The backend response does not match the expected forensic report format."
        );
      }

      setProgress(100);
      setState("success");

      // Give React one paint to show completion before handing the report
      // to the parent. Ignore stale requests if the modal was retried/closed.
      window.setTimeout(() => {
        if (requestId === requestIdRef.current) {
          onComplete(payload);
        }
      }, 150);
    } catch (error) {
      if (requestId !== requestIdRef.current) return;

      const isTimeout =
        error instanceof DOMException &&
        (error.name === "TimeoutError" || error.name === "AbortError");

      const message =
        isTimeout
          ? "The forensic backend did not respond within 30 seconds. Check the backend and retry."
          : error instanceof TypeError
            ? `Unable to reach the forensic backend at ${apiUrl}. Make sure the FastAPI service is running.`
            : error instanceof Error
              ? error.message
              : "The analysis could not be completed.";

      setState("error");
      setErrorMessage(message);
      setProgress(0);
    }
  }, [file, onComplete]);

  useEffect(() => {
    void analyze();

    return () => {
      requestIdRef.current += 1;
    };
  }, [analyze]);

  const handleRetry = () => {
    setIsRetrying(true);
    void analyze();
  };

  const handleClose = () => {
    requestIdRef.current += 1;
    onClose();
  };

  return (
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 p-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-labelledby="forensic-scanner-title"
    >
      <div className="w-full max-w-xl overflow-hidden rounded-2xl border border-cyan-400/20 bg-[#080d14] shadow-[0_0_80px_rgba(0,0,0,0.65)]">
        <div className="border-b border-white/10 px-6 py-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="font-mono text-[10px] uppercase tracking-[0.28em] text-cyan-400/70">
                SPECTRE.DFIR // FORENSIC PIPELINE
              </p>
              <h2
                id="forensic-scanner-title"
                className="mt-1 text-lg font-semibold text-white"
              >
                {state === "error"
                  ? "Analysis interrupted"
                  : state === "success"
                    ? "Analysis complete"
                    : "Analyzing evidence"}
              </h2>
            </div>

            <button
              type="button"
              onClick={handleClose}
              aria-label="Close forensic scanner"
              className="rounded-lg p-2 text-slate-500 transition hover:bg-white/5 hover:text-white focus:outline-none focus:ring-2 focus:ring-cyan-400/50"
            >
              <span aria-hidden="true">×</span>
            </button>
          </div>
        </div>

        <div className="px-6 py-7">
          {state !== "error" ? (
            <>
              <div className="rounded-xl border border-white/10 bg-black/20 p-4">
                <div className="flex items-center justify-between gap-4">
                  <div className="min-w-0">
                    <p className="font-mono text-[10px] uppercase tracking-wider text-slate-500">
                      Evidence
                    </p>
                    <p className="mt-1 truncate text-sm text-slate-200">
                      {file.name}
                    </p>
                  </div>

                  <span className="shrink-0 font-mono text-xs text-cyan-400">
                    {progress}%
                  </span>
                </div>

                <div
                  className="mt-4 h-1.5 overflow-hidden rounded-full bg-white/10"
                  aria-label={`Analysis progress ${progress}%`}
                  role="progressbar"
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={progress}
                >
                  <div
                    className="h-full rounded-full bg-cyan-400 transition-all duration-300"
                    style={{ width: `${progress}%` }}
                  />
                </div>

                <p className="mt-3 font-mono text-[10px] uppercase tracking-wider text-slate-500">
                  {state === "checking" && "Checking backend connectivity…"}
                  {state === "uploading" && "Uploading evidence…"}
                  {state === "processing" && "Running forensic analysis…"}
                  {state === "success" && "Report received"}
                </p>
              </div>

              <p className="mt-4 text-center font-mono text-[10px] text-slate-600">
                Backend: {getApiBase()} · Hard timeout: 30s
              </p>
            </>
          ) : (
            <div
              className="rounded-xl border border-red-400/20 bg-red-500/5 p-5"
              role="alert"
              aria-live="assertive"
            >
              <div className="flex gap-3">
                <div className="mt-0.5 text-red-400" aria-hidden="true">
                  !
                </div>
                <div className="min-w-0">
                  <h3 className="font-semibold text-red-300">
                    Backend connection failed
                  </h3>
                  <p className="mt-2 text-sm leading-6 text-slate-300">
                    {errorMessage}
                  </p>
                </div>
              </div>

              <div className="mt-5 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
                <button
                  type="button"
                  onClick={handleClose}
                  className="rounded-lg border border-white/10 px-4 py-2 text-sm font-medium text-slate-300 transition hover:bg-white/5 hover:text-white focus:outline-none focus:ring-2 focus:ring-cyan-400/50"
                >
                  Close
                </button>
                <button
                  type="button"
                  onClick={handleRetry}
                  disabled={isRetrying}
                  className="rounded-lg bg-cyan-400 px-4 py-2 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:cursor-wait disabled:opacity-60 focus:outline-none focus:ring-2 focus:ring-cyan-300/60"
                >
                  {isRetrying ? "Retrying…" : "Retry analysis"}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}


export { ForensicScannerModal };
export default ForensicScannerModal;
