"use client";

import { useState, useRef, DragEvent, ChangeEvent, KeyboardEvent } from "react";

interface DropzoneProps {
  onFileLoaded: (content: string, filename: string) => void;
  isLoading?: boolean;
}

export default function Dropzone({ onFileLoaded, isLoading = false }: DropzoneProps) {
  const [isDragOver, setIsDragOver] = useState(false);
  const [selectedFileName, setSelectedFileName] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const handleFileProcess = (file: File) => {
    setSelectedFileName(file.name);
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      if (content) {
        onFileLoaded(content, file.name);
      }
    };
    reader.readAsText(file);
  };

  const handleDragOver = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(true);
  };

  const handleDragLeave = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileProcess(e.dataTransfer.files[0]);
    }
  };

  const handleInputChange = (e: ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFileProcess(e.target.files[0]);
    }
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      fileInputRef.current?.click();
    }
  };

  const clearSelection = (e: React.MouseEvent) => {
    e.stopPropagation();
    setSelectedFileName(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  return (
    <div className="w-full">
      <input
        type="file"
        ref={fileInputRef}
        onChange={handleInputChange}
        accept=".eml,.msg,.txt,.pcap"
        className="hidden"
        id="email-evidence-upload"
        aria-label="Upload raw email or forensic telemetry file"
      />

      <div
        role="button"
        tabIndex={0}
        aria-label="Upload email evidence: drag and drop file here or press Enter to browse"
        onClick={() => fileInputRef.current?.click()}
        onKeyDown={handleKeyDown}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={`relative border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all duration-200 outline-none focus:ring-2 focus:ring-cyan-400 focus:border-cyan-400 ${
          isDragOver
            ? "border-cyan-400 bg-cyan-950/30 scale-[1.01]"
            : "border-slate-700/80 bg-slate-900/40 hover:border-slate-500 hover:bg-slate-900/60"
        }`}
      >
        <div className="flex flex-col items-center justify-center space-y-3 font-mono">
          {/* Upload Icon */}
          <div className="p-3.5 rounded-full bg-slate-800/80 border border-slate-700 text-cyan-400">
            <svg
              className="w-6 h-6"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
              aria-hidden="true"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
              />
            </svg>
          </div>

          <div className="space-y-1">
            <p className="text-sm font-semibold text-slate-200">
              {isLoading
                ? "INGESTING EVIDENCE STREAM..."
                : selectedFileName
                ? `LOADED: ${selectedFileName}`
                : "DRAG & DROP EMAIL TELEMETRY (.EML, .MSG, .TXT)"}
            </p>
            <p className="text-xs text-slate-400">
              or click / press Enter to browse local system storage
            </p>
          </div>

          {selectedFileName && (
            <div className="pt-2">
              <button
                type="button"
                onClick={clearSelection}
                aria-label="Clear selected file"
                title="Clear selected file"
                className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs text-rose-400 bg-rose-950/40 border border-rose-800/50 rounded hover:bg-rose-900/50 transition-colors"
              >
                <svg
                  className="w-3.5 h-3.5"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                  aria-hidden="true"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M6 18L18 6M6 6l12 12"
                  />
                </svg>
                <span>CLEAR FILE</span>
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}