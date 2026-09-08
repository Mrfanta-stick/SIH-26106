"use client";

import { useEffect, useRef, useState, useCallback, KeyboardEvent } from "react";

export interface CyberHoloCore3DProps {
  threatLevel?: number;
  statusText?: string;
}

export function CyberHoloCore3D({
  threatLevel = 45,
  statusText = "SYSTEM MONITORED",
}: CyberHoloCore3DProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);

  const [rotationX, setRotationX] = useState<number>(0.2);
  const [rotationY, setRotationY] = useState<number>(0.3);
  const [isAutoRotating, setIsAutoRotating] = useState<boolean>(true);
  const isDraggingRef = useRef<boolean>(false);
  const previousMousePositionRef = useRef<{ x: number; y: number }>({ x: 0, y: 0 });

  const clampRotation = (val: number, min: number, max: number) => {
    return Math.min(Math.max(val, min), max);
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const step = 0.08;
    switch (e.key) {
      case "ArrowUp":
        e.preventDefault();
        setRotationX((prev) => clampRotation(prev - step, -1.2, 1.2));
        break;
      case "ArrowDown":
        e.preventDefault();
        setRotationX((prev) => clampRotation(prev + step, -1.2, 1.2));
        break;
      case "ArrowLeft":
        e.preventDefault();
        setRotationY((prev) => prev - step);
        break;
      case "ArrowRight":
        e.preventDefault();
        setRotationY((prev) => prev + step);
        break;
      case " ":
        e.preventDefault();
        setIsAutoRotating((prev) => !prev);
        break;
      case "r":
      case "R":
        e.preventDefault();
        setRotationX(0.2);
        setRotationY(0.3);
        break;
      default:
        break;
    }
  };

  const handleMouseDown = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    isDraggingRef.current = true;
    previousMousePositionRef.current = { x: e.clientX, y: e.clientY };
  }, []);

  const handleMouseMove = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    if (!isDraggingRef.current) return;
    const deltaX = e.clientX - previousMousePositionRef.current.x;
    const deltaY = e.clientY - previousMousePositionRef.current.y;

    setRotationY((prev) => prev + deltaX * 0.008);
    setRotationX((prev) => clampRotation(prev + deltaY * 0.008, -1.2, 1.2));

    previousMousePositionRef.current = { x: e.clientX, y: e.clientY };
  }, []);

  const handleMouseUpOrLeave = useCallback(() => {
    isDraggingRef.current = false;
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animationFrameId: number;
    let localRotY = rotationY;

    const render = () => {
      if (!canvas || !ctx) return;

      const width = (canvas.width = canvas.parentElement?.clientWidth || 300);
      const height = (canvas.height = canvas.parentElement?.clientHeight || 300);
      const centerX = width / 2;
      const centerY = height / 2;
      const radius = Math.min(centerX, centerY) * 0.55;

      ctx.clearRect(0, 0, width, height);

      if (isAutoRotating && !isDraggingRef.current) {
        localRotY += 0.01;
      } else {
        localRotY = rotationY;
      }

      const effectiveRotX = rotationX;

      const primaryColor =
        threatLevel > 75
          ? "244, 63, 94"
          : threatLevel > 40
          ? "245, 158, 11"
          : "6, 182, 212";

      const numRings = 8;
      for (let i = 0; i < numRings; i++) {
        const theta = (i * Math.PI) / numRings;
        const currentR = radius * Math.sin(theta);
        const yOffset = radius * Math.cos(theta) * Math.cos(effectiveRotX);

        ctx.beginPath();
        ctx.ellipse(
          centerX,
          centerY + yOffset,
          Math.max(1, currentR),
          Math.max(1, currentR * Math.sin(effectiveRotX + Math.PI / 2)),
          localRotY,
          0,
          2 * Math.PI
        );
        ctx.strokeStyle = `rgba(${primaryColor}, ${0.15 + (i % 2) * 0.15})`;
        ctx.lineWidth = 1;
        ctx.stroke();
      }

      const gradient = ctx.createRadialGradient(
        centerX,
        centerY,
        2,
        centerX,
        centerY,
        radius * 0.35
      );
      gradient.addColorStop(0, `rgba(${primaryColor}, 0.8)`);
      gradient.addColorStop(0.5, `rgba(${primaryColor}, 0.2)`);
      gradient.addColorStop(1, "rgba(0, 0, 0, 0)");

      ctx.beginPath();
      ctx.arc(centerX, centerY, radius * 0.35, 0, 2 * Math.PI);
      ctx.fillStyle = gradient;
      ctx.fill();

      const particleCount = 12;
      for (let p = 0; p < particleCount; p++) {
        const pAngle = (p * 2 * Math.PI) / particleCount + localRotY * 1.5;
        const px = centerX + Math.cos(pAngle) * (radius * 0.85);
        const py =
          centerY +
          Math.sin(pAngle) * (radius * 0.85) * Math.sin(effectiveRotX);

        ctx.beginPath();
        ctx.arc(px, py, 2.5, 0, 2 * Math.PI);
        ctx.fillStyle = `rgb(${primaryColor})`;
        ctx.shadowColor = `rgb(${primaryColor})`;
        ctx.shadowBlur = 8;
        ctx.fill();
        ctx.shadowBlur = 0;
      }

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
    };
  }, [rotationX, rotationY, isAutoRotating, threatLevel]);

  return (
    <div
      ref={containerRef}
      tabIndex={0}
      role="region"
      aria-label="3D Interactive Holographic Core: Use arrow keys to rotate, space to toggle auto-rotation, R to reset"
      onKeyDown={handleKeyDown}
      className="relative w-full h-64 rounded-xl border border-slate-800 bg-slate-950/70 p-4 flex flex-col items-center justify-center outline-none focus:ring-2 focus:ring-cyan-400/80 focus:border-cyan-400 transition-all cursor-grab active:cursor-grabbing"
    >
      <div className="absolute top-3 left-4 right-4 flex items-center justify-between font-mono text-[10px] text-slate-400">
        <span className="flex items-center gap-1.5">
          <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-ping" />
          HOLO-CORE MATRIX
        </span>
        <span className="text-slate-500">INTERACTIVE 3D VIZ</span>
      </div>

      <canvas
        ref={canvasRef}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUpOrLeave}
        onMouseLeave={handleMouseUpOrLeave}
        className="w-full h-full block"
      />

      <div className="absolute bottom-3 left-4 right-4 flex items-center justify-between font-mono text-[10px]">
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setIsAutoRotating((prev) => !prev)}
            aria-label={isAutoRotating ? "Pause auto rotation" : "Start auto rotation"}
            title="Toggle rotation"
            className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 hover:text-white transition-colors"
          >
            {isAutoRotating ? "PAUSE" : "ROTATE"}
          </button>
          <button
            type="button"
            onClick={() => {
              setRotationX(0.2);
              setRotationY(0.3);
            }}
            aria-label="Reset 3D core orientation"
            title="Reset orientation"
            className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 hover:text-white transition-colors"
          >
            RESET
          </button>
        </div>

        <span
          className={`font-semibold uppercase tracking-wider ${
            threatLevel > 75
              ? "text-rose-400"
              : threatLevel > 40
              ? "text-amber-400"
              : "text-cyan-400"
          }`}
        >
          {statusText}
        </span>
      </div>
    </div>
  );
}

export default CyberHoloCore3D;