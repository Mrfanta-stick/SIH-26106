'use client';

import React, { useEffect, useRef, useState } from 'react';
import { Cpu, ShieldAlert, Sparkles, RefreshCw } from 'lucide-react';

interface Point3D {
  x: number;
  y: number;
  z: number;
}

export const CyberHoloCore3D: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [isHovered, setIsHovered] = useState(false);
  const mouseRef = useRef({ isDown: false, lastX: 0, lastY: 0, rotX: 0.35, rotY: 0.6 });

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    const width = (canvas.width = 420);
    const height = (canvas.height = 360);
    const centerX = width / 2;
    const centerY = height / 2;

    // 1. Crystal Polyhedron Vertices (3D Octahedron / Quantum Core)
    const coreRadius = 45;
    const coreVertices: Point3D[] = [
      { x: 0, y: -coreRadius * 1.3, z: 0 },
      { x: coreRadius, y: 0, z: 0 },
      { x: 0, y: 0, z: coreRadius },
      { x: -coreRadius, y: 0, z: 0 },
      { x: 0, y: 0, z: -coreRadius },
      { x: 0, y: coreRadius * 1.3, z: 0 },
    ];

    const coreEdges = [
      [0, 1], [0, 2], [0, 3], [0, 4],
      [5, 1], [5, 2], [5, 3], [5, 4],
      [1, 2], [2, 3], [3, 4], [4, 1]
    ];

    // 2. Gyroscope Ring Points Generator
    const generateRing = (r: number, segments: number): Point3D[] => {
      const ring: Point3D[] = [];
      for (let i = 0; i < segments; i++) {
        const theta = (i * 2 * Math.PI) / segments;
        ring.push({ x: r * Math.cos(theta), y: r * Math.sin(theta), z: 0 });
      }
      return ring;
    };

    const ring1 = generateRing(95, 36);
    const ring2 = generateRing(125, 48);
    const ring3 = generateRing(145, 60);

    // 3. Ambient Orbiting Particle Dust
    const particleCount = 45;
    const particles = Array.from({ length: particleCount }, () => {
      const r = Math.random() * 80 + 70;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.random() * Math.PI;
      return {
        x: r * Math.sin(phi) * Math.cos(theta),
        y: r * Math.cos(phi),
        z: r * Math.sin(phi) * Math.sin(theta),
        speed: (Math.random() - 0.5) * 0.02,
        size: Math.random() * 1.5 + 0.8,
      };
    });

    let autoAngle = 0;

    const project = (p: Point3D, rx: number, ry: number, rz: number = 0) => {
      // Rotation matrices
      const cosY = Math.cos(ry), sinY = Math.sin(ry);
      const cosX = Math.cos(rx), sinX = Math.sin(rx);
      const cosZ = Math.cos(rz), sinZ = Math.sin(rz);

      // Rotate around Z
      let x = p.x * cosZ - p.y * sinZ;
      let y = p.x * sinZ + p.y * cosZ;
      let z = p.z;

      // Rotate around Y
      const x1 = x * cosY - z * sinY;
      const z1 = x * sinY + z * cosY;

      // Rotate around X
      const y2 = y * cosX - z1 * sinX;
      const z2 = z1 * cosX + y * sinX;

      const fov = 380;
      const scale = fov / (fov + z2);
      return {
        x: centerX + x1 * scale,
        y: centerY + y2 * scale,
        z: z2,
        scale,
      };
    };

    const render = () => {
      ctx.clearRect(0, 0, width, height);

      if (!mouseRef.current.isDown) {
        autoAngle += 0.012;
      }

      const baseRotX = mouseRef.current.rotX;
      const baseRotY = mouseRef.current.rotY + autoAngle;

      // A. Ambient Core Radial Glow
      const ambientGlow = ctx.createRadialGradient(centerX, centerY, 10, centerX, centerY, 150);
      ambientGlow.addColorStop(0, 'rgba(168, 85, 247, 0.25)');
      ambientGlow.addColorStop(0.4, 'rgba(6, 182, 212, 0.1)');
      ambientGlow.addColorStop(1, 'rgba(0,0,0,0)');
      ctx.fillStyle = ambientGlow;
      ctx.beginPath();
      ctx.arc(centerX, centerY, 150, 0, Math.PI * 2);
      ctx.fill();

      // B. Render Orbiting Gyroscopic Rings
      const drawRing = (ringPoints: Point3D[], rx: number, ry: number, rz: number, color: string, isDashed = false) => {
        const projected = ringPoints.map(p => project(p, rx, ry, rz));
        ctx.strokeStyle = color;
        ctx.lineWidth = 1.2;
        if (isDashed) ctx.setLineDash([4, 6]);
        else ctx.setLineDash([]);

        ctx.beginPath();
        projected.forEach((p, idx) => {
          if (idx === 0) ctx.moveTo(p.x, p.y);
          else ctx.lineTo(p.x, p.y);
        });
        ctx.closePath();
        ctx.stroke();
        ctx.setLineDash([]);
      };

      drawRing(ring1, baseRotX + 0.5, baseRotY * 1.2, autoAngle * 0.5, 'rgba(168, 85, 247, 0.45)');
      drawRing(ring2, baseRotX - 0.4, -baseRotY * 0.9, autoAngle * 0.3, 'rgba(6, 182, 212, 0.4)', true);
      drawRing(ring3, baseRotX + Math.PI / 4, baseRotY * 0.7, 0, 'rgba(244, 63, 94, 0.3)');

      // C. Render Floating Quantum Particle Dust
      particles.forEach(p => {
        const pt = project(p, baseRotX, baseRotY);
        const alpha = Math.max(0.1, (pt.z + 150) / 300);
        ctx.fillStyle = `rgba(192, 132, 252, ${alpha})`;
        ctx.beginPath();
        ctx.arc(pt.x, pt.y, Math.max(0.5, p.size * pt.scale), 0, Math.PI * 2);
        ctx.fill();
      });

      // D. Render 3D Polyhedron Crystal Core
      const projCore = coreVertices.map(v => project(v, baseRotX, baseRotY * 1.5, autoAngle));

      // Draw Edges
      ctx.strokeStyle = '#c084fc';
      ctx.lineWidth = 1.8;
      coreEdges.forEach(([start, end]) => {
        const p1 = projCore[start];
        const p2 = projCore[end];
        ctx.beginPath();
        ctx.moveTo(p1.x, p1.y);
        ctx.lineTo(p2.x, p2.y);
        ctx.stroke();
      });

      // Draw Core Vertices
      projCore.forEach((p, idx) => {
        ctx.beginPath();
        ctx.arc(p.x, p.y, idx === 0 || idx === 5 ? 3.5 : 2.5, 0, Math.PI * 2);
        ctx.fillStyle = idx % 2 === 0 ? '#f43f5e' : '#38bdf8';
        ctx.shadowBlur = 10;
        ctx.shadowColor = ctx.fillStyle;
        ctx.fill();
      });
      ctx.shadowBlur = 0;

      // E. Laser Sweeper Horizon Line
      const sweepY = centerY + Math.sin(autoAngle * 2) * 65;
      const laserGrad = ctx.createLinearGradient(centerX - 120, sweepY, centerX + 120, sweepY);
      laserGrad.addColorStop(0, 'rgba(0,0,0,0)');
      laserGrad.addColorStop(0.5, 'rgba(6, 182, 212, 0.6)');
      laserGrad.addColorStop(1, 'rgba(0,0,0,0)');
      ctx.strokeStyle = laserGrad;
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.moveTo(centerX - 120, sweepY);
      ctx.lineTo(centerX + 120, sweepY);
      ctx.stroke();

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    // Mouse Drag Listeners
    const handleMouseDown = (e: MouseEvent) => {
      mouseRef.current.isDown = true;
      mouseRef.current.lastX = e.clientX;
      mouseRef.current.lastY = e.clientY;
    };
    const handleMouseMove = (e: MouseEvent) => {
      if (!mouseRef.current.isDown) return;
      const dx = e.clientX - mouseRef.current.lastX;
      const dy = e.clientY - mouseRef.current.lastY;
      mouseRef.current.rotY += dx * 0.008;
      mouseRef.current.rotX += dy * 0.008;
      mouseRef.current.lastX = e.clientX;
      mouseRef.current.lastY = e.clientY;
    };
    const handleMouseUp = () => {
      mouseRef.current.isDown = false;
    };

    canvas.addEventListener('mousedown', handleMouseDown);
    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mouseup', handleMouseUp);

    return () => {
      cancelAnimationFrame(animationFrameId);
      canvas.removeEventListener('mousedown', handleMouseDown);
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
    };
  }, []);

  return (
    <div className="relative rounded-2xl bg-[#0d0c18]/90 backdrop-blur-2xl border border-white/15 p-5 shadow-2xl overflow-hidden flex flex-col items-center justify-between">
      {/* Top Header */}
      <div className="w-full flex items-center justify-between pb-3 border-b border-white/10 text-xs font-mono">
        <div className="flex items-center gap-2">
          <Cpu className="w-4 h-4 text-purple-400 animate-pulse" />
          <span className="text-white font-bold tracking-wide">QUANTUM EVIDENCE CORE</span>
        </div>
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/25 text-[10px] text-cyan-300 font-mono">
          <Sparkles className="w-3 h-3 text-cyan-400" /> ROTATABLE 3D
        </span>
      </div>

      {/* 3D Canvas Projection */}
      <div className="relative my-2 flex items-center justify-center cursor-grab active:cursor-grabbing">
        <canvas ref={canvasRef} className="w-[340px] h-[290px]" />
      </div>

      {/* Bottom Status Bar */}
      <div className="w-full p-2.5 rounded-xl bg-white/[0.03] border border-white/5 flex items-center justify-between text-[11px] font-mono">
        <span className="text-slate-400">Cryptographic Anchor:</span>
        <span className="text-emerald-400 font-bold tracking-wide">SHA-256 IMMUTABLE</span>
      </div>
    </div>
  );
};