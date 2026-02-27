import { useEffect, useRef } from 'react';
import { motion } from 'framer-motion';

interface UsageChartProps {
  title: string;
  data?: { value: number }[];
  color: 'cyan' | 'green';
}

interface Particle {
  x: number;
  y: number;
  vx: number;
  vy: number;
  life: number;
  maxLife: number;
  size: number;
}

/**
 * Renders real data points as a smooth graph.
 * Falls back to gentle animated wave if no data provided.
 * Data is stored in a ref to avoid re-creating the canvas animation on each push.
 */
export function UsageChart({ title, data, color }: UsageChartProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const frameRef = useRef<number>(0);
  const particlesRef = useRef<Particle[]>([]);
  const dataRef = useRef(data);

  // Update the data ref without restarting the animation
  dataRef.current = data;

  const strokeColor = color === 'cyan' ? '#00f0ff' : '#00ff88';
  const strokeRgb = color === 'cyan' ? '0, 240, 255' : '0, 255, 136';

  // Animation runs once on mount, reads data from ref
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animId: number;
    let lastDrawTime = 0;
    const FPS_INTERVAL = 1000 / 16; // ~16fps — smooth, no flicker

    const resize = () => {
      const rect = canvas.getBoundingClientRect();
      canvas.width = rect.width * 2;
      canvas.height = rect.height * 2;
      ctx.scale(2, 2);
    };
    resize();
    const resizeObserver = new ResizeObserver(resize);
    resizeObserver.observe(canvas);

    const draw = (timestamp: number) => {
      animId = requestAnimationFrame(draw);

      // Throttle to ~16fps
      const elapsed = timestamp - lastDrawTime;
      if (elapsed < FPS_INTERVAL) return;
      lastDrawTime = timestamp - (elapsed % FPS_INTERVAL);

      frameRef.current++;
      const w = canvas.width / 2;
      const h = canvas.height / 2;
      ctx.setTransform(2, 0, 0, 2, 0, 0);
      ctx.clearRect(0, 0, w, h);

      // -- Background --
      ctx.fillStyle = 'rgba(4, 10, 24, 0.75)';
      ctx.fillRect(0, 0, w, h);

      // -- Grid (magenta, subtle) --
      ctx.strokeStyle = `rgba(255, 0, 255, 0.15)`;
      ctx.lineWidth = 0.5;
      const gridStep = 24;
      for (let x = 0; x < w; x += gridStep) {
        ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke();
      }
      for (let y = 0; y < h; y += gridStep) {
        ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
      }

      // -- Build data points from ref (no re-rendering) --
      const padX = 8, padY = 20;
      const usableW = w - padX * 2;
      const usableH = h - padY * 2;
      const currentData = dataRef.current;

      let values: number[];
      if (currentData && currentData.length >= 2) {
        values = currentData.map(d => Math.max(0, Math.min(100, d.value)));
      } else {
        // Gentle fallback wave (very slow)
        const t = frameRef.current * 0.003;
        values = [];
        for (let i = 0; i < 30; i++) {
          const frac = i / 29;
          values.push(50 + Math.sin(frac * Math.PI * 2 + t) * 20 + Math.sin(frac * 5 + t * 0.5) * 8);
        }
      }

      const n = values.length;
      const pts: { x: number; y: number }[] = [];
      for (let i = 0; i < n; i++) {
        const frac = i / (n - 1);
        pts.push({
          x: padX + frac * usableW,
          y: padY + (1 - values[i] / 100) * usableH,
        });
      }

      // -- Build smooth path --
      const buildPath = () => {
        ctx.beginPath();
        ctx.moveTo(pts[0].x, pts[0].y);
        for (let i = 1; i < n - 1; i++) {
          const mx = (pts[i].x + pts[i + 1].x) / 2;
          const my = (pts[i].y + pts[i + 1].y) / 2;
          ctx.quadraticCurveTo(pts[i].x, pts[i].y, mx, my);
        }
        ctx.lineTo(pts[n - 1].x, pts[n - 1].y);
      };

      // -- Gradient fill --
      buildPath();
      ctx.lineTo(padX + usableW, h);
      ctx.lineTo(padX, h);
      ctx.closePath();
      const grad = ctx.createLinearGradient(0, 0, 0, h);
      grad.addColorStop(0, `rgba(${strokeRgb}, 0.22)`);
      grad.addColorStop(0.5, `rgba(${strokeRgb}, 0.08)`);
      grad.addColorStop(1, `rgba(${strokeRgb}, 0.01)`);
      ctx.fillStyle = grad;
      ctx.fill();

      // -- Pass 1: Wide glow --
      buildPath();
      ctx.shadowColor = `rgba(${strokeRgb}, 0.6)`;
      ctx.shadowBlur = 12;
      ctx.strokeStyle = `rgba(${strokeRgb}, 0.3)`;
      ctx.lineWidth = 6;
      ctx.lineCap = 'round';
      ctx.lineJoin = 'round';
      ctx.stroke();
      ctx.shadowBlur = 0;

      // -- Pass 2: Main colored line --
      buildPath();
      ctx.shadowColor = `rgba(${strokeRgb}, 0.8)`;
      ctx.shadowBlur = 6;
      ctx.strokeStyle = strokeColor;
      ctx.lineWidth = 2.2;
      ctx.stroke();
      ctx.shadowBlur = 0;

      // -- Pass 3: White hot core --
      buildPath();
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.85)';
      ctx.lineWidth = 0.9;
      ctx.stroke();

      // -- Particles along path --
      if (Math.random() < 0.25 && pts.length > 1) {
        const idx = Math.floor(Math.random() * pts.length);
        const pt = pts[idx];
        particlesRef.current.push({
          x: pt.x,
          y: pt.y,
          vx: (Math.random() - 0.5) * 0.4,
          vy: -Math.random() * 0.6,
          life: 0,
          maxLife: 50 + Math.random() * 50,
          size: 0.8 + Math.random() * 1.2,
        });
      }

      // Update & draw particles
      particlesRef.current = particlesRef.current.filter(p => p.life < p.maxLife);
      for (const p of particlesRef.current) {
        p.life++;
        p.x += p.vx;
        p.y += p.vy;
        const alpha = 1 - p.life / p.maxLife;
        ctx.fillStyle = `rgba(255, 255, 255, ${alpha * 0.4})`;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size * alpha, 0, Math.PI * 2);
        ctx.fill();
      }

      // Title is rendered as static HTML overlay — not in canvas
    };

    animId = requestAnimationFrame(draw);

    return () => {
      cancelAnimationFrame(animId);
      resizeObserver.disconnect();
    };
    // Only depend on color/title — data is read from ref
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [color, strokeColor, strokeRgb, title]);

  const borderColor = color === 'cyan' ? 'var(--cyan)' : 'var(--green-cyan)';

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.98 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ delay: 0.3 }}
      className="tech-card relative overflow-hidden flex flex-col"
      style={{ border: `1px solid ${borderColor}` }}>

      {/* HUD corner accents */}
      <span className="corner corner-tl" style={{ borderColor }} />
      <span className="corner corner-tr" style={{ borderColor }} />
      <span className="corner corner-bl" style={{ borderColor }} />
      <span className="corner corner-br" style={{ borderColor }} />

      {/* Static title — NOT drawn in canvas to avoid flicker */}
      <div className="absolute top-1.5 left-2 z-10 text-[11px] font-['Share_Tech_Mono'] tracking-wider"
        style={{ color: 'rgba(74, 106, 138, 0.8)' }}>
        {title}
      </div>

      <canvas
        ref={canvasRef}
        className="flex-1 w-full"
        style={{ display: 'block' }} />
    </motion.div>
  );
}