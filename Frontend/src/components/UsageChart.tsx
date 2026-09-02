import { useEffect, useRef } from 'react';
import { motion } from 'framer-motion';

interface UsageChartProps {
  title: string;
  data?: { value: number }[];
  color: 'cyan' | 'green';
}

const MAX_SAMPLES = 60;

function prepareValues(data?: { value: number }[]) {
  if (!data?.length) return [];
  const raw = data.slice(-MAX_SAMPLES).map(point => Math.max(0, Math.min(100, point.value)));
  const firstSignal = raw.findIndex(value => value > 0.05);
  const trimmed = firstSignal > 0 ? raw.slice(firstSignal) : raw;
  if (trimmed.length < 3) return trimmed;
  return trimmed.map((value, index) => {
    const previous = trimmed[Math.max(0, index - 1)];
    const next = trimmed[Math.min(trimmed.length - 1, index + 1)];
    return previous * 0.2 + value * 0.6 + next * 0.2;
  });
}

export function UsageChart({ title, data, color }: UsageChartProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const dataRef = useRef(data);
  const frameRef = useRef(0);

  useEffect(() => { dataRef.current = data; }, [data]);

  const strokeColor = color === 'cyan' ? '#00f0ff' : '#00ff9d';
  const strokeRgb = color === 'cyan' ? '0, 240, 255' : '0, 255, 157';

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationId = 0;
    let previousTime = 0;
    let width = 0;
    let height = 0;
    let dpr = 1;

    const resize = () => {
      const rect = canvas.getBoundingClientRect();
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      width = Math.max(1, rect.width);
      height = Math.max(1, rect.height);
      canvas.width = Math.round(width * dpr);
      canvas.height = Math.round(height * dpr);
    };
    const observer = new ResizeObserver(resize);
    observer.observe(canvas);
    resize();

    const render = (time: number) => {
      animationId = requestAnimationFrame(render);
      if (time - previousTime < 1000 / 24) return;
      previousTime = time;
      frameRef.current += 1;

      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, width, height);
      const top = 32, right = 14, bottom = 18, left = 14;
      const chartWidth = Math.max(1, width - left - right);
      const chartHeight = Math.max(1, height - top - bottom);

      const background = ctx.createLinearGradient(0, top, 0, height);
      background.addColorStop(0, 'rgba(6, 18, 38, 0.94)');
      background.addColorStop(1, 'rgba(3, 8, 22, 0.98)');
      ctx.fillStyle = background;
      ctx.fillRect(0, 0, width, height);

      for (let division = 0; division <= 8; division++) {
        const x = left + chartWidth * division / 8;
        ctx.strokeStyle = division % 2 === 0 ? 'rgba(0, 240, 255, 0.075)' : 'rgba(255, 0, 255, 0.045)';
        ctx.beginPath(); ctx.moveTo(x, top); ctx.lineTo(x, height - bottom); ctx.stroke();
      }
      for (let division = 0; division <= 4; division++) {
        const y = top + chartHeight * division / 4;
        ctx.strokeStyle = division === 2 ? 'rgba(0, 240, 255, 0.11)' : 'rgba(255, 0, 255, 0.065)';
        ctx.beginPath(); ctx.moveTo(left, y); ctx.lineTo(width - right, y); ctx.stroke();
        if (division > 0 && division < 4) {
          ctx.fillStyle = 'rgba(110, 145, 175, 0.42)';
          ctx.font = '8px "Share Tech Mono", monospace';
          ctx.fillText(`${100 - division * 25}`, left + 4, y - 4);
        }
      }

      let values = prepareValues(dataRef.current);
      if (values.length < 2) {
        const base = values[0] ?? 0;
        values = [base, base];
      }
      const slot = chartWidth / (MAX_SAMPLES - 1);
      const startX = values.length >= MAX_SAMPLES ? left : width - right - slot * (values.length - 1);
      const points = values.map((value, index) => ({
        x: startX + slot * index,
        y: top + (1 - value / 100) * chartHeight,
      }));

      const trace = () => {
        ctx.beginPath();
        ctx.moveTo(points[0].x, points[0].y);
        for (let index = 0; index < points.length - 1; index++) {
          const current = points[index], next = points[index + 1];
          const middleX = (current.x + next.x) / 2;
          ctx.bezierCurveTo(middleX, current.y, middleX, next.y, next.x, next.y);
        }
      };

      trace();
      ctx.save();
      ctx.translate(0, 3);
      ctx.strokeStyle = `rgba(${strokeRgb}, 0.13)`;
      ctx.lineWidth = 5;
      ctx.stroke();
      ctx.restore();

      trace();
      ctx.lineTo(points[points.length - 1].x, height - bottom);
      ctx.lineTo(points[0].x, height - bottom);
      ctx.closePath();
      const fill = ctx.createLinearGradient(0, top, 0, height - bottom);
      fill.addColorStop(0, `rgba(${strokeRgb}, 0.24)`);
      fill.addColorStop(0.55, `rgba(${strokeRgb}, 0.07)`);
      fill.addColorStop(1, `rgba(${strokeRgb}, 0)`);
      ctx.fillStyle = fill;
      ctx.fill();

      trace();
      ctx.shadowColor = strokeColor;
      ctx.shadowBlur = 9;
      ctx.strokeStyle = `rgba(${strokeRgb}, 0.38)`;
      ctx.lineWidth = 4;
      ctx.stroke();
      ctx.shadowBlur = 0;
      trace();
      ctx.strokeStyle = strokeColor;
      ctx.lineWidth = 1.8;
      ctx.stroke();

      const head = points[points.length - 1];
      const pulse = 3.2 + Math.sin(frameRef.current * 0.12) * 0.8;
      ctx.strokeStyle = `rgba(${strokeRgb}, 0.16)`;
      ctx.setLineDash([3, 5]);
      ctx.beginPath(); ctx.moveTo(head.x, top); ctx.lineTo(head.x, height - bottom); ctx.stroke();
      ctx.setLineDash([]);
      ctx.shadowColor = strokeColor;
      ctx.shadowBlur = 12;
      ctx.fillStyle = '#ffffff';
      ctx.beginPath(); ctx.arc(head.x, head.y, 1.7, 0, Math.PI * 2); ctx.fill();
      ctx.strokeStyle = `rgba(${strokeRgb}, 0.7)`;
      ctx.lineWidth = 1;
      ctx.beginPath(); ctx.arc(head.x, head.y, pulse, 0, Math.PI * 2); ctx.stroke();
      ctx.shadowBlur = 0;

      ctx.fillStyle = strokeColor;
      ctx.font = '10px "Share Tech Mono", monospace';
      ctx.textAlign = 'right';
      const latestRaw = dataRef.current?.[dataRef.current.length - 1]?.value ?? 0;
      ctx.fillText(`${Math.max(0, Math.min(100, latestRaw)).toFixed(1)}%`, width - right, 18);
      ctx.textAlign = 'left';
    };

    animationId = requestAnimationFrame(render);
    return () => { cancelAnimationFrame(animationId); observer.disconnect(); };
  }, [strokeColor, strokeRgb]);

  const borderColor = color === 'cyan' ? 'var(--cyan)' : 'var(--green-cyan)';
  return (
    <motion.div initial={{ opacity: 0, scale: 0.98 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: 0.25 }} className="tech-card relative overflow-hidden flex flex-col" style={{ border: `1px solid ${borderColor}` }}>
      <span className="corner corner-tl" style={{ borderColor }} />
      <span className="corner corner-tr" style={{ borderColor }} />
      <span className="corner corner-bl" style={{ borderColor }} />
      <span className="corner corner-br" style={{ borderColor }} />
      <div className="absolute top-2 left-3 z-10 flex items-center gap-2 text-[10px] font-['Share_Tech_Mono'] tracking-[0.12em]" style={{ color: 'rgba(135, 170, 200, 0.68)' }}>
        <span className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: strokeColor, boxShadow: `0 0 7px ${strokeColor}` }} />
        {title}
      </div>
      <canvas ref={canvasRef} className="flex-1 w-full" style={{ display: 'block' }} aria-label={`${title} telemetry chart`} />
    </motion.div>
  );
}
