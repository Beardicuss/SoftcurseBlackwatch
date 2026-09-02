import { useState, useEffect, useCallback } from 'react';
import { LayoutDashboardIcon } from 'lucide-react';
import { motion } from 'framer-motion';
import { StatCard } from '../components/StatCard';
import { UsageChart } from '../components/UsageChart';

// ── Bridge types ──
interface BlackwatchData {
  cpu: number;
  ramUsedMB: number;
  ramPercent: number;
  processCount: number;
  threatCount: number;
  cpuHistory: number[];
  ramHistory: number[];
  statusText: string;
  isScanning: boolean;
  healthLevel: 'Healthy' | 'Degraded' | 'Error';
  healthMessage: string;
  lastSuccessfulScanUtc: string | null;
}

// Default data shown before C# connects
const defaultData: BlackwatchData = {
  cpu: 0,
  ramUsedMB: 0,
  ramPercent: 0,
  processCount: 0,
  threatCount: 0,
  cpuHistory: [],
  ramHistory: [],
  statusText: 'INITIALIZING MONITORING...',
  isScanning: false,
  healthLevel: 'Error',
  healthMessage: 'Telemetry has not completed yet.',
  lastSuccessfulScanUtc: null,
};

function getInitialData(): BlackwatchData {
  const initialJson = window.__blackwatchData ?? window.__sentinelData;
  if (!initialJson) return defaultData;

  try {
    return JSON.parse(initialJson) as BlackwatchData;
  } catch {
    return defaultData;
  }
}

export function Dashboard() {
  const [data, setData] = useState<BlackwatchData>(getInitialData);

  // C# calls this function to push data
  const handleUpdate = useCallback((json: string) => {
    try {
      const parsed = JSON.parse(json) as BlackwatchData;
      setData(parsed);
      // Forward status to StatusBar
      window.updateStatusBar?.(parsed.statusText, parsed.isScanning);
      // Forward threat state to HologramSphere
      window.updateThreatState?.(parsed.threatCount > 0);
      // Forward status to Sidebar
      window.updateSidebarStatus?.(parsed.statusText);
    } catch { /* ignore bad JSON */ }
  }, []);

  useEffect(() => {
    // Expose the update function globally so C# can call it
    window.updateBlackwatchData = handleUpdate;
    // One-release compatibility alias for older desktop shells.
    window.updateSentinelData = handleUpdate;

    return () => {
      delete window.updateBlackwatchData;
      delete window.updateSentinelData;
    };
  }, [handleUpdate]);

  // Convert arrays to chart format
  const cpuChartData = data.cpuHistory.map(v => ({ value: v }));
  const ramChartData = data.ramHistory.map(v => ({ value: v }));

  return (
    <div className="flex-1 flex flex-col relative overflow-hidden">
      {/* Cables image in the bottom area of main content */}
      <div
        className="absolute bottom-0 left-0 right-0 pointer-events-none z-0"
        style={{
          height: '40%',
          backgroundImage:
            'url(./cables.png)',
          backgroundSize: 'contain',
          backgroundPosition: 'bottom right',
          backgroundRepeat: 'no-repeat',
          mixBlendMode: 'screen',
          opacity: 0.5,
          transform: 'scaleX(-1)'
        }} />

      {/* Main content */}
      <div className="relative z-10 flex-1 flex flex-col p-5 overflow-auto">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          className="flex items-center gap-2 mb-5">
          <div className="flex items-center justify-center w-6 h-6 border border-[var(--cyan)]">
            <LayoutDashboardIcon size={14} className="text-[var(--cyan)]" />
          </div>
          <h2 className="text-lg font-['Orbitron'] font-bold text-[var(--cyan)] text-glow-cyan tracking-wider">
            DASHBOARD
          </h2>
        </motion.div>

        <div
          role="status"
          className={`mb-4 border px-3 py-2 text-xs font-['Share_Tech_Mono'] ${
            data.healthLevel === 'Healthy'
              ? 'border-[rgba(0,255,170,0.35)] text-[var(--green)] bg-[rgba(0,255,170,0.05)]'
              : 'border-[rgba(255,170,0,0.45)] text-[#ffaa00] bg-[rgba(255,170,0,0.07)]'
          }`}
        >
          TELEMETRY: {data.healthLevel.toUpperCase()} — {data.healthMessage}
          {data.lastSuccessfulScanUtc && ` • Last complete cycle: ${new Date(data.lastSuccessfulScanUtc).toLocaleTimeString()}`}
        </div>

        {/* Stat cards row */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.1 }}
          className="grid grid-cols-4 gap-4 mb-5">
          <StatCard label="CPU" value={data.cpu.toFixed(1)} unit="%" progress={data.cpu} variant="cyan" />
          <StatCard label="MEMORY" value={Math.round(data.ramUsedMB).toString()} unit="MB" progress={data.ramPercent} variant="cyan" />
          <StatCard label="PROCESSES" value={data.processCount.toString()} variant="cyan" />
          <StatCard label="THREATS" value={data.threatCount.toString()} variant="magenta" />
        </motion.div>

        {/* Charts row */}
        <div className="flex-1 grid grid-cols-2 gap-5 min-h-[280px]">
          <UsageChart title="CPU USAGE HISTORY" data={cpuChartData.length > 1 ? cpuChartData : undefined} color="cyan" />
          <UsageChart title="MEMORY USAGE HISTORY" data={ramChartData.length > 1 ? ramChartData : undefined} color="green" />
        </div>
      </div>
    </div>);
}
