import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { ChevronDown, ChevronRight } from 'lucide-react';

interface ThreatEvidence {
  evidenceId: string;
  name: string;
  description: string;
  observedValue: string;
  weight: number;
  category: string;
  confidence: string;
  ruleVersion: string;
}

interface Threat {
  level: string;
  score: number;
  processName: string;
  pid: number;
  path: string;
  action: string;
  confidence: string;
  explanation: string;
  ruleSetVersion: string;
  evidence: ThreatEvidence[];
}

interface ThreatPayload { items?: Threat[]; count?: number }

export function ThreatsPage() {
  const [threats, setThreats] = useState<Threat[]>([]);
  const [count, setCount] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    window.updateThreats = (json: string) => {
      try {
        const data = JSON.parse(json) as ThreatPayload;
        setThreats(Array.isArray(data.items) ? data.items : []);
        setCount(typeof data.count === 'number' ? data.count : 0);
      } catch (error) { console.error('Invalid threat payload', error); }
    };
    return () => { delete window.updateThreats; };
  }, []);

  const levelColor = (level: string) => ({
    critical: '#ff2244', high: '#ff6600', suspicious: '#ffaa00', low: '#00f0ff'
  }[level?.toLowerCase()] ?? '#4a6a8a');

  const confidenceColor = (confidence: string) => ({
    high: '#ff5577', medium: '#ffaa00', low: '#00d8e8', none: '#4a6a8a'
  }[confidence?.toLowerCase()] ?? '#4a6a8a');

  return (
    <div className="flex-1 flex flex-col p-5 overflow-hidden">
      <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} className="flex items-center gap-3 mb-5">
        <div className="flex items-center justify-center w-6 h-6 border border-[var(--cyan)]" aria-hidden="true">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" strokeWidth="2"><path d="M12 2L2 7V14C2 21 7.8 26.4 14 28C20.2 26.4 26 21 26 14V7L12 2Z" /></svg>
        </div>
        <h2 className="text-lg font-['Orbitron'] font-bold text-[var(--cyan)] text-glow-cyan tracking-wider">EVIDENCE REVIEW</h2>
        <span className="text-xs text-[var(--text-dim)] font-['Share_Tech_Mono']">— {count} flagged</span>
      </motion.div>

      <div className="flex-1 overflow-auto">
        <table className="w-full text-xs font-['Share_Tech_Mono']">
          <thead>
            <tr className="border-b border-[rgba(0,240,255,0.2)]">
              <th className="w-8" aria-label="Evidence details" />
              {['LEVEL', 'CONFIDENCE', 'SCORE', 'PROCESS', 'PID', 'ACTION'].map(label =>
                <th key={label} className="text-left py-2 px-3 text-[var(--cyan)] font-normal tracking-wider">{label}</th>)}
            </tr>
          </thead>
          <tbody>
            {threats.length === 0 ? (
              <tr><td colSpan={7} className="py-8 text-center text-[var(--text-dim)]">No reviewable evidence detected</td></tr>
            ) : threats.map((threat) => {
              const rowId = `${threat.pid}:${threat.ruleSetVersion}`;
              const isExpanded = expanded === rowId;
              return [
                <tr key={rowId} className="border-b border-[rgba(0,240,255,0.05)] hover:bg-[rgba(0,240,255,0.03)] transition-colors">
                  <td className="pl-2">
                    <button
                      type="button"
                      className="p-1 text-[var(--cyan)] focus-visible:outline focus-visible:outline-1 focus-visible:outline-[var(--cyan)]"
                      aria-expanded={isExpanded}
                      aria-label={`${isExpanded ? 'Hide' : 'Show'} evidence for ${threat.processName}`}
                      onClick={() => setExpanded(isExpanded ? null : rowId)}
                    >{isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</button>
                  </td>
                  <td className="py-2 px-3 font-bold" style={{ color: levelColor(threat.level) }}>{threat.level}</td>
                  <td className="py-2 px-3 font-bold" style={{ color: confidenceColor(threat.confidence) }}>{threat.confidence}</td>
                  <td className="py-2 px-3 text-[var(--text-primary)]">{threat.score}</td>
                  <td className="py-2 px-3 text-[var(--text-primary)]">{threat.processName}</td>
                  <td className="py-2 px-3 text-[var(--text-dim)]">{threat.pid}</td>
                  <td className="py-2 px-3 font-bold text-[var(--magenta)]">{threat.action}</td>
                </tr>,
                isExpanded && <tr key={`${rowId}:evidence`} className="border-b border-[rgba(0,240,255,0.12)] bg-[rgba(2,12,28,0.88)]">
                  <td colSpan={7} className="p-4">
                    <div className="grid grid-cols-[minmax(0,1fr)_auto] gap-3 mb-3">
                      <div>
                        <div className="text-[var(--text-primary)]">{threat.explanation}</div>
                        <div className="mt-1 text-[var(--text-dim)] break-all">{threat.path || 'Executable path unavailable'}</div>
                      </div>
                      <div className="text-[10px] text-[var(--text-dim)]">RULESET {threat.ruleSetVersion || 'BUILT-IN'}</div>
                    </div>
                    <div className="space-y-2">
                      {threat.evidence.map(item => (
                        <div key={item.evidenceId} className="grid grid-cols-[130px_70px_minmax(0,1fr)] gap-3 border-l-2 border-[rgba(0,240,255,0.4)] bg-[rgba(0,240,255,0.035)] px-3 py-2">
                          <div>
                            <div className="text-[var(--cyan)]">{item.name}</div>
                            <div className="text-[10px] text-[var(--text-dim)]">+{item.weight} · {item.category}</div>
                          </div>
                          <div className="font-bold" style={{ color: confidenceColor(item.confidence) }}>{item.confidence}</div>
                          <div>
                            <div className="text-[var(--text-primary)]">{item.description}</div>
                            <div className="mt-1 text-[10px] text-[var(--text-dim)] break-all">Observed: {item.observedValue} · Rule {item.ruleVersion}</div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </td>
                </tr>
              ];
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
