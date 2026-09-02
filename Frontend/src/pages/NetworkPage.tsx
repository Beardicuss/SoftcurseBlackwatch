import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { ChevronDown, ChevronRight } from 'lucide-react';

interface NetworkEvidence {
  ruleId: string;
  description: string;
  observedValue: string;
  confidence: string;
  sourceEvidenceId: string;
}

interface Connection {
  connectionId: string;
  protocol: string;
  addressFamily: string;
  state: string;
  localEndpoint: string;
  remoteEndpoint: string;
  remoteHostName: string;
  remotePort: number;
  processName: string;
  processIsSigned: boolean | null;
  processCompanyName: string;
  processFileHash: string;
  suspiciousReason: string;
  confidence: string;
  firstSeenUtc: string;
  lastSeenUtc: string;
  observationCount: number;
  evidence: NetworkEvidence[];
}

interface NetworkPayload { items?: Connection[]; count?: number; suspiciousCount?: number }

export function NetworkPage() {
  const [connections, setConnections] = useState<Connection[]>([]);
  const [count, setCount] = useState(0);
  const [suspiciousCount, setSuspiciousCount] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    window.updateNetwork = (json: string) => {
      try {
        const data = JSON.parse(json) as NetworkPayload;
        setConnections(Array.isArray(data.items) ? data.items : []);
        setCount(typeof data.count === 'number' ? data.count : 0);
        setSuspiciousCount(typeof data.suspiciousCount === 'number' ? data.suspiciousCount : 0);
      } catch (error) { console.error('Invalid network payload', error); }
    };
    return () => { delete window.updateNetwork; };
  }, []);

  const confidenceColor = (confidence: string) => ({
    high: '#ff5577', medium: '#ffaa00', low: '#00d8e8', none: '#4a6a8a'
  }[confidence?.toLowerCase()] ?? '#4a6a8a');

  const formatTime = (value: string) => {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? '—' : date.toLocaleTimeString();
  };

  return (
    <div className="flex-1 flex flex-col p-5 overflow-hidden">
      <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} className="flex items-center gap-3 mb-5">
        <div className="flex items-center justify-center w-6 h-6 border border-[var(--cyan)]" aria-hidden="true">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" strokeWidth="1.6"><circle cx="12" cy="12" r="10" /><ellipse cx="12" cy="12" rx="4" ry="10" /></svg>
        </div>
        <h2 className="text-lg font-['Orbitron'] font-bold text-[var(--cyan)] text-glow-cyan tracking-wider">NETWORK EVIDENCE</h2>
        <span className="text-xs text-[var(--text-dim)] font-['Share_Tech_Mono']">— {count} active</span>
        {suspiciousCount > 0 && <span className="text-xs font-bold text-[#ff2244] font-['Share_Tech_Mono']">({suspiciousCount} corroborated)</span>}
      </motion.div>

      <div className="flex-1 overflow-auto">
        <table className="w-full text-xs font-['Share_Tech_Mono']">
          <thead><tr className="border-b border-[rgba(0,240,255,0.2)]">
            <th className="w-8" aria-label="Connection evidence" />
            {['PROTOCOL', 'STATUS', 'PROCESS', 'LOCAL', 'REMOTE', 'CONFIDENCE', 'SEEN'].map(label =>
              <th key={label} className="text-left py-2 px-3 text-[var(--cyan)] font-normal tracking-wider">{label}</th>)}
          </tr></thead>
          <tbody>
            {connections.length === 0 ? (
              <tr><td colSpan={8} className="py-8 text-center text-[var(--text-dim)]">No active connections</td></tr>
            ) : connections.map(connection => {
              const open = expanded === connection.connectionId;
              return [
                <tr key={connection.connectionId} className="border-b border-[rgba(0,240,255,0.05)] hover:bg-[rgba(0,240,255,0.03)] transition-colors">
                  <td className="pl-2"><button type="button" className="p-1 text-[var(--cyan)] focus-visible:outline focus-visible:outline-1 focus-visible:outline-[var(--cyan)]" aria-expanded={open} aria-label={`${open ? 'Hide' : 'Show'} connection evidence`} onClick={() => setExpanded(open ? null : connection.connectionId)}>{open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</button></td>
                  <td className="py-2 px-3 text-[var(--text-primary)]">{connection.protocol}/{connection.addressFamily}</td>
                  <td className="py-2 px-3 text-[var(--text-primary)]">{connection.state}</td>
                  <td className="py-2 px-3 text-[var(--text-primary)]">{connection.processName}</td>
                  <td className="py-2 px-3 text-[var(--text-dim)]">{connection.localEndpoint}</td>
                  <td className="py-2 px-3 text-[var(--text-dim)]">
                    <div>{connection.remoteEndpoint}</div>
                    {connection.remoteHostName && <div className="text-[10px] text-[var(--cyan)] truncate max-w-[220px]">{connection.remoteHostName}</div>}
                  </td>
                  <td className="py-2 px-3 font-bold" style={{ color: confidenceColor(connection.confidence) }}>{connection.confidence}</td>
                  <td className="py-2 px-3 text-[var(--text-dim)]">{connection.observationCount}×</td>
                </tr>,
                open && <tr key={`${connection.connectionId}:detail`} className="border-b border-[rgba(0,240,255,0.12)] bg-[rgba(2,12,28,0.88)]"><td colSpan={8} className="p-4">
                  <div className="flex justify-between gap-4 mb-3">
                    <div>
                      <div className="text-[var(--text-primary)]">{connection.suspiciousReason || 'No suspicious network evidence observed.'}</div>
                      <div className="mt-1 text-[10px] text-[var(--text-dim)]">
                        Binary: {connection.processIsSigned === true ? 'SIGNED' : connection.processIsSigned === false ? 'UNSIGNED' : 'UNKNOWN'}
                        {connection.processCompanyName ? ` · ${connection.processCompanyName}` : ''}
                        {connection.processFileHash ? ` · SHA256 ${connection.processFileHash.slice(0, 16)}…` : ''}
                      </div>
                    </div>
                    <div className="text-[10px] text-[var(--text-dim)] whitespace-nowrap">FIRST {formatTime(connection.firstSeenUtc)} · LAST {formatTime(connection.lastSeenUtc)}</div>
                  </div>
                  {connection.evidence.length === 0 ? <div className="text-[var(--text-dim)]">No evidence attached.</div> : connection.evidence.map(item =>
                    <div key={`${item.ruleId}:${item.observedValue}`} className="grid grid-cols-[180px_70px_minmax(0,1fr)] gap-3 border-l-2 border-[rgba(0,240,255,0.4)] bg-[rgba(0,240,255,0.035)] px-3 py-2 mb-2">
                      <div className="text-[var(--cyan)]">{item.ruleId}</div>
                      <div className="font-bold" style={{ color: confidenceColor(item.confidence) }}>{item.confidence}</div>
                      <div><div className="text-[var(--text-primary)]">{item.description}</div><div className="text-[10px] text-[var(--text-dim)]">Observed: {item.observedValue}{item.sourceEvidenceId ? ` · Evidence ${item.sourceEvidenceId.slice(0, 12)}…` : ''}</div></div>
                    </div>)}
                </td></tr>
              ];
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
