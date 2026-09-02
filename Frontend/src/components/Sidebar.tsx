import { useState, useEffect, useRef, type KeyboardEvent } from 'react';
import { motion } from 'framer-motion';
import { HologramSphere } from './HologramSphere';

const DashboardIcon = () => (
  <svg width="28" height="28" viewBox="0 0 28 28" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
    <rect x="2" y="2" width="10" height="10" rx="0.8" />
    <rect x="16" y="2" width="10" height="10" rx="0.8" />
    <rect x="2" y="16" width="10" height="10" rx="0.8" />
    <rect x="16" y="16" width="10" height="10" rx="0.8" />
    <circle cx="21" cy="21" r="2" fill="currentColor" stroke="none" opacity="0.9" />
  </svg>
);

const ThreatsIcon = () => (
  <svg width="28" height="28" viewBox="0 0 28 28" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
    <path d="M14 2L2 7V14C2 21 7.8 26.4 14 28C20.2 26.4 26 21 26 14V7L14 2Z" />
    <line x1="14" y1="9" x2="14" y2="17" strokeWidth="2.2" />
    <circle cx="14" cy="21" r="1.4" fill="currentColor" stroke="none" />
  </svg>
);

const ProcessesIcon = () => (
  <svg width="28" height="28" viewBox="0 0 28 28" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
    <rect x="7" y="7" width="14" height="14" rx="1" />
    <rect x="11" y="11" width="6" height="6" rx="0.5" />
    <line x1="11" y1="7" x2="11" y2="3" /><line x1="17" y1="7" x2="17" y2="3" />
    <line x1="11" y1="21" x2="11" y2="25" /><line x1="17" y1="21" x2="17" y2="25" />
    <line x1="7" y1="11" x2="3" y2="11" /><line x1="7" y1="17" x2="3" y2="17" />
    <line x1="21" y1="11" x2="25" y2="11" /><line x1="21" y1="17" x2="25" y2="17" />
  </svg>
);

const NetworkIcon = () => (
  <svg width="28" height="28" viewBox="0 0 28 28" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round">
    <circle cx="14" cy="14" r="12" />
    <ellipse cx="14" cy="14" rx="5" ry="12" />
    <line x1="2" y1="10" x2="26" y2="10" />
    <line x1="2" y1="14" x2="26" y2="14" />
    <line x1="2" y1="18" x2="26" y2="18" />
    <circle cx="14" cy="14" r="2" fill="currentColor" stroke="none" />
  </svg>
);

const LogsIcon = () => (
  <svg width="28" height="28" viewBox="0 0 28 28" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
    <path d="M6 2H18L22 6V25A1 1 0 0121 26H6A1 1 0 015 25V3A1 1 0 016 2Z" />
    <polyline points="18,2 18,7 22,7" />
    <line x1="9" y1="12" x2="19" y2="12" />
    <line x1="9" y1="16" x2="19" y2="16" />
    <line x1="9" y1="20" x2="15" y2="20" />
    <circle cx="17" cy="20" r="1.2" fill="currentColor" stroke="none" />
  </svg>
);

const SettingsIcon = () => (
  <svg width="28" height="28" viewBox="0 0 28 28" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <path d="M14 3L16.2 4.8 19 4.2 20.6 6.8 19 8.8 19.5 11.8 16.8 12.8 15.8 15.6 13.2 15.6 12.2 12.8 9.5 11.8 10 8.8 8.4 6.8 10 4.2 12.8 4.8Z" />
    <path d="M14 25L11.8 23.2 9 23.8 7.4 21.2 9 19.2 8.5 16.2 11.2 15.2 12.2 12.4 14.8 12.4 15.8 15.2 18.5 16.2 18 19.2 19.6 21.2 18 23.8 15.2 23.2Z" />
    <circle cx="14" cy="14" r="4" />
  </svg>
);

const FaqIcon = () => (
  <svg width="28" height="28" viewBox="0 0 28 28" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="14" cy="14" r="12" />
    <path d="M9.8 10.2A4.4 4.4 0 0114 7.5c2.5 0 4.5 1.6 4.5 3.8 0 3.3-4.5 3.3-4.5 6.1" />
    <circle cx="14" cy="21.5" r="1" fill="currentColor" stroke="none" />
  </svg>
);

// ── HUD Ring Wrapper ──────────────────────────────────────────
interface HudIconProps {
  icon: React.ReactNode;
  active?: boolean;
}

const HudIcon: React.FC<HudIconProps> = ({ icon, active }) => {
  const cyan = active ? '#00f0ff' : 'rgba(0,190,210,0.4)';
  return (
    <div className="relative flex-shrink-0" style={{ width: 38, height: 38 }}>
      {/* Outer dashed ring - rotates */}
      <div style={{
        position: 'absolute', inset: 0, borderRadius: '50%',
        border: `1px dashed ${active ? 'rgba(0,240,255,0.55)' : 'rgba(0,180,200,0.22)'}`,
        animation: `hudSpin ${active ? '5s' : '14s'} linear infinite`,
      }} />
      {/* Arrow tick at top of outer ring */}
      <div style={{
        position: 'absolute', top: 0, left: '50%',
        width: 5, height: 5,
        borderTop: `1.5px solid ${cyan}`,
        borderRight: `1.5px solid ${cyan}`,
        transform: 'translateX(-50%) rotate(45deg)',
        boxShadow: active ? `0 0 5px ${cyan}` : 'none',
      }} />
      {/* Mid ring - counter-rotates */}
      <div style={{
        position: 'absolute', inset: 5, borderRadius: '50%',
        border: `1px solid ${active ? 'rgba(0,240,255,0.28)' : 'rgba(0,180,200,0.1)'}`,
        animation: `hudSpinRev ${active ? '9s' : '20s'} linear infinite`,
      }} />
      {/* Dot on mid ring */}
      <div style={{
        position: 'absolute', top: 4, left: '50%',
        width: active ? 3 : 2, height: active ? 3 : 2,
        borderRadius: '50%', background: cyan,
        transform: 'translateX(-50%)',
        boxShadow: active ? `0 0 6px ${cyan}` : 'none',
      }} />
      {/* Inner circle face */}
      <div style={{
        position: 'absolute', inset: 9, borderRadius: '50%',
        background: active
          ? 'radial-gradient(circle at 35% 35%, #0a2a40, #060b18)'
          : 'radial-gradient(circle at 35% 35%, #081620, #060b18)',
        border: `1.2px solid ${active ? 'rgba(0,240,255,0.65)' : 'rgba(0,180,200,0.18)'}`,
        boxShadow: active
          ? '0 0 0 2px rgba(0,240,255,0.06), 0 0 14px rgba(0,240,255,0.2), inset 0 0 12px rgba(0,30,60,0.7)'
          : 'inset 0 0 8px rgba(0,8,24,0.8)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        transition: 'all 0.3s',
      }}>
        <div style={{
          color: active ? '#00f0ff' : 'rgba(0,150,170,0.5)',
          filter: active ? 'drop-shadow(0 0 4px #00f0ff) drop-shadow(0 0 10px rgba(0,240,255,0.5))' : 'none',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          transform: 'scale(0.46)',
        }}>
          {icon}
        </div>
      </div>
    </div>
  );
};

// ── Nav data ──────────────────────────────────────────────────
const navItems = [
  { id: 'dashboard', label: 'DASHBOARD', icon: <DashboardIcon /> },
  { id: 'threats', label: 'THREATS', icon: <ThreatsIcon /> },
  { id: 'processes', label: 'PROCESSES', icon: <ProcessesIcon /> },
  { id: 'network', label: 'NETWORK', icon: <NetworkIcon /> },
  { id: 'logs', label: 'LOGS', icon: <LogsIcon /> },
  { id: 'settings', label: 'SETTINGS', icon: <SettingsIcon /> },
  { id: 'faq', label: 'FAQ / ABOUT', icon: <FaqIcon /> },
];

// ── Sidebar ───────────────────────────────────────────────────
interface SidebarProps {
  activeView: number;
  onNavigate: (viewId: number) => void;
}

export function Sidebar({ activeView, onNavigate }: SidebarProps) {
  const [statusText, setStatusText] = useState('INITIALIZING MONITORING...');
  const navButtons = useRef<Array<HTMLButtonElement | null>>([]);

  useEffect(() => {
    window.updateSidebarStatus = (text: string) => setStatusText(text);
    return () => { delete window.updateSidebarStatus; };
  }, []);

  return (
    <aside className="w-[220px] bg-[var(--bg-dark)] flex flex-col border-r border-[rgba(0,240,255,0.15)] relative overflow-hidden">
      <style>{`
        @keyframes hudSpin    { to { transform: rotate(360deg); } }
        @keyframes hudSpinRev { to { transform: rotate(-360deg); } }
      `}</style>

      <div className="absolute inset-0" style={{
        backgroundImage: 'url(./background.png)',
        backgroundSize: 'cover', backgroundPosition: 'left center', opacity: 0.5,
      }} />
      <div className="absolute inset-0 bg-[var(--bg-dark)] opacity-70" />

      {/* Logo */}
      <div className="relative z-10 px-4 py-3 border-b border-[rgba(0,240,255,0.15)]">
        <img
          src="./blackwatch-logo.png"
          alt="Softcurse Blackwatch"
          className="w-full h-[82px] object-contain drop-shadow-[0_0_10px_rgba(0,240,255,0.35)]"
        />
        <p className="-mt-1 text-center text-[8px] tracking-[0.2em] text-[rgba(0,240,255,0.55)] font-['Share_Tech_Mono']">
          A SOFTCURSE CREATION · v0.1.0 EARLY ALPHA
        </p>
      </div>

      {/* Nav */}
      <nav className="relative z-10 flex-1 py-2" aria-label="Blackwatch sections">
        <ul className="space-y-0.5">
          {navItems.map((item, index) => {
            const isActive = index === activeView;
            return (
              <li key={item.id}>
                <button
                  ref={(element) => { navButtons.current[index] = element; }}
                  onClick={() => onNavigate(index)}
                  onKeyDown={(event: KeyboardEvent<HTMLButtonElement>) => {
                    const last = navItems.length - 1;
                    const target = event.key === 'ArrowDown' ? (index + 1) % navItems.length
                      : event.key === 'ArrowUp' ? (index - 1 + navItems.length) % navItems.length
                      : event.key === 'Home' ? 0
                      : event.key === 'End' ? last
                      : null;
                    if (target === null) return;
                    event.preventDefault();
                    navButtons.current[target]?.focus();
                    onNavigate(target);
                  }}
                  aria-current={isActive ? 'page' : undefined}
                  className={`w-full flex items-center gap-3 px-4 py-1 text-xs tracking-wider transition-all relative
                    ${isActive
                      ? 'text-[var(--cyan)] bg-[rgba(0,240,255,0.08)]'
                      : 'text-[var(--text-dim)] hover:text-[rgba(0,220,240,0.65)] hover:bg-[rgba(0,240,255,0.03)]'}`}
                >
                  {isActive && (
                    <motion.div
                      layoutId="activeIndicator"
                      className="absolute left-0 top-0 bottom-0 w-[3px] bg-[var(--cyan)]"
                      style={{ boxShadow: '0 0 8px var(--cyan), 0 0 15px var(--cyan)' }}
                      initial={false}
                      transition={{ type: 'spring', stiffness: 500, damping: 30 }}
                    />
                  )}
                  <HudIcon icon={item.icon} active={isActive} />
                  <span className="font-['Share_Tech_Mono']">{item.label}</span>
                </button>
              </li>
            );
          })}
        </ul>
      </nav>

      {/* Globe */}
      <div className="relative z-10 p-1">
        <div className="relative w-full aspect-square max-w-[150px] mx-auto overflow-hidden">
          <HologramSphere />
        </div>
      </div>

      {/* Cables */}
      <div className="relative z-10 h-8 overflow-hidden">
        <div className="absolute inset-0" style={{
          backgroundImage: 'url(./cables.png)',
          backgroundSize: 'cover', backgroundPosition: 'bottom center',
          mixBlendMode: 'screen', opacity: 0.6, transform: 'scaleX(-1)',
        }} />
      </div>

      <div className="relative z-10 px-4 py-3 border-t border-[rgba(0,240,255,0.15)]">
        <p className="text-[10px] text-[var(--cyan)] text-glow-cyan text-center tracking-wide font-['Share_Tech_Mono']">
          {statusText}
        </p>
      </div>
    </aside>
  );
}
