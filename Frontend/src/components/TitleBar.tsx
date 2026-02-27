import { MinusIcon, SquareIcon, XIcon } from 'lucide-react';

function sendCmd(cmd: string) {
  try { (window as any).chrome?.webview?.postMessage(cmd); } catch { }
}

export function TitleBar() {
  return (
    <div
      className="h-8 bg-[#0a0e14] flex items-center justify-between px-3 border-b border-[rgba(0,240,255,0.1)] select-none"
      onMouseDown={(e) => {
        // Only drag on left-click, not on buttons
        if (e.button === 0 && (e.target as HTMLElement).closest('button') === null) {
          sendCmd('dragstart');
        }
      }}
    >
      {/* Left side - App title */}
      <div className="flex items-center gap-2">
        <div
          className="w-2.5 h-2.5 rounded-full bg-[#00ff88]"
          style={{
            boxShadow:
              '0 0 6px rgba(0,255,136,0.8), 0 0 12px rgba(0,255,136,0.4)'
          }} />

        <span className="text-[10px] tracking-widest text-[var(--text-dim)] font-['Share_Tech_Mono']">
          SOFTCURSE SENTINEL
        </span>
      </div>

      {/* Right side - Window controls */}
      <div className="flex items-center gap-0">
        <button
          onClick={() => sendCmd('minimize')}
          className="w-10 h-8 flex items-center justify-center text-[var(--text-dim)] hover:bg-[rgba(255,255,255,0.05)] transition-colors"
          aria-label="Minimize">
          <MinusIcon size={12} strokeWidth={1.5} />
        </button>
        <button
          onClick={() => sendCmd('maximize')}
          className="w-10 h-8 flex items-center justify-center text-[var(--text-dim)] hover:bg-[rgba(255,255,255,0.05)] transition-colors"
          aria-label="Maximize">
          <SquareIcon size={10} strokeWidth={1.5} />
        </button>
        <button
          onClick={() => sendCmd('close')}
          className="w-10 h-8 flex items-center justify-center text-[var(--text-dim)] hover:bg-red-600 hover:text-white transition-colors"
          aria-label="Close">
          <XIcon size={12} strokeWidth={1.5} />
        </button>
      </div>
    </div>);
}