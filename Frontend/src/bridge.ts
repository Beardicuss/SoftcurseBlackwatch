export type BridgeCommand =
  | { version: 1; type: 'window'; action: 'minimize' | 'maximize' | 'close' | 'dragstart' }
  | { version: 1; type: 'app'; action: 'scan' | 'purge' }
  | { version: 1; type: 'navigate'; viewId: number }
  | { version: 1; type: 'process'; action: 'kill'; pid: number }
  | { version: 1; type: 'setting'; action: 'dryrun' | 'tray'; enabled: boolean }
  | { version: 1; type: 'whitelist'; action: 'remove'; value: string }
  | { version: 1; type: 'trusted'; action: 'remove'; value: string }
  | { version: 1; type: 'trusted'; action: 'browse' }
  | { version: 1; type: 'diagnostics'; action: 'export' }
  | { version: 1; type: 'recovery'; action: 'restore' | 'finalize' | 'dismiss'; value: string };

type SnapshotMessage = { version: 1; type: 'snapshot'; channel: string; data: unknown };

declare global {
  interface Window {
    chrome?: { webview?: { postMessage(message: BridgeCommand): void } };
    setActiveView?: (viewId: number) => void;
    updateStatusBar?: (text: string, scanning: boolean) => void;
    updateThreatCount?: (count: number) => void;
    updateConnectionCount?: (count: number) => void;
    updateThreatState?: (active: boolean) => void;
    updateSidebarStatus?: (text: string) => void;
    updateBlackwatchData?: (json: string) => void;
    updateSentinelData?: (json: string) => void;
    __blackwatchData?: string;
    __sentinelData?: string;
    updateThreats?: (json: string) => void;
    updateProcesses?: (json: string) => void;
    updateNetwork?: (json: string) => void;
    updateLogs?: (json: string) => void;
    updateSettings?: (json: string) => void;
  }
}

type UnversionedCommand<T> = T extends unknown ? Omit<T, 'version'> : never;

export function sendBridgeCommand(command: UnversionedCommand<BridgeCommand>): boolean {
  const bridge = window.chrome?.webview;
  if (!bridge) {
    console.warn('Blackwatch desktop bridge is unavailable', command);
    return false;
  }

  bridge.postMessage({ version: 1, ...command } as BridgeCommand);
  return true;
}

export function installSnapshotBridge(): () => void {
  const bridge = window.chrome?.webview as ({
    addEventListener?: (type: 'message', listener: (event: MessageEvent<SnapshotMessage>) => void) => void;
    removeEventListener?: (type: 'message', listener: (event: MessageEvent<SnapshotMessage>) => void) => void;
  } | undefined);
  if (!bridge?.addEventListener) return () => undefined;

  const listener = (event: MessageEvent<SnapshotMessage>) => {
    const message = event.data;
    if (!message || message.version !== 1 || message.type !== 'snapshot') return;
    const json = JSON.stringify(message.data);
    switch (message.channel) {
      case 'activeView': window.setActiveView?.(Number(message.data)); break;
      case 'dashboard': window.updateBlackwatchData?.(json); break;
      case 'threats': window.updateThreats?.(json); break;
      case 'processes': window.updateProcesses?.(json); break;
      case 'network': window.updateNetwork?.(json); break;
      case 'logs': window.updateLogs?.(json); break;
      case 'settings': window.updateSettings?.(json); break;
    }
  };
  bridge.addEventListener('message', listener);
  return () => bridge.removeEventListener?.('message', listener);
}
