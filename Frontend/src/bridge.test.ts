import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { installSnapshotBridge, sendBridgeCommand } from './bridge';

describe('sendBridgeCommand', () => {
  beforeEach(() => {
    vi.stubGlobal('window', {});
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('sends a versioned command to the desktop host', () => {
    const postMessage = vi.fn();
    window.chrome = { webview: { postMessage } };

    const sent = sendBridgeCommand({ type: 'process', action: 'kill', pid: 42 });

    expect(sent).toBe(true);
    expect(postMessage).toHaveBeenCalledOnce();
    expect(postMessage).toHaveBeenCalledWith({
      version: 1,
      type: 'process',
      action: 'kill',
      pid: 42,
    });
  });

  it('reports an unavailable desktop host without throwing', () => {
    const warning = vi.spyOn(console, 'warn').mockImplementation(() => undefined);

    const sent = sendBridgeCommand({ type: 'app', action: 'scan' });

    expect(sent).toBe(false);
    expect(warning).toHaveBeenCalledOnce();
  });

  it('routes only versioned snapshot messages and unregisters cleanly', () => {
    let listener: ((event: MessageEvent) => void) | undefined;
    const addEventListener = vi.fn((_type: string, callback: (event: MessageEvent) => void) => { listener = callback; });
    const removeEventListener = vi.fn();
    const updateProcesses = vi.fn();
    vi.stubGlobal('window', {
      chrome: { webview: { addEventListener, removeEventListener } },
      updateProcesses,
    });

    const uninstall = installSnapshotBridge();
    listener?.({ data: { version: 1, type: 'snapshot', channel: 'processes', data: { items: [], count: 0 } } } as MessageEvent);
    listener?.({ data: { version: 2, type: 'snapshot', channel: 'processes', data: { items: ['rejected'] } } } as MessageEvent);
    uninstall();

    expect(updateProcesses).toHaveBeenCalledOnce();
    expect(updateProcesses).toHaveBeenCalledWith('{"items":[],"count":0}');
    expect(removeEventListener).toHaveBeenCalledWith('message', listener);
  });
});
