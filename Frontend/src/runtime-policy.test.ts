import { readFileSync, readdirSync } from 'node:fs';
import { dirname, extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const sourceRoot = dirname(fileURLToPath(import.meta.url));
const frontendRoot = join(sourceRoot, '..');

function runtimeSources(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return runtimeSources(path);
    if (entry.name.includes('.test.')) return [];
    return ['.css', '.html', '.js', '.jsx', '.ts', '.tsx'].includes(extname(path)) ? [path] : [];
  });
}

describe('local-only WebView runtime policy', () => {
  it('blocks external connections and active embedded content', () => {
    const html = readFileSync(join(frontendRoot, 'index.html'), 'utf8');

    expect(html).toContain("connect-src 'none'");
    expect(html).toContain("object-src 'none'");
    expect(html).toContain("frame-src 'none'");
    expect(html).toContain("form-action 'none'");
  });

  it('contains no remote runtime resources or network clients', () => {
    const violations = [join(frontendRoot, 'index.html'), ...runtimeSources(sourceRoot)]
      .flatMap((path) => {
        const source = readFileSync(path, 'utf8');
        return /https?:\/\//i.test(source) || /\b(fetch|WebSocket|EventSource)\s*\(/.test(source)
          ? [path]
          : [];
      });

    expect(violations).toEqual([]);
  });
});
