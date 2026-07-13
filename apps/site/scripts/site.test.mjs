import { access, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';

const root = resolve(import.meta.dirname, '..', 'public');

test('landing page has the required product, custody and release signals', async () => {
  const html = await readFile(resolve(root, 'index.html'), 'utf8');
  assert.match(html, /<title>Edict \| Edict Protect/);
  assert.match(html, /<h1>Edict Protect<\/h1>/);
  assert.match(html, /non-custodial/i);
  assert.match(html, /testnet preview/i);
  assert.match(html, /not for production value/i);
  assert.match(html, /Edict is the trust layer for autonomous commerce/);
  assert.match(html, /id="integrate"/);
  assert.match(html, /Core registration path/);
  assert.match(html, /Design partnership/);
  assert.match(html, /data-scenario=/);
  assert.match(html, /id="signal-canvas"/);
  assert.doesNotMatch(html, /concept[- ]b/i);
  assert.doesNotMatch(html, /<script[^>]+src=["']https?:/i);
  assert.doesNotMatch(html, /<link[^>]+href=["']https?:/i);
});

test('all local site assets exist', async () => {
  await Promise.all([
    'assets/site.css',
    'assets/site.js',
    'assets/hero-signal.jpg',
  ].map((path) => access(resolve(root, path))));
});

test('landing page uses the monochrome animated signal field', async () => {
  const [css, javascript] = await Promise.all([
    readFile(resolve(root, 'assets/site.css'), 'utf8'),
    readFile(resolve(root, 'assets/site.js'), 'utf8'),
  ]);

  assert.match(css, /hero-signal\.jpg/);
  assert.doesNotMatch(css, /#38d9ff|#bdff31|#ff795c|56,\s*217,\s*255|189,\s*255,\s*49|255,\s*121,\s*92/i);
  assert.match(javascript, /requestAnimationFrame\(drawSignal\)/);
  assert.match(javascript, /const routes = \[/);
  assert.match(javascript, /const checkpoints = Array\.from/);
  assert.match(javascript, /prefers-reduced-motion/);
});
