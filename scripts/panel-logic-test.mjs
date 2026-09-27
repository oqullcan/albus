// Panel.qml logic tests — single-source extraction, zero duplication.
//
// The pure functions (canon, numOr, uiConfigShape, cfgFingerprint,
// parseConfigJson) are extracted VERBATIM from Panel.qml at test time and
// evaluated with a stubbed `root` global. There is no copied logic to
// drift: if someone edits the QML, the tests run the edited code.
// Hermetic: embedded backend fixture mirrors `albus config get` output;
// loopback-free, network-free. Runs in CI (runner node) and locally:
//   node --test scripts/panel-logic-test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const QML = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), '..', 'Panel.qml'),
  'utf8'
);

// Extract `function NAME(...) {...}` with string- and line-comment-aware
// brace matching (QML/JS subset: '...' "..." strings, // comments).
function extract(name) {
  const marker = `function ${name}(`;
  const start = QML.indexOf(marker);
  assert.notEqual(start, -1, `${name} must exist in Panel.qml`);
  let i = QML.indexOf('{', start);
  let depth = 0;
  let quote = null;
  for (let j = i; j < QML.length; j++) {
    const c = QML[j];
    if (quote) {
      if (c === '\\') { j++; continue; }
      if (c === quote) quote = null;
      continue;
    }
    if (c === "'" || c === '"') { quote = c; continue; }
    if (c === '/' && QML[j + 1] === '/') {
      const nl = QML.indexOf('\n', j);
      j = nl === -1 ? QML.length : nl;
      continue;
    }
    if (c === '{') depth++;
    else if (c === '}') {
      depth--;
      if (depth === 0) return QML.slice(start, j + 1);
    }
  }
  throw new Error(`${name}: unbalanced braces in Panel.qml`);
}

for (const fn of ['canon', 'numOr', 'uiConfigShape', 'cfgFingerprint', 'parseConfigJson']) {
  (0, eval)(extract(fn));
}

// Backend fixture mirroring `albus config get` (incl. persisted mss:100
// tuning, plus all 20 fingerprinted keys).
const BACKEND = {
  mss: 100, min_mss: 64, restore_mss: 0, restore_after_bytes: 600,
  ports: [443], cgroup_path: '/sys/fs/cgroup', auto_ttl: true, fake_ttl: 8,
  fake_sni: null, fake_bad_checksum: false, doh_upstream: 'quad9',
  doh_bootstrap_ips: [], block_quic: true, block_stun: true, kill_switch: true,
  network_lockdown: false, block_ipv6: true, dnssec: true, pqc: true,
  ram_only: false,
};

function draftRoot(over = {}) {
  return Object.assign(
    {
      activeDnsKey: BACKEND.doh_upstream, mullvadProfile: 'standard', customDnsUrl: '',
      customBootstrapPrimary: '', customBootstrapSecondary: '',
      customMss: String(BACKEND.mss), customMinMss: String(BACKEND.min_mss),
      customFakeTtl: '', customFakeSni: '', fakeBadChecksum: false,
      blockQuicEnabled: true, blockStunEnabled: true, killSwitchEnabled: true,
      networkLockdownEnabled: false, blockIpv6Enabled: true, dnssecEnabled: true,
      pqcEnabled: true, ramOnlyEnabled: false, storedPorts: BACKEND.ports,
      storedRestoreAfterBytes: BACKEND.restore_after_bytes,
      storedRestoreMss: BACKEND.restore_mss, storedCgroup: BACKEND.cgroup_path,
      isConfigLoading: false, isDirty: false,
      effectiveFingerprint: cfgFingerprint(BACKEND),
    },
    over
  );
}

test('canon sorts keys stably', () => {
  assert.equal(canon({ b: 1, a: { d: 4, c: 3 } }), '{"a":{"c":3,"d":4},"b":1}');
});

test('cfgFingerprint is key-order invariant', () => {
  const shuffled = {};
  for (const k of Object.keys(BACKEND).reverse()) shuffled[k] = BACKEND[k];
  assert.equal(cfgFingerprint(BACKEND), cfgFingerprint(shuffled));
});

test('mirroring draft is clean; one toggle dirties', () => {
  globalThis.root = draftRoot();
  assert.equal(canon(uiConfigShape()), root.effectiveFingerprint);
  root.blockQuicEnabled = false;
  assert.notEqual(canon(uiConfigShape()), root.effectiveFingerprint);
  root.blockQuicEnabled = true;
  assert.equal(canon(uiConfigShape()), root.effectiveFingerprint);
});

test('mullvad alias round-trips', () => {
  const mull = Object.assign({}, BACKEND, { doh_upstream: 'mullvad-base' });
  globalThis.root = draftRoot({ activeDnsKey: 'mullvad-base', mullvadProfile: 'base' });
  assert.equal(canon(uiConfigShape()), cfgFingerprint(mull));
});

test('parseConfigJson fallback semantics', () => {
  assert.equal(parseConfigJson(''), null);
  assert.equal(parseConfigJson('{nope'), null);
  assert.equal(parseConfigJson('{"mss": 100}').mss, 100);
});

test('numOr defaults', () => {
  assert.equal(numOr('', 88), 88);
  assert.equal(numOr('abc', 64), 64);
  assert.equal(numOr('100', 88), 100);
});
