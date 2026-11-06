/**
 * `casesApi.getAttackChain` — the response body the API actually sends.
 *
 * `services/api/tests/fixtures/attack_chain_response.json` is the exact body
 * `GET /cases/{id}/attack-chain` returns for the LockBit scenario; the API's
 * own test fails if the response stops matching it. Feeding it through the
 * real mapper here means a field the backend adds, renames or reshapes cannot
 * be dropped on the way to the screen without this test noticing — which is
 * how `via_alert_id`, `truncated` and the stage fields went unread.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';
import { casesApi } from './api';

const FIXTURE = JSON.parse(
  readFileSync(
    resolve(__dirname, '../../../../services/api/tests/fixtures/attack_chain_response.json'),
    'utf8',
  ),
);

function jsonResponse(body: unknown) {
  return {
    ok: true,
    status: 200,
    statusText: 'OK',
    headers: new Headers({ 'content-type': 'application/json' }),
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as unknown as Response;
}

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('casesApi.getAttackChain mapping', () => {
  it('carries every per-link field the API sends', async () => {
    fetchMock.mockResolvedValue(jsonResponse(FIXTURE));

    const timeline = await casesApi.getAttackChain('case-1');

    expect(timeline).not.toBeNull();
    const byTitle = Object.fromEntries(timeline!.chain.map((l) => [l.title.slice(0, 5), l]));
    const credential = byTitle['Crede'];
    const enumeration = byTitle['S3 bu'];

    expect(credential.tactic).toBe('initial-access');
    expect(credential.stage).toBe(2);
    expect(credential.strength!).toBeGreaterThan(0.9);
    expect(credential.outOfSequence).toBe(false);
    expect(credential.viaAlertId).toBeNull();

    // A two-hop link names the alert that bridged it in.
    expect(enumeration.distance).toBe(2);
    expect(enumeration.viaAlertId).toBe(byTitle['Cloud'].alertId);
    expect(enumeration.tactic).toBe('discovery');
    expect(enumeration.strength!).toBeLessThan(byTitle['Cloud'].strength!);
  });

  it('carries the chain-level completeness fields', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({
        ...FIXTURE,
        truncated: true,
        truncated_reasons: ['sweep_limit', 'max_length'],
        suppressed_pivots: [
          { kind: 'Endpoint', value: '198.51.100.9', reason: 'high_fanout', alert_count: 30 },
          { kind: 'Identity', value: 'system', reason: 'generic_account', alert_count: null },
        ],
      }),
    );

    const timeline = await casesApi.getAttackChain('case-1');

    expect(timeline!.truncated).toBe(true);
    expect(timeline!.truncatedReasons).toEqual(['sweep_limit', 'max_length']);
    expect(timeline!.suppressedPivots).toEqual([
      { kind: 'Endpoint', value: '198.51.100.9', reason: 'high_fanout', alertCount: 30 },
      { kind: 'Identity', value: 'system', reason: 'generic_account', alertCount: null },
    ]);
  });

  it('reports a complete chain as complete, and an unmapped link as having no stage', async () => {
    const body = structuredClone(FIXTURE);
    body.chain[0].stage = null;
    body.chain[0].tactic = null;
    fetchMock.mockResolvedValue(jsonResponse(body));

    const timeline = await casesApi.getAttackChain('case-1');

    expect(timeline!.truncated).toBe(false);
    expect(timeline!.truncatedReasons).toEqual([]);
    expect(timeline!.suppressedPivots).toEqual([]);
    expect(timeline!.chain[0].stage).toBeNull();
    expect(timeline!.chain[0].tactic).toBeNull();
  });

  it('does not invent completeness when an older API omits the fields', async () => {
    const legacy = structuredClone(FIXTURE);
    delete legacy.truncated;
    delete legacy.truncated_reasons;
    delete legacy.suppressed_pivots;
    for (const l of legacy.chain) {
      delete l.strength;
      delete l.stage;
      delete l.tactic;
      delete l.via_alert_id;
      delete l.out_of_sequence;
    }
    fetchMock.mockResolvedValue(jsonResponse(legacy));

    const timeline = await casesApi.getAttackChain('case-1');

    // Unknown is not "complete": the console must be able to tell the difference.
    expect(timeline!.truncated).toBeNull();
    expect(timeline!.chain[0].strength).toBeNull();
    expect(timeline!.chain[0].viaAlertId).toBeNull();
  });
});
