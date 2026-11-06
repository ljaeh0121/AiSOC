import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { render, screen, within } from '@testing-library/react';
import { casesApi, type AttackChainTimeline, type Case } from '@/lib/api';
import { __setDemoModeForTests } from '@/lib/demoMode';

// We mock SWR rather than the real network layer so the test stays
// hermetic and so we can exercise both the loaded and fallback paths.
// The mock is key-aware so different panels in the workspace (the case
// header vs the attack-chain panel) can return different shapes.
const swrState = vi.hoisted(() => ({
  caseData: undefined as Case | undefined,
  caseError: undefined as Error | undefined,
  attackChainData: undefined as AttackChainTimeline | null | undefined,
  attackChainError: undefined as Error | undefined,
  attackChainLoading: false,
}));

function isAttackChainKey(key: unknown): boolean {
  if (Array.isArray(key)) return key[0] === 'case:attack-chain';
  return false;
}

function isAttackPathKey(key: unknown): boolean {
  return typeof key === 'string' && key.startsWith('case:') && key.endsWith(':attack-path');
}

vi.mock('swr', () => ({
  __esModule: true,
  default: (key: unknown) => {
    if (isAttackChainKey(key)) {
      return {
        data: swrState.attackChainData,
        error: swrState.attackChainError,
        isLoading:
          swrState.attackChainLoading ||
          (swrState.attackChainData === undefined && !swrState.attackChainError),
        mutate: vi.fn(async () => undefined),
      };
    }
    if (isAttackPathKey(key)) {
      // We don't exercise the attack-path tab in these tests; return an
      // empty resolved state so it doesn't show a phantom loading skeleton.
      return {
        data: null,
        error: undefined,
        isLoading: false,
        mutate: vi.fn(async () => undefined),
      };
    }
    if (Array.isArray(key) && key[0] === 'war-rooms') {
      // Depth 9.4's panel reads a list; an empty one renders its empty state
      // without the panel swallowing the case fetch below.
      return {
        data: [],
        error: undefined,
        isLoading: false,
        mutate: vi.fn(async () => undefined),
      };
    }
    // Default: case workspace fetch.
    return {
      data: swrState.caseData,
      error: swrState.caseError,
      isLoading: !swrState.caseData && !swrState.caseError,
      mutate: vi.fn(async () => undefined),
    };
  },
}));

vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ children, href, ...rest }: { children: React.ReactNode; href: string }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}));

const searchParamsState = vi.hoisted(() => ({ params: new URLSearchParams() }));

vi.mock('next/navigation', () => ({
  useSearchParams: () => searchParamsState.params,
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => '/cases/INC-001',
}));

vi.mock('react-hot-toast', () => {
  const fn = vi.fn();
  // react-hot-toast exports both `toast()` and `toast.success/error`; mirror that.
  return {
    __esModule: true,
    default: Object.assign(fn, {
      success: vi.fn(),
      error: vi.fn(),
      loading: vi.fn(),
    }),
    toast: Object.assign(fn, {
      success: vi.fn(),
      error: vi.fn(),
      loading: vi.fn(),
    }),
    Toaster: () => null,
  };
});

// Stub the heavy children — they have their own SWR + WS deps and are
// not what we're smoke-testing here.
vi.mock('./InvestigationLedger', () => ({
  InvestigationLedger: () => <div data-testid="investigation-ledger" />,
}));

vi.mock('@/components/copilot/ContextualActions', () => ({
  ContextualActions: () => <div data-testid="contextual-actions" />,
}));

import { CaseWorkspace } from './CaseWorkspace';

const fakeCase: Case = {
  id: 'INC-001',
  title: 'Suspected lateral movement from finance subnet',
  description: 'Multiple high-severity alerts indicate a pivot via SMB.',
  status: 'investigating',
  severity: 'critical',
  assignee: 'sasha.lin@example.com',
  tags: ['lateral-movement'],
  mitre: ['T1021.002', 'T1078'],
  alertIds: ['alert-1'],
  alertCount: 1,
  createdBy: 'system',
  createdAt: new Date(Date.now() - 60_000).toISOString(),
  updatedAt: new Date(Date.now() - 30_000).toISOString(),
  timeline: [],
  tasks: [],
};

describe('CaseWorkspace', () => {
  beforeEach(() => {
    swrState.caseData = fakeCase;
    swrState.caseError = undefined;
    swrState.attackChainData = undefined;
    swrState.attackChainError = undefined;
    swrState.attackChainLoading = false;
    searchParamsState.params = new URLSearchParams();
  });

  afterEach(() => {
    vi.clearAllMocks();
    __setDemoModeForTests(null);
  });

  it('renders the case header with title, severity, and MITRE chips', () => {
    render(<CaseWorkspace caseId="INC-001" />);

    expect(
      screen.getByRole('heading', { level: 1, name: /lateral movement from finance subnet/i }),
    ).toBeInTheDocument();
    expect(screen.getByText('critical')).toBeInTheDocument();

    // MITRE techniques should render as outbound links to attack.mitre.org.
    const t1021 = screen.getByRole('link', { name: /T1021\.002/ });
    expect(t1021).toHaveAttribute('href', 'https://attack.mitre.org/techniques/T1021/002/');
    expect(screen.getByRole('link', { name: /T1078/ })).toHaveAttribute(
      'href',
      'https://attack.mitre.org/techniques/T1078/',
    );
  });

  it('shows the demo banner when the backend errors out in the hosted demo', () => {
    // This case previously asserted the fallback fired on *any* deployment.
    // `buildDemoCase(caseId)` copies the route param, so outside the demo it
    // put an invented title, assignee and timeline on screen under the id the
    // analyst had opened. The fallback is right for the hosted demo, which
    // has no backend of its own, and wrong everywhere else — see
    // `CaseWorkspaceHonesty.test.tsx` for the other half.
    __setDemoModeForTests(true);
    swrState.caseData = undefined;
    swrState.caseError = new Error('fetch failed');

    render(<CaseWorkspace caseId="INC-001" />);

    expect(
      screen.getByRole('heading', { level: 1, name: /lateral movement from finance subnet/i }),
    ).toBeInTheDocument();
    expect(screen.getByText(/demo data — writes disabled/i)).toBeInTheDocument();
  });

  describe('attack-chain panel', () => {
    beforeEach(() => {
      // Force the attack-chain tab to render by setting ?tab=attack-chain.
      searchParamsState.params = new URLSearchParams('tab=attack-chain');
    });

    it('renders an empty state when the backend returns no chain', () => {
      swrState.attackChainData = null;

      render(<CaseWorkspace caseId="INC-001" />);

      expect(screen.getByText(/no attack chain yet/i)).toBeInTheDocument();
    });

    it('renders an error state when the chain request fails', () => {
      swrState.attackChainData = undefined;
      swrState.attackChainError = new Error('boom');

      render(<CaseWorkspace caseId="INC-001" />);

      expect(screen.getByText(/failed to load attack chain/i)).toBeInTheDocument();
    });

    it('renders chain links, confidence, and entity summary when data is loaded', () => {
      const now = new Date('2026-05-15T00:00:00Z').toISOString();
      const timeline: AttackChainTimeline = {
        caseId: 'INC-001',
        tenantId: 'tenant-1',
        window: '24h',
        seedAlertId: 'alert-seed',
        chainSignature: 'sig-xyz',
        confidence: 0.82,
        truncated: false,
        truncatedReasons: [],
        suppressedPivots: [],
        generatedAt: now,
        // The seed is not a member of the chain; the API returns only the
        // alerts related to it.
        chain: [
          {
            alertId: 'alert-2',
            title: 'Lateral SMB session to FIN-DB-02',
            severity: 'high',
            eventTime: new Date('2026-05-15T00:05:00Z').toISOString(),
            score: 0.74,
            distance: 1,
            dtSeconds: 300,
            sharedEntities: [{ kind: 'user', value: 'svc-finance' }],
            mitreTechniques: ['T1021.002'],
            connectorType: 'edr',
            sourceEventIds: ['evt-2'],
            viaAlertId: null,
            strength: 0.9,
            stage: 9,
            tactic: 'lateral-movement',
            outOfSequence: false,
          },
        ],
        entityGraph: {
          nodes: [
            {
              id: 'alert:alert-seed',
              kind: 'Alert',
              label: 'Seed — Suspicious PowerShell on FIN-WS-01',
              severity: 'critical',
              event_time: now,
            },
            { id: 'alert:alert-2', kind: 'Alert', severity: 'high' },
            { id: 'user:svc-finance', kind: 'user', label: 'svc-finance' },
          ],
          edges: [{ source: 'alert:alert-2', target: 'user:svc-finance', kind: 'TOUCHES' }],
        },
      };
      swrState.attackChainData = timeline;

      render(<CaseWorkspace caseId="INC-001" />);

      // The seed is named in its own header; the chain holds the related alert.
      expect(screen.getByTestId('chain-seed')).toHaveTextContent(
        /Seed — Suspicious PowerShell on FIN-WS-01/i,
      );
      expect(screen.getByText(/Lateral SMB session to FIN-DB-02/i)).toBeInTheDocument();

      // Confidence is surfaced as a percentage to the analyst.
      expect(screen.getByText(/82%/)).toBeInTheDocument();

      // MITRE techniques from the chain should be visible.
      expect(screen.getByText('T1021.002')).toBeInTheDocument();
    });

    describe('what the analyst is told about the chain', () => {
      const FIXTURE = JSON.parse(
        readFileSync(
          resolve(
            __dirname,
            '../../../../../services/api/tests/fixtures/attack_chain_response.json',
          ),
          'utf8',
        ),
      );

      // The body the API really sends, through the real mapper.
      async function load(patch: (body: any) => void = () => {}): Promise<AttackChainTimeline> {
        const body = structuredClone(FIXTURE);
        patch(body);
        vi.stubGlobal(
          'fetch',
          vi.fn().mockResolvedValue({
            ok: true,
            status: 200,
            statusText: 'OK',
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => body,
            text: async () => JSON.stringify(body),
          } as unknown as Response),
        );
        const timeline = await casesApi.getAttackChain('INC-001');
        vi.unstubAllGlobals();
        return timeline!;
      }

      const show = (timeline: AttackChainTimeline) => {
        swrState.attackChainData = timeline;
        render(<CaseWorkspace caseId="INC-001" />);
      };
      const card = (timeline: AttackChainTimeline, titlePrefix: string) =>
        screen.getByTestId(
          `chain-link-${timeline.chain.find((l) => l.title.startsWith(titlePrefix))!.alertId}`,
        );

      it('names the real seed alert and does not call the first link the seed', async () => {
        const timeline = await load();
        show(timeline);

        expect(screen.getByTestId('chain-seed')).toHaveTextContent(
          'Phishing email with malicious attachment delivered',
        );
        expect(screen.queryByText(/^seed$/i)).not.toBeInTheDocument();
      });

      it('labels each link with its ATT&CK tactic', async () => {
        const timeline = await load();
        show(timeline);

        expect(within(card(timeline, 'Credential')).getByText(/initial access/i)).toBeInTheDocument();
        expect(within(card(timeline, 'S3 bucket')).getByText(/discovery/i)).toBeInTheDocument();
        expect(within(card(timeline, 'Large outbound')).getByText(/collection/i)).toBeInTheDocument();
      });

      it('says so when no technique could be placed on the kill chain', async () => {
        const timeline = await load((b) => {
          b.chain[0].stage = null;
          b.chain[0].tactic = null;
        });
        show(timeline);

        expect(within(card(timeline, 'Credential')).getByText(/no tactic/i)).toBeInTheDocument();
      });

      it('marks only the links whose stage order contradicts the clock', async () => {
        const clean = await load();
        show(clean);
        expect(screen.queryByText(/out of sequence/i)).not.toBeInTheDocument();
      });

      it('flags a link that happened before one it follows in stage order', async () => {
        const timeline = await load((b) => {
          b.chain[3].out_of_sequence = true;
        });
        show(timeline);

        expect(screen.getAllByText(/out of sequence/i)).toHaveLength(1);
        expect(within(card(timeline, 'Large outbound')).getByText(/out of sequence/i)).toBeInTheDocument();
      });

      it('names the alert that bridged a deeper link in', async () => {
        const timeline = await load();
        show(timeline);

        expect(within(card(timeline, 'S3 bucket')).getByText(/via/i)).toHaveTextContent(
          'Cloud auth anomaly: impossible-travel sign-in to AWS console',
        );
        expect(within(card(timeline, 'Credential')).queryByText(/^via/i)).not.toBeInTheDocument();
      });

      it('measures time from the seed, not from the previous link', async () => {
        const timeline = await load();
        show(timeline);

        // The credential-harvest alert is 5 minutes after the seed.
        expect(within(card(timeline, 'Credential')).getByText('±5m from seed')).toBeInTheDocument();
      });

      it('shows how strong the evidence for each link is', async () => {
        const timeline = await load();
        show(timeline);

        expect(within(card(timeline, 'Credential')).getByText(/evidence 96%/i)).toBeInTheDocument();
        expect(within(card(timeline, 'S3 bucket')).getByText(/evidence 43%/i)).toBeInTheDocument();
      });

      it('explains what the confidence figure is', async () => {
        const timeline = await load();
        show(timeline);

        expect(screen.getByTitle(/mean evidence strength.*not a calibrated probability/i)).toBeInTheDocument();
      });

      it('warns that a truncated chain is not the whole picture, and why', async () => {
        const timeline = await load((b) => {
          b.truncated = true;
          b.truncated_reasons = ['sweep_limit', 'max_length'];
        });
        show(timeline);

        const banner = screen.getByTestId('chain-truncated');
        expect(banner).toHaveTextContent(/incomplete/i);
        expect(banner).toHaveTextContent(/row limit/i);
        expect(banner).toHaveTextContent(/length cap/i);
      });

      it('shows no warning for a complete chain', async () => {
        const timeline = await load();
        show(timeline);

        expect(screen.queryByTestId('chain-truncated')).not.toBeInTheDocument();
      });

      it('does not claim completeness when the API does not say', async () => {
        const timeline = await load((b) => {
          delete b.truncated;
          delete b.truncated_reasons;
        });
        show(timeline);

        expect(screen.getByTestId('chain-completeness-unknown')).toBeInTheDocument();
      });

      it('lists the entities the traversal declined to follow', async () => {
        const timeline = await load((b) => {
          b.suppressed_pivots = [
            { kind: 'Endpoint', value: '198.51.100.9', reason: 'high_fanout', alert_count: 30 },
            { kind: 'Identity', value: 'system', reason: 'generic_account', alert_count: null },
          ];
        });
        show(timeline);

        const note = screen.getByTestId('chain-suppressed');
        expect(note).toHaveTextContent('198.51.100.9');
        expect(note).toHaveTextContent(/30 alerts/i);
        expect(note).toHaveTextContent('system');
        expect(note).toHaveTextContent(/shared account/i);
      });

      it('does not say that MITRE techniques link alerts', async () => {
        swrState.attackChainData = null;
        render(<CaseWorkspace caseId="INC-001" />);

        expect(screen.queryByText(/or MITRE techniques/i)).not.toBeInTheDocument();
        expect(screen.getByText(/share an entity/i)).toBeInTheDocument();
      });
    });

    // Helper: read the active window from the WindowSelector. The UI is a
    // segmented button group (role=group, buttons with aria-pressed) rather
    // than a <select>, so we resolve the active choice by looking inside the
    // labelled group for the lone button with aria-pressed="true".
    const readActiveWindow = (): string | null => {
      const group = screen.getByLabelText(/attack chain time window/i);
      const pressed = within(group).getAllByRole('button', { pressed: true });
      // The component invariant is exactly one option pressed at a time.
      expect(pressed).toHaveLength(1);
      return pressed[0]?.textContent?.replace(/\s+/g, '') ?? null;
    };

    it('honors the ?window=… deep link on first render', () => {
      // Regression for PR #145 review: the changelog claims the window
      // selection survives reload via ?window=…. Mount with both the
      // tab AND window params set, and assert the WindowSelector is
      // showing the linked value rather than the default `24h`.
      searchParamsState.params = new URLSearchParams('tab=attack-chain&window=72h');
      swrState.attackChainData = null;

      render(<CaseWorkspace caseId="INC-001" />);

      // The window selector must show 72h as the active choice. Since
      // `WindowSelector value={windowParam}` is bound directly to the
      // panel state, the selector reading 72h proves the URL value
      // flowed through `initialWindow` into the state — which in turn
      // is what SWR keys the fetch on.
      expect(readActiveWindow()).toBe('72h');
    });

    it('falls back to the 24h default when ?window=… is missing or unknown', () => {
      // Just the tab, no window param → default `24h` (NOT the previous
      // `1h` default the PR shipped with; switched to 24h per review
      // because 1h showed an empty state for most realistic cases).
      searchParamsState.params = new URLSearchParams('tab=attack-chain');
      swrState.attackChainData = null;

      const { unmount } = render(<CaseWorkspace caseId="INC-001" />);
      expect(readActiveWindow()).toBe('24h');
      unmount();

      // An obviously-invalid value must also fall back to the default
      // (defence-in-depth: the type guard refuses anything outside the
      // closed `AttackChainWindow` set), not crash the panel.
      searchParamsState.params = new URLSearchParams('tab=attack-chain&window=900years');
      swrState.attackChainData = null;

      render(<CaseWorkspace caseId="INC-001" />);
      expect(readActiveWindow()).toBe('24h');
    });
  });
});
