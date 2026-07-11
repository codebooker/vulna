import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { AuthProvider } from '../src/auth/AuthProvider';
import { PresetsPage } from '../src/pages/PresetsPage';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

const standardPreset = {
  key: 'standard',
  version: 1,
  name: 'Standard Security Check',
  use_case: 'Default homelab scan',
  description: 'Safe checks',
  stages: [{ key: 'discovery', scanner: 'nmap', classification: 'safe', label: 'Discovery' }],
  rate: { packets_per_second: 150, concurrency: 4 },
  workload_class: 'moderate',
  duration_class: 'minutes',
  mode: 'vulnerability_assessment',
  web_profile: null,
  intrusive: false,
  active_web: false,
  uses_credentials: false,
};

describe('PresetsPage', () => {
  beforeEach(() => {
    localStorage.setItem('vulna.token', 'tok123');
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith('/api/v1/auth/me')) {
          return jsonResponse({
            id: 'u1',
            email: 'a@example.com',
            full_name: null,
            role: 'administrator',
            organization_id: 'o1',
            is_active: true,
          });
        }
        if (url.endsWith('/api/v1/presets')) {
          return jsonResponse({ presets: [standardPreset] });
        }
        if (url.endsWith('/api/v1/presets/preview')) {
          return jsonResponse({
            preset: 'standard',
            preset_version: 1,
            stages_to_run: [
              { key: 'discovery', scanner: 'nmap', classification: 'safe', label: 'Discovery' },
            ],
            skipped: [
              { stage: 'vuln', scanner: 'nuclei', reason: 'The vuln stage needs nuclei.' },
            ],
            blocked: false,
            estimate: { workload_class: 'moderate', size_class: 'medium', duration_range: 'a few minutes' },
            tuning: { packets_per_second: 150, concurrency: 4 },
            scanners: [{ scanner: 'nmap', status: 'installed', detail: 'available' }],
            profile: 'lite',
            capability_warning: 'This is a heavy preset and the Scout is on Lite-tier hardware.',
          });
        }
        return jsonResponse({ detail: 'not found' }, 404);
      }),
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('lists presets and previews stages + why-skipped', async () => {
    render(
      <AuthProvider>
        <PresetsPage />
      </AuthProvider>,
    );
    const card = await screen.findByRole('button', { name: /Standard Security Check/ });
    fireEvent.click(card);
    await waitFor(() => expect(screen.getByText(/Stages that will run/)).toBeInTheDocument());
    expect(screen.getByText(/needs nuclei/)).toBeInTheDocument();
    // Phase 27: a heavy preset on Lite-tier hardware warns.
    expect(screen.getByText(/Lite-tier hardware/)).toBeInTheDocument();
  });
});
