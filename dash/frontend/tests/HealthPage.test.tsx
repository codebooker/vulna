import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { HealthPage } from '../src/pages/HealthPage';

afterEach(() => {
  vi.restoreAllMocks();
});

describe('HealthPage', () => {
  it('shows backend reachable when the API responds ok', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith('/health')) {
        return new Response(
          JSON.stringify({ status: 'ok', service: 'VulnaDash' }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      return new Response(
        JSON.stringify({
          service: 'VulnaDash',
          version: '0.1.0',
          environment: 'test',
          api_version: 'v1',
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<HealthPage />);

    await waitFor(() => expect(screen.getByText('Backend reachable')).toBeInTheDocument());
    expect(screen.getByText('VulnaDash')).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('shows backend unreachable when the API fails', async () => {
    const fetchMock = vi.fn(async () => new Response('nope', { status: 500 }));
    vi.stubGlobal('fetch', fetchMock);

    render(<HealthPage />);

    await waitFor(() => expect(screen.getByText('Backend unreachable')).toBeInTheDocument());
  });
});
