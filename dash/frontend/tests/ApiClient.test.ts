import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError, api, setStepUpHandler } from '../src/api/client';

function page(items: unknown[], total: number, offset: number): Response {
  return new Response(JSON.stringify({ items, total, limit: 200, offset }), {
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('API client pagination', () => {
  afterEach(() => {
    setStepUpHandler(null);
    vi.restoreAllMocks();
  });

  it('bounds the browser findings snapshot and reports truncation', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = new URL(String(input), 'http://test');
      const offset = Number(url.searchParams.get('offset') ?? 0);
      return page(
        Array.from({ length: 200 }, (_, i) => ({ id: `f${offset + i}` })),
        1001,
        offset,
      );
    });
    vi.stubGlobal('fetch', fetchMock);

    const result = await api.listFindingSnapshot('token');
    expect(result.items).toHaveLength(1000);
    expect(result.total).toBe(1001);
    expect(result.truncated).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(5);
  });

  it('preserves structured API errors and retries once after interactive step-up', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            detail: { code: 'step_up_required', message: 'Recent authentication is required' },
          }),
          { status: 403, statusText: 'Forbidden', headers: { 'Content-Type': 'application/json' } },
        ),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ items: [], total: 0, limit: 50, offset: 0 }), {
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    vi.stubGlobal('fetch', fetchMock);
    const stepUp = vi.fn().mockResolvedValue(undefined);
    setStepUpHandler(stepUp);

    await expect(api.listReports('token')).resolves.toMatchObject({ total: 0 });
    expect(stepUp).toHaveBeenCalledOnce();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('keeps a structured error code when no step-up prompt is registered', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({ detail: { code: 'interactive_step_up_required', message: 'Use a user session' } }),
          { status: 403, statusText: 'Forbidden', headers: { 'Content-Type': 'application/json' } },
        ),
      ),
    );

    await expect(api.listReports('token')).rejects.toMatchObject({
      status: 403,
      code: 'interactive_step_up_required',
      message: 'Use a user session',
    } satisfies Partial<ApiError>);
  });
});
