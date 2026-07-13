import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../src/api/client';

function page(items: unknown[], total: number, offset: number): Response {
  return new Response(JSON.stringify({ items, total, limit: 200, offset }), {
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('API client pagination', () => {
  afterEach(() => vi.restoreAllMocks());

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
});
