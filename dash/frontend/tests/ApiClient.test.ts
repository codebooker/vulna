import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../src/api/client';

function page(items: unknown[], total: number, offset: number): Response {
  return new Response(JSON.stringify({ items, total, limit: 200, offset }), {
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('API client pagination', () => {
  afterEach(() => vi.restoreAllMocks());

  it('loads every findings page instead of silently stopping at 200', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('offset=0')) {
        return page(
          Array.from({ length: 200 }, (_, i) => ({ id: `f${i}` })),
          201,
          0,
        );
      }
      if (url.includes('offset=200')) return page([{ id: 'f200' }], 201, 200);
      return new Response(null, { status: 404 });
    });
    vi.stubGlobal('fetch', fetchMock);

    const result = await api.listAllFindings('token');
    expect(result.items).toHaveLength(201);
    expect(result.total).toBe(201);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
