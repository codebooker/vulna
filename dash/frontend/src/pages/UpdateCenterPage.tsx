import { useCallback, useEffect, useState } from 'react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { Card } from '../components/ui/card';
import { Code, CodeBlock } from '../components/ui/misc';
import { InlineError } from '../components/ui/states';
import type { UpdateCenter } from '../types/update';

/** Update center (display only). Updates are checked and applied by the
 *  operator with the signature-verifying `vulna` CLI. */
export function UpdateCenterPage() {
  const { token, user } = useAuth();
  const [info, setInfo] = useState<UpdateCenter | null>(null);
  const [error, setError] = useState<string | null>(null);

  const isAdmin = user?.role === 'administrator';

  const load = useCallback(async () => {
    if (!token) return;
    try {
      setInfo(await api.updateCenter(token));
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : 'Failed to load update info.');
    }
  }, [token]);

  useEffect(() => {
    if (isAdmin) void load();
  }, [isAdmin, load]);

  if (!isAdmin || !info) {
    return error ? (
      <div aria-label="Updates">
        <h2 className="mb-2 text-[15px] font-semibold text-text">Updates</h2>
        <InlineError message={error} />
      </div>
    ) : null;
  }

  return (
    <div aria-label="Update center">
      <h2 className="mb-1 text-[15px] font-semibold text-text">Updates</h2>
      <p className="mb-4 max-w-2xl text-[13px] text-muted">
        Current version <Code>{info.current_version}</Code> on the{' '}
        <strong className="text-text">{info.channel}</strong> channel. Updates are applied by an
        operator with the signature-verifying <Code>vulna</Code> CLI — the web UI only shows version
        info.
      </p>
      {error && <InlineError message={error} className="mb-3" />}
      <Card className="mb-3 p-4">
        <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
          Check for updates
        </p>
        <CodeBlock>{info.how_to_check}</CodeBlock>
        <p className="mb-1.5 mt-3 text-xs font-semibold uppercase tracking-wide text-muted">
          Apply an update
        </p>
        <CodeBlock>{info.how_to_apply}</CodeBlock>
      </Card>
      <p className="text-xs text-muted">
        These update types are kept separate: {info.update_types.join(', ')}.
      </p>
      <p className="mt-1 text-xs text-muted">{info.note}</p>
    </div>
  );
}
