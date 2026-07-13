import { useCallback, useEffect, useMemo, useState } from 'react';
import { api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { DataTable, type ColumnDef } from '../components/app/data-table';
import { PageHeader } from '../components/app/page-header';
import { Badge } from '../components/ui/badge';
import { formatWhenFull } from '../lib/utils';
import type { UserSummary } from '../types/auth';

/** Phase 33 administrator inventory. Lifecycle actions intentionally arrive in Phase 34. */
export function UsersPage() {
  const { token } = useAuth();
  const [users, setUsers] = useState<UserSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      setUsers((await api.listUsers(token)).items);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load users.');
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  const columns: ColumnDef<UserSummary>[] = useMemo(
    () => [
      {
        id: 'user',
        header: 'User',
        cell: (user) => (
          <span>
            <span className="block font-medium text-text">{user.full_name || user.email}</span>
            <span className="block text-xs text-muted">{user.email}</span>
          </span>
        ),
        sortValue: (user) => user.full_name || user.email,
        csvValue: (user) => user.email,
      },
      {
        id: 'status',
        header: 'Status',
        cell: (user) => (
          <Badge tone={user.is_active ? 'ok' : 'neutral'} dot>
            {user.is_active ? 'Active' : 'Inactive'}
          </Badge>
        ),
        sortValue: (user) => (user.is_active ? 1 : 0),
        csvValue: (user) => (user.is_active ? 'active' : 'inactive'),
      },
      {
        id: 'role',
        header: 'Role',
        cell: (user) => <Badge tone="accent">{user.role.replace(/_/g, ' ')}</Badge>,
        sortValue: (user) => user.role,
        csvValue: (user) => user.role,
      },
      {
        id: 'source',
        header: 'Source',
        cell: () => <span className="text-xs text-muted">Local</span>,
        csvValue: () => 'local',
      },
      {
        id: 'mfa',
        header: 'MFA',
        cell: () => <span className="text-xs text-faint">Available in Phase 36</span>,
        csvValue: () => 'planned',
      },
      {
        id: 'sites',
        header: 'Sites',
        cell: () => <span className="text-xs text-muted">All sites</span>,
        csvValue: () => 'all',
      },
      {
        id: 'last_login',
        header: 'Last login',
        cell: (user) => (
          <span className="text-xs text-muted">
            {user.last_login_at ? formatWhenFull(user.last_login_at) : 'Never'}
          </span>
        ),
        sortValue: (user) => user.last_login_at ?? '',
        csvValue: (user) => user.last_login_at ?? '',
      },
    ],
    [],
  );

  return (
    <div aria-label="Users">
      <PageHeader
        crumbs={[{ label: 'Administration' }, { label: 'Users' }]}
        title="Users"
        description="A read-only account inventory. Invitations, assignments, and lifecycle controls arrive in Phase 34."
      />
      <DataTable
        columns={columns}
        rows={users}
        rowKey={(user) => user.id}
        searchText={(user) => `${user.full_name ?? ''} ${user.email} ${user.role}`}
        searchPlaceholder="Search users…"
        loading={loading}
        error={error}
        onRetry={() => void load()}
        emptyTitle="No users"
        emptyDescription="No accounts are visible in this organization."
        exportName="users"
        storageKey="vulnadash.users"
        defaultSort={{ id: 'user', dir: 'asc' }}
      />
    </div>
  );
}
