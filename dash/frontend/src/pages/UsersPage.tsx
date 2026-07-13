import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react';
import { Copy, KeyRound, MailPlus, UserPlus } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import { DataTable, type ColumnDef, type FilterDef } from '../components/app/data-table';
import { PageHeader } from '../components/app/page-header';
import { Badge, type BadgeTone } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Field, Input, Select, Textarea } from '../components/ui/input';
import { Drawer, Modal } from '../components/ui/overlay';
import { InlineError } from '../components/ui/states';
import { useToast } from '../lib/toast';
import { formatWhenFull } from '../lib/utils';
import type {
  AccountStatus,
  LifecycleEvent,
  LoginHistoryEvent,
  Role,
  SiteAccessMode,
  UserSession,
  UserSummary,
} from '../types/auth';
import type { Site } from '../types/inventory';

const ROLES: Role[] = [
  'administrator',
  'security_operator',
  'pentest_approver',
  'remediation_owner',
  'auditor',
  'viewer',
];

const STATUS_TONES: Record<AccountStatus, BadgeTone> = {
  invited: 'accent',
  active: 'ok',
  suspended: 'warn',
  deactivated: 'neutral',
  locked: 'bad',
};

function label(value: string) {
  return value.replace(/_/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function siteLabel(user: UserSummary, sites: Site[]) {
  if (user.site_access_mode === 'all' || user.role === 'administrator') return 'All sites';
  const names = user.site_ids
    .map((siteId) => sites.find((site) => site.id === siteId)?.name)
    .filter(Boolean);
  return names.length ? names.join(', ') : 'No sites';
}

interface OneTimeLink {
  title: string;
  url: string;
  expiresAt: string;
}

export function UsersPage() {
  const { token } = useAuth();
  const [users, setUsers] = useState<UserSummary[]>([]);
  const [sites, setSites] = useState<Site[]>([]);
  const [selected, setSelected] = useState<UserSummary | null>(null);
  const [inviteOpen, setInviteOpen] = useState(false);
  const [oneTimeLink, setOneTimeLink] = useState<OneTimeLink | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const [userPage, sitePage] = await Promise.all([api.listUsers(token), api.listSites(token)]);
      setUsers(userPage.items);
      setSites(sitePage.items);
      setSelected((current) =>
        current ? (userPage.items.find((user) => user.id === current.id) ?? null) : null,
      );
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
          <Badge tone={STATUS_TONES[user.account_status]} dot>
            {label(user.account_status)}
          </Badge>
        ),
        sortValue: (user) => user.account_status,
      },
      {
        id: 'role',
        header: 'Role',
        cell: (user) => <Badge tone="accent">{label(user.role)}</Badge>,
        sortValue: (user) => user.role,
      },
      {
        id: 'source',
        header: 'Source',
        cell: (user) => (
          <span className="text-xs text-muted">{label(user.authentication_source)}</span>
        ),
        sortValue: (user) => user.authentication_source,
      },
      {
        id: 'mfa',
        header: 'MFA',
        cell: (user) => (
          <Badge
            tone={
              user.mfa_status === 'enrolled'
                ? 'ok'
                : user.mfa_status === 'required'
                  ? 'warn'
                  : 'neutral'
            }
          >
            {label(user.mfa_status)}
          </Badge>
        ),
        csvValue: (user) => user.mfa_status,
      },
      {
        id: 'sites',
        header: 'Sites',
        cell: (user) => <span className="text-xs text-muted">{siteLabel(user, sites)}</span>,
        csvValue: (user) => siteLabel(user, sites),
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
      },
    ],
    [sites],
  );

  const filters: FilterDef<UserSummary>[] = useMemo(
    () => [
      {
        id: 'status',
        label: 'Status',
        options: Object.keys(STATUS_TONES).map((value) => ({ value, label: label(value) })),
        predicate: (user, value) => user.account_status === value,
      },
      {
        id: 'source',
        label: 'Source',
        options: ['local', 'jit', 'scim'].map((value) => ({ value, label: label(value) })),
        predicate: (user, value) => user.authentication_source === value,
      },
    ],
    [],
  );

  return (
    <div aria-label="Users">
      <PageHeader
        crumbs={[{ label: 'Administration' }, { label: 'Users' }]}
        title="Users"
        description="Invite users, control account status and site access, and review lifecycle history."
        actions={
          <Button variant="primary" onClick={() => setInviteOpen(true)}>
            <UserPlus size={14} aria-hidden /> Invite user
          </Button>
        }
      />
      <DataTable
        columns={columns}
        rows={users}
        rowKey={(user) => user.id}
        searchText={(user) => `${user.full_name ?? ''} ${user.email} ${user.role}`}
        searchPlaceholder="Search users…"
        filters={filters}
        onRowClick={setSelected}
        loading={loading}
        error={error}
        onRetry={() => void load()}
        emptyTitle="No users"
        emptyDescription="Invite an account to this organization."
        emptyAction={<Button onClick={() => setInviteOpen(true)}>Invite user</Button>}
        exportName="users"
        storageKey="vulnadash.users"
        defaultSort={{ id: 'user', dir: 'asc' }}
      />
      <InviteUserModal
        open={inviteOpen}
        sites={sites}
        onClose={() => setInviteOpen(false)}
        onInvited={(created) => {
          setInviteOpen(false);
          if (created.invitation_url && created.invitation_expires_at) {
            setOneTimeLink({
              title: 'Invitation link',
              url: created.invitation_url,
              expiresAt: created.invitation_expires_at,
            });
          }
          void load();
        }}
      />
      <UserDrawer
        user={selected}
        sites={sites}
        onClose={() => setSelected(null)}
        onChanged={() => void load()}
        onLink={setOneTimeLink}
      />
      <OneTimeLinkModal value={oneTimeLink} onClose={() => setOneTimeLink(null)} />
    </div>
  );
}

function SiteChoices({
  sites,
  selected,
  onChange,
}: {
  sites: Site[];
  selected: string[];
  onChange: (value: string[]) => void;
}) {
  return (
    <div className="max-h-40 space-y-1 overflow-y-auto rounded-lg border border-border p-2">
      {sites.length === 0 && <p className="text-xs text-faint">No sites have been created.</p>}
      {sites.map((site) => (
        <label
          key={site.id}
          className="flex items-center gap-2 rounded px-1 py-1 text-xs text-muted"
        >
          <input
            type="checkbox"
            checked={selected.includes(site.id)}
            onChange={() =>
              onChange(
                selected.includes(site.id)
                  ? selected.filter((value) => value !== site.id)
                  : [...selected, site.id],
              )
            }
          />
          {site.name}
        </label>
      ))}
    </div>
  );
}

function InviteUserModal({
  open,
  sites,
  onClose,
  onInvited,
}: {
  open: boolean;
  sites: Site[];
  onClose: () => void;
  onInvited: (created: Awaited<ReturnType<typeof api.inviteUser>>) => void;
}) {
  const { token } = useAuth();
  const { toast } = useToast();
  const [email, setEmail] = useState('');
  const [fullName, setFullName] = useState('');
  const [role, setRole] = useState<Role>('viewer');
  const [mode, setMode] = useState<SiteAccessMode>('assigned');
  const [siteIds, setSiteIds] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      const created = await api.inviteUser(token, {
        email,
        full_name: fullName.trim() || null,
        role,
        site_access_mode: mode,
        site_ids: mode === 'assigned' ? siteIds : [],
      });
      setEmail('');
      setFullName('');
      setRole('viewer');
      setMode('assigned');
      setSiteIds([]);
      toast('success', 'Invitation created.');
      onInvited(created);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not invite this user.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Invite a user"
      description="The user chooses their own password through a single-use link."
      wide
    >
      <form className="grid gap-3 sm:grid-cols-2" onSubmit={submit}>
        <Field label="Email" htmlFor="invite-email">
          <Input
            id="invite-email"
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </Field>
        <Field label="Full name" htmlFor="invite-name" hint="Optional">
          <Input id="invite-name" value={fullName} onChange={(e) => setFullName(e.target.value)} />
        </Field>
        <Field label="Role" htmlFor="invite-role">
          <Select id="invite-role" value={role} onChange={(e) => setRole(e.target.value as Role)}>
            {ROLES.map((value) => (
              <option key={value} value={value}>
                {label(value)}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Site access" htmlFor="invite-site-mode">
          <Select
            id="invite-site-mode"
            value={mode}
            onChange={(e) => setMode(e.target.value as SiteAccessMode)}
          >
            <option value="assigned">Assigned sites</option>
            <option value="all">All sites</option>
          </Select>
        </Field>
        {mode === 'assigned' && (
          <Field label="Assigned sites" className="sm:col-span-2">
            <SiteChoices sites={sites} selected={siteIds} onChange={setSiteIds} />
          </Field>
        )}
        {error && <InlineError message={error} className="sm:col-span-2" />}
        <div className="flex justify-end gap-2 sm:col-span-2">
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" loading={busy}>
            Create invitation
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function UserDrawer({
  user,
  sites,
  onClose,
  onChanged,
  onLink,
}: {
  user: UserSummary | null;
  sites: Site[];
  onClose: () => void;
  onChanged: () => void;
  onLink: (value: OneTimeLink) => void;
}) {
  const { token, user: currentUser } = useAuth();
  const { toast } = useToast();
  const [role, setRole] = useState<Role>('viewer');
  const [mode, setMode] = useState<SiteAccessMode>('assigned');
  const [siteIds, setSiteIds] = useState<string[]>([]);
  const [lifecycle, setLifecycle] = useState<LifecycleEvent[]>([]);
  const [logins, setLogins] = useState<LoginHistoryEvent[]>([]);
  const [sessions, setSessions] = useState<UserSession[]>([]);
  const [statusAction, setStatusAction] = useState<AccountStatus | null>(null);
  const [reason, setReason] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!user) return;
    setRole(user.role);
    setMode(user.site_access_mode);
    setSiteIds(user.site_ids);
    setError(null);
    if (token) {
      void Promise.all([
        api.userLifecycle(token, user.id),
        api.userLoginHistory(token, user.id),
        api.userSessions(token, user.id),
      ])
        .then(([events, history, sessionRows]) => {
          setLifecycle(events.items);
          setLogins(history.items);
          setSessions(sessionRows);
        })
        .catch(() => {
          setLifecycle([]);
          setLogins([]);
          setSessions([]);
        });
    }
  }, [token, user]);

  async function run(action: () => Promise<void>, success: string) {
    setBusy(true);
    setError(null);
    try {
      await action();
      toast('success', success);
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The lifecycle action failed.');
    } finally {
      setBusy(false);
    }
  }

  const save = () => {
    if (!token || !user) return;
    void run(async () => {
      if (role !== user.role) await api.updateUser(token, user.id, { role });
      if (
        mode !== user.site_access_mode ||
        JSON.stringify([...siteIds].sort()) !== JSON.stringify([...user.site_ids].sort())
      ) {
        await api.updateUserSiteAccess(
          token,
          user.id,
          mode,
          mode === 'assigned' ? siteIds : [],
          'Administrator updated site access',
        );
      }
    }, 'User access updated.');
  };

  const issueInvitation = () => {
    if (!token || !user) return;
    void run(async () => {
      const result = await api.issueInvitation(token, user.id);
      onLink({
        title: 'Invitation link',
        url: result.invitation_url,
        expiresAt: result.expires_at,
      });
    }, 'A new invitation was created.');
  };

  const issueReset = () => {
    if (!token || !user) return;
    void run(async () => {
      const result = await api.issuePasswordReset(token, user.id);
      onLink({ title: 'Password-reset link', url: result.reset_url, expiresAt: result.expires_at });
    }, 'A password-reset link was created.');
  };

  const changeStatus = () => {
    if (!token || !user || !statusAction || !reason.trim()) return;
    void run(async () => {
      await api.updateUserStatus(token, user.id, statusAction, reason.trim());
      setStatusAction(null);
      setReason('');
    }, `Account ${statusAction}.`);
  };

  const revokeSession = (sessionId: string) => {
    if (!token || !user) return;
    void run(async () => {
      await api.revokeUserSession(token, user.id, sessionId);
      const updated = await api.userSessions(token, user.id);
      setSessions(updated);
    }, 'Session revoked.');
  };

  const dirty =
    user &&
    (role !== user.role ||
      mode !== user.site_access_mode ||
      JSON.stringify([...siteIds].sort()) !== JSON.stringify([...user.site_ids].sort()));
  const isSelf = user?.id === currentUser?.id;

  return (
    <>
      <Drawer
        open={user !== null}
        onClose={onClose}
        title={user?.full_name || user?.email || ''}
        description={user?.email}
        size="lg"
      >
        {user && (
          <div className="flex flex-col gap-4">
            {error && <InlineError message={error} />}
            <div className="flex flex-wrap gap-2">
              <Badge tone={STATUS_TONES[user.account_status]} dot>
                {label(user.account_status)}
              </Badge>
              <Badge tone="accent">{label(user.authentication_source)}</Badge>
              <Badge
                tone={
                  user.mfa_status === 'enrolled'
                    ? 'ok'
                    : user.mfa_status === 'required'
                      ? 'warn'
                      : 'neutral'
                }
              >
                MFA {label(user.mfa_status)}
              </Badge>
            </div>
            <section className="grid gap-3 rounded-lg border border-border p-3 sm:grid-cols-2">
              <Field label="Role" htmlFor="user-role">
                <Select
                  id="user-role"
                  value={role}
                  disabled={isSelf}
                  onChange={(e) => setRole(e.target.value as Role)}
                >
                  {ROLES.map((value) => (
                    <option key={value} value={value}>
                      {label(value)}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field label="Site access" htmlFor="user-site-mode">
                <Select
                  id="user-site-mode"
                  value={mode}
                  onChange={(e) => setMode(e.target.value as SiteAccessMode)}
                >
                  <option value="assigned">Assigned sites</option>
                  <option value="all">All sites</option>
                </Select>
              </Field>
              {mode === 'assigned' && (
                <Field label="Assigned sites" className="sm:col-span-2">
                  <SiteChoices sites={sites} selected={siteIds} onChange={setSiteIds} />
                </Field>
              )}
              <div className="flex justify-end sm:col-span-2">
                <Button variant="outline" size="sm" loading={busy} disabled={!dirty} onClick={save}>
                  Save access
                </Button>
              </div>
            </section>
            <section>
              <h3 className="mb-2 text-xs font-semibold text-text">Lifecycle actions</h3>
              <div className="flex flex-wrap gap-2">
                {user.authentication_source === 'local' && !isSelf && (
                  <Button size="sm" variant="outline" onClick={issueInvitation} loading={busy}>
                    <MailPlus size={13} />{' '}
                    {user.account_status === 'invited' ? 'Replace invitation' : 'Issue invitation'}
                  </Button>
                )}
                {user.authentication_source === 'local' && user.account_status === 'active' && (
                  <Button size="sm" variant="outline" onClick={issueReset} loading={busy}>
                    <KeyRound size={13} /> Reset password
                  </Button>
                )}
                {!isSelf && user.account_status === 'active' && (
                  <Button size="sm" variant="outline" onClick={() => setStatusAction('suspended')}>
                    Suspend
                  </Button>
                )}
                {!isSelf &&
                  ['suspended', 'deactivated', 'locked'].includes(user.account_status) && (
                    <Button size="sm" variant="outline" onClick={() => setStatusAction('active')}>
                      Reactivate
                    </Button>
                  )}
                {!isSelf && user.account_status !== 'deactivated' && (
                  <Button
                    size="sm"
                    variant="destructive"
                    onClick={() => setStatusAction('deactivated')}
                  >
                    Deactivate
                  </Button>
                )}
              </div>
            </section>
            <section>
              <h3 className="mb-2 text-xs font-semibold text-text">Sessions</h3>
              <div className="space-y-2 rounded-lg border border-border p-3">
                {sessions.length === 0 && (
                  <p className="text-xs text-faint">No session records are available.</p>
                )}
                {sessions.map((session) => (
                  <div
                    key={session.id}
                    className="flex flex-col justify-between gap-2 text-xs sm:flex-row sm:items-center"
                  >
                    <span className="min-w-0 text-muted">
                      <span className="block truncate font-medium text-text">
                        {session.device_name || 'Unnamed device'}
                      </span>
                      <span className="block truncate">
                        {session.source_ip || 'Unknown IP'} · Last seen{' '}
                        {formatWhenFull(session.last_seen_at)}
                      </span>
                    </span>
                    <span className="flex shrink-0 items-center gap-2">
                      <Badge tone={session.active ? 'ok' : 'neutral'}>
                        {session.active ? 'Active' : 'Revoked or expired'}
                      </Badge>
                      {session.active && (
                        <Button
                          size="sm"
                          variant="outline"
                          loading={busy}
                          onClick={() => revokeSession(session.id)}
                        >
                          Revoke
                        </Button>
                      )}
                    </span>
                  </div>
                ))}
              </div>
            </section>
            <section>
              <h3 className="mb-2 text-xs font-semibold text-text">Login history</h3>
              <div className="space-y-2 rounded-lg border border-border p-3">
                {logins.length === 0 && (
                  <p className="text-xs text-faint">No login events recorded.</p>
                )}
                {logins.map((event) => (
                  <div key={event.id} className="flex justify-between gap-3 text-xs">
                    <span>
                      <Badge tone={event.outcome === 'succeeded' ? 'ok' : 'warn'}>
                        {label(event.outcome)}
                      </Badge>{' '}
                      {event.source_ip ?? 'Unknown IP'}
                    </span>
                    <span className="text-faint">{formatWhenFull(event.occurred_at)}</span>
                  </div>
                ))}
              </div>
            </section>
            <section>
              <h3 className="mb-2 text-xs font-semibold text-text">Lifecycle history</h3>
              <div className="space-y-2 rounded-lg border border-border p-3">
                {lifecycle.length === 0 && (
                  <p className="text-xs text-faint">No lifecycle events recorded.</p>
                )}
                {lifecycle.map((event) => (
                  <div key={event.id} className="flex justify-between gap-3 text-xs">
                    <span className="text-muted">
                      {label(event.event_type.replace(/^user\./, ''))}
                      {event.reason ? ` · ${event.reason}` : ''}
                    </span>
                    <span className="shrink-0 text-faint">{formatWhenFull(event.created_at)}</span>
                  </div>
                ))}
              </div>
            </section>
          </div>
        )}
      </Drawer>
      <Modal
        open={statusAction !== null}
        onClose={() => setStatusAction(null)}
        title={`${statusAction ? label(statusAction) : 'Change'} account`}
        description="This action is immediate and is recorded in the audit and lifecycle history."
        footer={
          <>
            <Button variant="ghost" onClick={() => setStatusAction(null)}>
              Cancel
            </Button>
            <Button
              variant={statusAction === 'deactivated' ? 'destructive' : 'primary'}
              loading={busy}
              disabled={!reason.trim()}
              onClick={changeStatus}
            >
              Confirm
            </Button>
          </>
        }
      >
        <Field label="Reason" htmlFor="status-reason">
          <Textarea
            id="status-reason"
            required
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
        </Field>
      </Modal>
    </>
  );
}

function OneTimeLinkModal({ value, onClose }: { value: OneTimeLink | null; onClose: () => void }) {
  const { toast } = useToast();
  const copy = async () => {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value.url);
      toast('success', 'Link copied to clipboard.');
    } catch {
      toast('error', 'Could not copy automatically. Select and copy the link manually.');
    }
  };
  return (
    <Modal
      open={value !== null}
      onClose={onClose}
      title={value?.title ?? 'One-time link'}
      description="This value is shown once. It is stored only as a purpose-bound hash."
      footer={
        <Button variant="primary" onClick={onClose}>
          Done
        </Button>
      }
    >
      {value && (
        <div className="flex flex-col gap-3">
          <Field
            label="Copy this link"
            htmlFor="one-time-link"
            hint={`Expires ${formatWhenFull(value.expiresAt)}`}
          >
            <div className="flex gap-2">
              <Input id="one-time-link" readOnly value={value.url} />
              <Button variant="outline" aria-label="Copy one-time link" onClick={() => void copy()}>
                <Copy size={14} />
              </Button>
            </div>
          </Field>
        </div>
      )}
    </Modal>
  );
}
