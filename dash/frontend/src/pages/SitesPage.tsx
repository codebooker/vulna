import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { ApiError, api } from '../api/client';
import { useAuth } from '../auth/useAuth';
import type { Site } from '../types/inventory';

export function SitesPage() {
  const { token, user, logout } = useAuth();
  const [sites, setSites] = useState<Site[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const isAdmin = user?.role === 'administrator';

  const loadSites = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const page = await api.listSites(token);
      setSites(page.items);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        logout();
        return;
      }
      setError(err instanceof Error ? err.message : 'Failed to load sites.');
    } finally {
      setLoading(false);
    }
  }, [token, logout]);

  useEffect(() => {
    void loadSites();
  }, [loadSites]);

  return (
    <div className="card">
      <h2>Sites</h2>
      {loading && <p className="detail">Loading sites…</p>}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}

      {!loading && sites.length === 0 && !error && <p className="detail">No sites yet.</p>}

      {sites.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Code</th>
              <th>Timezone</th>
            </tr>
          </thead>
          <tbody>
            {sites.map((site) => (
              <tr key={site.id}>
                <td>{site.name}</td>
                <td>
                  <code>{site.code}</code>
                </td>
                <td>{site.timezone}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {isAdmin && <CreateSiteForm onCreated={loadSites} />}
    </div>
  );
}

function CreateSiteForm({ onCreated }: { onCreated: () => void }) {
  const { token, logout } = useAuth();
  const [name, setName] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (!token) return;
    setError(null);
    setSubmitting(true);
    try {
      await api.createSite(token, { name, code });
      setName('');
      setCode('');
      onCreated();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        logout();
        return;
      }
      setError(err instanceof Error ? err.message : 'Failed to create site.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form className="form inline" onSubmit={handleSubmit}>
      <h3>Add a site</h3>
      <div className="row">
        <label className="field">
          <span>Name</span>
          <input value={name} onChange={(e) => setName(e.target.value)} required />
        </label>
        <label className="field">
          <span>Code</span>
          <input value={code} onChange={(e) => setCode(e.target.value)} required />
        </label>
      </div>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <button type="submit" className="btn" disabled={submitting}>
        {submitting ? 'Creating…' : 'Create site'}
      </button>
    </form>
  );
}
