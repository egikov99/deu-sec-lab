'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

export default function NewProjectPage() {
  const router = useRouter();
  const [form, setForm] = useState({
    name: '',
    target: '',
    description: '',
    scan_type: 'basic',
    default_scan_mode: 'safe_validation',
    authorization_confirmed: false,
    credentials: {
      username: '',
      password: '',
      bearer_token: '',
      cookie: '',
      custom_headers: '',
      second_user: '',
      role_labels: '',
    },
    origin_ip: '',
    origin_scan_confirmed: false,
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const project = await api.createProject(form);
      router.push(`/projects/${project.id}`);
    } catch (err: any) {
      setError(err.message || 'Failed to create project');
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="mx-auto min-h-screen max-w-3xl px-6 py-16">
      <Card>
        <CardHeader>
          <CardTitle>Create project</CardTitle>
        </CardHeader>
        <CardContent>
          <form className="space-y-4" onSubmit={submit}>
            <div>
              <label className="mb-2 block text-sm text-slate-300">Project name</label>
              <input className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
            </div>
            <div>
              <label className="mb-2 block text-sm text-slate-300">Target URL or domain</label>
              <input className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2" value={form.target} onChange={(e) => setForm({ ...form, target: e.target.value })} required />
            </div>
            <div>
              <label className="mb-2 block text-sm text-slate-300">Description</label>
              <textarea className="min-h-24 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
            </div>
            <div>
              <label className="mb-2 block text-sm text-slate-300">Scan type</label>
              <select className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2" value={form.scan_type} onChange={(e) => setForm({ ...form, scan_type: e.target.value })}>
                <option value="basic">Basic</option>
                <option value="extended">Extended</option>
              </select>
            </div>
            <div>
              <label className="mb-2 block text-sm text-slate-300">Validation mode</label>
              <select className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2" value={form.default_scan_mode} onChange={(e) => setForm({ ...form, default_scan_mode: e.target.value })}>
                <option value="safe_validation">Safe validation</option>
                <option value="passive">Passive</option>
                <option value="explicit_approval">Explicit approval</option>
              </select>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <label className="mb-2 block text-sm text-slate-300">Username (optional)</label>
                <input className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2" value={form.credentials.username} onChange={(e) => setForm({ ...form, credentials: { ...form.credentials, username: e.target.value } })} />
              </div>
              <div>
                <label className="mb-2 block text-sm text-slate-300">Password (optional)</label>
                <input type="password" className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2" value={form.credentials.password} onChange={(e) => setForm({ ...form, credentials: { ...form.credentials, password: e.target.value } })} />
              </div>
              <div>
                <label className="mb-2 block text-sm text-slate-300">Bearer token (optional)</label>
                <input type="password" className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2" value={form.credentials.bearer_token} onChange={(e) => setForm({ ...form, credentials: { ...form.credentials, bearer_token: e.target.value } })} />
              </div>
              <div>
                <label className="mb-2 block text-sm text-slate-300">Cookie (optional)</label>
                <input type="password" className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2" value={form.credentials.cookie} onChange={(e) => setForm({ ...form, credentials: { ...form.credentials, cookie: e.target.value } })} />
              </div>
            </div>
            <div>
              <label className="mb-2 block text-sm text-slate-300">Origin IP (optional)</label>
              <input className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2" value={form.origin_ip} onChange={(e) => setForm({ ...form, origin_ip: e.target.value })} placeholder="93.184.216.34" />
            </div>
            <label className="flex items-start gap-3 rounded-lg border border-slate-800 bg-slate-950/70 p-3 text-sm text-slate-300">
              <input type="checkbox" className="mt-1" checked={form.origin_scan_confirmed} onChange={(e) => setForm({ ...form, origin_scan_confirmed: e.target.checked })} />
              <span>I confirm that I am authorized to scan the configured origin IP.</span>
            </label>
            <label className="flex items-start gap-3 rounded-lg border border-cyan-800/60 bg-cyan-950/20 p-3 text-sm text-slate-200">
              <input type="checkbox" className="mt-1" checked={form.authorization_confirmed} onChange={(e) => setForm({ ...form, authorization_confirmed: e.target.checked })} required />
              <span>I confirm that I own or am authorized to test this target.</span>
            </label>
            {error ? <p className="text-sm text-rose-400">{error}</p> : null}
            <Button type="submit" disabled={loading}>{loading ? 'Creating…' : 'Create project'}</Button>
          </form>
        </CardContent>
      </Card>
    </main>
  );
}
