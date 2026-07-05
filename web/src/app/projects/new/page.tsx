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
            {error ? <p className="text-sm text-rose-400">{error}</p> : null}
            <Button type="submit" disabled={loading}>{loading ? 'Creating…' : 'Create project'}</Button>
          </form>
        </CardContent>
      </Card>
    </main>
  );
}
