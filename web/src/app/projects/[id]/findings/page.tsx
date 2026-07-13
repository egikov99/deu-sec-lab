'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { api } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

export default function ProjectFindingsPage() {
  const params = useParams<{ id: string }>();
  const projectId = Number(params?.id);
  const [findings, setFindings] = useState<any[]>([]);

  useEffect(() => {
    if (projectId) api.listFindings(projectId).then(setFindings).catch(() => setFindings([]));
  }, [projectId]);

  return (
    <main className="mx-auto min-h-screen max-w-6xl px-6 py-16">
      <div className="mb-8">
        <p className="text-sm uppercase tracking-[0.3em] text-cyan-400">Findings</p>
        <h1 className="text-3xl font-semibold">Project findings</h1>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>All recorded findings</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {findings.length ? findings.map((finding) => (
              <div key={finding.id} className="rounded-lg border border-slate-800 bg-slate-950/70 p-4">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-slate-100">{finding.title}</div>
                    <div className="text-sm text-slate-500">{finding.category} · {finding.endpoint || 'endpoint not recorded'}</div>
                  </div>
                  <span className="rounded-full bg-slate-800 px-3 py-1 text-xs uppercase">{finding.severity}</span>
                </div>
                <div className="mt-3 grid gap-2 text-sm text-slate-400 sm:grid-cols-3">
                  <div>Confidence: {finding.confidence}</div>
                  <div>Validation: {finding.validation_status}</div>
                  <div>Status: {finding.status}</div>
                </div>
              </div>
            )) : <p className="text-sm text-slate-400">No findings recorded yet.</p>}
          </div>
          <Link href={`/projects/${projectId}`} className="mt-6 block text-sm text-cyan-300">Back to project</Link>
        </CardContent>
      </Card>
    </main>
  );
}
