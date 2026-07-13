'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { api } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

export default function ProjectReportsPage() {
  const params = useParams<{ id: string }>();
  const projectId = Number(params?.id);
  const [reports, setReports] = useState<any[]>([]);

  useEffect(() => {
    if (projectId) api.listReports(projectId).then(setReports).catch(() => setReports([]));
  }, [projectId]);

  return (
    <main className="mx-auto min-h-screen max-w-6xl px-6 py-16">
      <div className="mb-8">
        <p className="text-sm uppercase tracking-[0.3em] text-cyan-400">Reports</p>
        <h1 className="text-3xl font-semibold">Reports and raw artifacts</h1>
      </div>
      <div className="grid gap-6">
        {reports.length ? reports.map((scan) => (
          <Card key={scan.scan_id}>
            <CardHeader>
              <CardTitle>Scan #{scan.scan_id} · {scan.status}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="mb-4 text-sm text-slate-500">Claude-BugHunter commit: {scan.methodology_commit || 'not recorded'}</div>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {scan.files?.map((file: string) => (
                  <a key={file} href={api.reportDownloadUrl(scan.scan_id, file)} className="rounded-lg border border-slate-800 bg-slate-950/70 px-3 py-2 text-sm text-slate-300">
                    {file}
                  </a>
                ))}
              </div>
            </CardContent>
          </Card>
        )) : (
          <Card>
            <CardContent>
              <p className="text-sm text-slate-400">No reports generated yet.</p>
            </CardContent>
          </Card>
        )}
      </div>
      <Link href={`/projects/${projectId}`} className="mt-6 block text-sm text-cyan-300">Back to project</Link>
    </main>
  );
}
