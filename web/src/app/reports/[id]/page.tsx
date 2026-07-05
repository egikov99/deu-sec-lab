'use client';

import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import { api } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

export default function ReportPage() {
  const params = useParams<{ id: string }>();
  const id = Number(params?.id);
  const [report, setReport] = useState<any>(null);

  useEffect(() => {
    if (!id) return;
    api.getReport(id).then(setReport).catch(() => setReport(null));
  }, [id]);

  if (!report) return <main className="mx-auto min-h-screen max-w-6xl px-6 py-16">Loading report…</main>;

  return (
    <main className="mx-auto min-h-screen max-w-6xl px-6 py-16">
      <Card>
        <CardHeader>
          <CardTitle>Report for scan #{report.scan_id}</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-6">
            <div>
              <h2 className="mb-2 text-lg font-semibold text-white">Summary</h2>
              <p className="whitespace-pre-wrap text-sm text-slate-400">{report.summary}</p>
            </div>
            <div>
              <h2 className="mb-2 text-lg font-semibold text-white">Markdown</h2>
              <pre className="max-h-96 overflow-auto whitespace-pre-wrap rounded-xl border border-slate-800 bg-slate-950/70 p-4 text-xs text-slate-400">{report.markdown}</pre>
            </div>
            <div>
              <h2 className="mb-2 text-lg font-semibold text-white">Findings JSON</h2>
              <pre className="max-h-96 overflow-auto whitespace-pre-wrap rounded-xl border border-slate-800 bg-slate-950/70 p-4 text-xs text-slate-400">{JSON.stringify(report.findings, null, 2)}</pre>
            </div>
          </div>
        </CardContent>
      </Card>
    </main>
  );
}
