'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { PauseCircle, RotateCcw } from 'lucide-react';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ProgressBar } from '@/components/ui/progress';

export default function ScanRunPage() {
  const params = useParams<{ id: string; scanId: string }>();
  const projectId = Number(params?.id);
  const scanId = Number(params?.scanId);
  const [scan, setScan] = useState<any>(null);

  async function refresh() {
    if (!scanId) return;
    setScan(await api.getScan(scanId));
  }

  useEffect(() => {
    refresh();
  }, [scanId]);

  useEffect(() => {
    if (!scan || !['queued', 'planning', 'running', 'validating', 'reporting', 'waiting_approval'].includes(scan.status)) return;
    const timer = setInterval(refresh, 2000);
    return () => clearInterval(timer);
  }, [scan?.id, scan?.status]);

  if (!scan) return <main className="mx-auto min-h-screen max-w-6xl px-6 py-16">Loading...</main>;

  const latestStep = scan.steps?.[scan.steps.length - 1];

  return (
    <main className="mx-auto min-h-screen max-w-6xl px-6 py-16">
      <div className="mb-8 flex items-center justify-between gap-4">
        <div>
          <p className="text-sm uppercase tracking-[0.3em] text-cyan-400">Scan run</p>
          <h1 className="text-3xl font-semibold">Scan #{scan.id}</h1>
        </div>
        <div className="flex gap-2">
          <Button variant="secondary" onClick={() => api.resumeScan(scan.id).then(refresh)} className="inline-flex items-center gap-2">
            <RotateCcw className="h-4 w-4" /> Resume
          </Button>
          <Button variant="secondary" onClick={() => api.cancelScan(scan.id).then(refresh)} className="inline-flex items-center gap-2">
            <PauseCircle className="h-4 w-4" /> Stop
          </Button>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-[1fr,0.8fr]">
        <Card>
          <CardHeader>
            <CardTitle>Progress</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-medium">{scan.current_step || 'Queued'}</div>
                  <div className="text-sm text-slate-400">Status: {scan.status} · Phase: {scan.phase}</div>
                </div>
                <span className="rounded-full bg-slate-800 px-3 py-1 text-xs uppercase">{scan.status}</span>
              </div>
              <ProgressBar value={scan.progress || 0} />
              <div className="grid gap-2 text-sm text-slate-400 sm:grid-cols-2">
                <div>Current skill: <span className="text-slate-200">{latestStep?.skill || scan.selected_skills?.[0] || 'pending'}</span></div>
                <div>Current tool: <span className="text-slate-200">{latestStep?.tool || 'pending'}</span></div>
                <div>Model: <span className="text-slate-200">{scan.model || 'not set'}</span></div>
                <div>Token usage: <span className="text-slate-200">{JSON.stringify(scan.token_usage || {})}</span></div>
              </div>
              {latestStep?.ai_analysis?.operational_summary ? (
                <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3 text-sm text-slate-300">
                  {latestStep.ai_analysis.operational_summary}
                </div>
              ) : null}
              {scan.approval_requests?.length ? (
                <div className="rounded-lg border border-amber-600/40 bg-amber-950/30 p-3 text-sm text-amber-100">
                  <div className="font-medium">Approval required</div>
                  <pre className="mt-2 whitespace-pre-wrap text-xs">{JSON.stringify(scan.approval_requests[scan.approval_requests.length - 1], null, 2)}</pre>
                </div>
              ) : null}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Reports</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {scan.files?.length ? scan.files.map((file: string) => (
                <a key={file} href={api.reportDownloadUrl(scan.id, file)} className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/70 px-3 py-2 text-sm text-slate-300">
                  <span>{file}</span>
                </a>
              )) : <p className="text-sm text-slate-400">No report files yet.</p>}
              <Link href={`/projects/${projectId}`} className="block text-sm text-cyan-300">Back to project</Link>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="mt-6 grid gap-6 lg:grid-cols-[1fr,1fr]">
        <Card>
          <CardHeader>
            <CardTitle>Agent steps</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {scan.steps?.length ? scan.steps.map((step: any) => (
                <div key={step.id} className="rounded-lg border border-slate-800 bg-slate-950/70 p-3 text-sm">
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-slate-100">#{step.sequence} {step.tool || step.phase}</span>
                    <span className="rounded-full bg-slate-800 px-2 py-1 text-xs">{step.status}</span>
                  </div>
                  <div className="mt-2 text-slate-500">{step.skill}</div>
                  <div className="mt-2 text-slate-400">{step.ai_analysis?.operational_summary || 'No operational summary yet.'}</div>
                </div>
              )) : <p className="text-sm text-slate-400">No steps recorded yet.</p>}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Live logs</CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="max-h-[520px] overflow-auto whitespace-pre-wrap text-xs text-slate-400">{scan.logs || 'Waiting for worker...'}</pre>
          </CardContent>
        </Card>
      </div>
    </main>
  );
}
