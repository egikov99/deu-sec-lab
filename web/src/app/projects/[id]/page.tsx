'use client';

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { motion } from 'framer-motion';
import { Download, ExternalLink, FileText, Play, ShieldCheck } from 'lucide-react';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ProgressBar } from '@/components/ui/progress';
import { formatDate } from '@/lib/utils';

export default function ProjectDetailPage() {
  const params = useParams<{ id: string }>();
  const id = Number(params?.id);
  const [project, setProject] = useState<any>(null);
  const [scan, setScan] = useState<any>(null);
  const [scans, setScans] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);

  const refresh = async () => {
    if (!id) return;
    const data = await api.getProject(id);
    setProject(data.project);
    setScan(data.latest_scan || null);
    setScans(data.scans || []);
  };

  useEffect(() => {
    refresh();
  }, [id]);

  useEffect(() => {
    if (!scan || !['queued', 'planning', 'running', 'validating', 'reporting', 'waiting_approval'].includes(scan.status)) return;
    const timer = setInterval(async () => {
      const updated = await api.getScan(scan.id);
      setScan(updated);
    }, 2000);
    return () => clearInterval(timer);
  }, [scan?.id, scan?.status]);

  async function startScan() {
    setLoading(true);
    try {
      const result = await api.startScan(id);
      setScan(result.scan);
    } finally {
      setLoading(false);
    }
  }

  const severitySummary = useMemo(() => {
    const findings = scan?.findings || [];
    return findings.reduce((acc: Record<string, number>, item: any) => {
      acc[item.severity] = (acc[item.severity] || 0) + 1;
      return acc;
    }, {});
  }, [scan?.findings]);

  if (!project) return <main className="mx-auto min-h-screen max-w-6xl px-6 py-16">Loading…</main>;

  return (
    <main className="mx-auto min-h-screen max-w-6xl px-6 py-16">
      <div className="mb-8 flex items-center justify-between gap-4">
        <div>
          <p className="text-sm uppercase tracking-[0.3em] text-cyan-400">Project details</p>
          <h1 className="text-3xl font-semibold">{project.name}</h1>
        </div>
        <Button onClick={startScan} disabled={loading} className="inline-flex items-center gap-2">
          <Play className="h-4 w-4" />
          {loading ? 'Starting...' : 'Проверить безопасность'}
        </Button>
      </div>

      <div className="grid gap-6 lg:grid-cols-[1.2fr,0.8fr]">
        <Card>
          <CardHeader>
            <CardTitle>Project overview</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-slate-400">{project.description || 'No description'}</p>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-3">
                <div className="text-xs uppercase tracking-[0.3em] text-slate-500">Target</div>
                <div className="mt-2 font-medium">{project.target}</div>
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-3">
                <div className="text-xs uppercase tracking-[0.3em] text-slate-500">Scan type</div>
                <div className="mt-2 font-medium">{project.scan_type}</div>
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-3">
                <div className="text-xs uppercase tracking-[0.3em] text-slate-500">Validation</div>
                <div className="mt-2 font-medium">{project.default_scan_mode}</div>
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-3">
                <div className="text-xs uppercase tracking-[0.3em] text-slate-500">Authorization</div>
                <div className="mt-2 font-medium">{project.authorization_confirmed ? 'Confirmed' : 'Missing'}</div>
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-3">
                <div className="text-xs uppercase tracking-[0.3em] text-slate-500">Origin IP</div>
                <div className="mt-2 font-medium">{project.origin_ip || 'Not configured'}</div>
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-3">
                <div className="text-xs uppercase tracking-[0.3em] text-slate-500">Origin scan</div>
                <div className="mt-2 font-medium">{project.origin_scan_confirmed ? 'Authorized' : 'Disabled'}</div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Scan status</CardTitle>
          </CardHeader>
          <CardContent>
            {!scan ? (
              <p className="text-sm text-slate-400">No scan started yet.</p>
            ) : (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-sm font-medium">{scan.current_step || 'Queued'}</div>
                    <div className="text-sm text-slate-400">Status: {scan.status}</div>
                    <div className="text-xs text-slate-500">Phase: {scan.phase || 'queued'}</div>
                  </div>
                  <span className="rounded-full bg-slate-800 px-3 py-1 text-xs uppercase">{scan.status}</span>
                </div>
                <ProgressBar value={scan.progress || 0} />
                <div className="grid gap-2 text-sm text-slate-400 sm:grid-cols-2">
                  <div>Skill: <span className="text-slate-200">{scan.steps?.at?.(-1)?.skill || scan.selected_skills?.[0] || 'pending'}</span></div>
                  <div>Tool: <span className="text-slate-200">{scan.steps?.at?.(-1)?.tool || 'pending'}</span></div>
                  <div>Model: <span className="text-slate-200">{scan.model || 'not set'}</span></div>
                  <div>Commit: <span className="text-slate-200">{scan.methodology_commit || 'pending'}</span></div>
                </div>
                {scan.approval_requests?.length ? (
                  <div className="rounded-xl border border-amber-600/40 bg-amber-950/30 p-3 text-sm text-amber-100">
                    Approval required: {scan.approval_requests[scan.approval_requests.length - 1]?.summary}
                  </div>
                ) : null}
                {scan.warnings?.length ? (
                  <div className="rounded-xl border border-amber-600/40 bg-amber-950/30 p-3 text-sm text-amber-200">
                    {scan.warnings.join(' ')}
                  </div>
                ) : null}
                <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-3">
                  <div className="text-xs uppercase tracking-[0.3em] text-slate-500">Live logs</div>
                  <pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap text-xs text-slate-400">{scan.logs || 'Waiting for the worker…'}</pre>
                </div>
                <Link href={`/projects/${project.id}/scans/${scan.id}`} className="flex items-center justify-between rounded-lg border border-cyan-700/50 bg-cyan-950/30 px-3 py-2 text-sm text-cyan-200">
                  <span>Open active scan</span>
                  <ExternalLink className="h-4 w-4" />
                </Link>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="mt-6 grid gap-6 lg:grid-cols-[1fr,0.8fr]">
        <Card>
          <CardHeader>
            <CardTitle>Security summary</CardTitle>
          </CardHeader>
          <CardContent>
            {scan?.summary ? (
              <div className="space-y-4">
                <p className="text-sm text-slate-300">{scan.summary}</p>
                {scan.normalized_outputs?.cdn_detection ? (
                  <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-3 text-sm text-slate-300">
                    CDN detected: {String(Boolean(scan.normalized_outputs.cdn_detection.is_cdn))}; providers: {(scan.normalized_outputs.cdn_detection.providers || []).join(', ') || 'none'}
                  </div>
                ) : null}
                <div className="flex flex-wrap gap-2">
                  {Object.entries(severitySummary).map(([severity, count]) => (
                    <span key={severity} className="rounded-full border border-slate-700 bg-slate-950/70 px-3 py-1 text-sm text-slate-300">{severity}: {String(count)}</span>
                  ))}
                </div>
              </div>
            ) : (
              <p className="text-sm text-slate-400">Run a scan to see generated findings and a summary.</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Report files</CardTitle>
          </CardHeader>
          <CardContent>
            {scan?.files?.length ? (
              <div className="space-y-3">
                {scan.files.map((file: string) => (
                  <a key={file} href={api.reportDownloadUrl(scan.id, file)} className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/70 px-3 py-2 text-sm text-slate-300">
                    <span>{file}</span>
                    <Download className="h-4 w-4" />
                  </a>
                ))}
                <Link href={`/reports/${scan.id}`} className="flex items-center justify-between rounded-lg border border-cyan-700/50 bg-cyan-950/30 px-3 py-2 text-sm text-cyan-200">
                  <span>Open report view</span>
                  <ExternalLink className="h-4 w-4" />
                </Link>
              </div>
            ) : (
              <p className="text-sm text-slate-400">Reports will appear once the scan completes.</p>
            )}
          </CardContent>
        </Card>
      </div>

      {scan?.findings?.length ? (
        <div className="mt-6">
          <Card>
            <CardHeader>
              <CardTitle>Findings</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {scan.findings.map((finding: any, index: number) => (
                  <motion.div key={`${finding.title}-${index}`} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
                    <div className="mb-2 flex items-center justify-between gap-3">
                      <div className="font-medium text-white">{finding.title}</div>
                      <span className="rounded-full bg-slate-800 px-3 py-1 text-xs uppercase">{finding.severity}</span>
                    </div>
                    <p className="mb-3 text-sm text-slate-400">{finding.description}</p>
                    <div className="space-y-2 text-sm text-slate-500">
                      <div><span className="text-slate-300">Recommendation:</span> {finding.recommendation}</div>
                      <div><span className="text-slate-300">Technical details:</span></div>
                      <pre className="max-h-48 overflow-auto whitespace-pre-wrap rounded-lg border border-slate-800 bg-slate-950 p-3 text-xs text-slate-400">{JSON.stringify(finding.technical_details || {}, null, 2)}</pre>
                      <div><span className="text-slate-300">Raw output:</span></div>
                      <pre className="max-h-48 overflow-auto whitespace-pre-wrap rounded-lg border border-slate-800 bg-slate-950 p-3 text-xs text-slate-400">{JSON.stringify(finding.raw_output || {}, null, 2)}</pre>
                    </div>
                  </motion.div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      ) : null}

      <div className="mt-6 grid gap-6 lg:grid-cols-[1fr,0.8fr]">
        <Card>
          <CardHeader>
            <CardTitle>Scan history</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {scans.length ? scans.map((item) => (
                <Link key={item.id} href={`/projects/${project.id}/scans/${item.id}`} className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/70 px-3 py-3 text-sm">
                  <div>
                    <div className="font-medium text-slate-100">Scan #{item.id} · {item.status}</div>
                    <div className="text-slate-500">{formatDate(item.created_at)} · {item.methodology_commit || 'commit pending'} · {item.selected_skills?.length || 0} skills</div>
                  </div>
                  <span className="rounded-full bg-slate-800 px-3 py-1 text-xs">{item.findings?.length || 0} findings</span>
                </Link>
              )) : <p className="text-sm text-slate-400">No scan runs yet.</p>}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Project data</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <Link href={`/projects/${project.id}/findings`} className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/70 px-3 py-2 text-sm text-slate-300">
                <span>All findings</span>
                <ShieldCheck className="h-4 w-4" />
              </Link>
              <Link href={`/projects/${project.id}/reports`} className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/70 px-3 py-2 text-sm text-slate-300">
                <span>Reports and artifacts</span>
                <FileText className="h-4 w-4" />
              </Link>
            </div>
          </CardContent>
        </Card>
      </div>
    </main>
  );
}
