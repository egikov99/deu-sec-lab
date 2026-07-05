'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import { Plus, ShieldCheck } from 'lucide-react';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

export default function ProjectsPage() {
  const [projects, setProjects] = useState<any[]>([]);

  useEffect(() => {
    api.listProjects().then(setProjects).catch(() => setProjects([]));
  }, []);

  return (
    <main className="mx-auto min-h-screen max-w-6xl px-6 py-16">
      <div className="mb-8 flex items-center justify-between">
        <div>
          <p className="text-sm uppercase tracking-[0.3em] text-cyan-400">Projects</p>
          <h1 className="text-3xl font-semibold">Internal projects</h1>
        </div>
        <Link href="/projects/new">
          <Button className="inline-flex items-center gap-2">
            <Plus className="h-4 w-4" /> Create project
          </Button>
        </Link>
      </div>

      <div className="grid gap-6">
        {projects.length === 0 ? (
          <Card>
            <CardHeader>
              <CardTitle>No projects yet</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-slate-400">Create your first project to start a scan.</p>
            </CardContent>
          </Card>
        ) : (
          projects.map((project) => (
            <Link key={project.id} href={`/projects/${project.id}`}>
              <Card className="cursor-pointer transition hover:border-cyan-500/40">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle>{project.name}</CardTitle>
                    <span className="rounded-full bg-slate-800 px-3 py-1 text-xs text-slate-300">{project.scan_type}</span>
                  </div>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-slate-400">{project.description || 'No description'}</p>
                  <div className="mt-4 flex items-center gap-4 text-sm text-slate-500">
                    <span className="inline-flex items-center gap-2"><ShieldCheck className="h-4 w-4" /> {project.target}</span>
                  </div>
                </CardContent>
              </Card>
            </Link>
          ))
        )}
      </div>
    </main>
  );
}
