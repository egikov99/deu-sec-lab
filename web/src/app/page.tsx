'use client';

import Link from 'next/link';
import { motion } from 'framer-motion';
import { ShieldCheck, ArrowRight } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

export default function HomePage() {
  return (
    <main className="mx-auto flex min-h-screen max-w-6xl flex-col justify-center px-6 py-16">
      <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} className="space-y-8">
        <div className="flex items-center gap-3 text-cyan-400">
          <ShieldCheck className="h-8 w-8" />
          <span className="text-lg font-semibold">DEU Security Platform</span>
        </div>

        <div className="space-y-4">
          <h1 className="max-w-3xl text-4xl font-semibold tracking-tight sm:text-6xl">
            Internal security validation, simplified.
          </h1>
          <p className="max-w-2xl text-lg text-slate-400">
            Create a project, add a target, run a scan, and review findings without needing a complex enterprise stack.
          </p>
        </div>

        <div className="flex flex-wrap gap-4">
          <Link href="/projects">
            <Button className="inline-flex items-center gap-2">Open projects <ArrowRight className="h-4 w-4" /></Button>
          </Link>
          <Link href="/projects/new">
            <Button variant="secondary">Create project</Button>
          </Link>
        </div>

        <div className="grid gap-6 md:grid-cols-3">
          <Card>
            <CardHeader>
              <CardTitle>Projects</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-slate-400">Organize each internal target and keep scan history together.</p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Scan progress</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-slate-400">Track queued, running, completed, and failed checks in real time.</p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Reports</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-slate-400">Download Markdown, HTML, JSON, and PDF reports after each scan.</p>
            </CardContent>
          </Card>
        </div>
      </motion.div>
    </main>
  );
}
