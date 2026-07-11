'use client';

import Link from 'next/link';
import { motion } from 'framer-motion';
import { ArrowRight, ShieldCheck } from 'lucide-react';
import { Button } from '@/components/ui/button';

export default function HomePage() {
  return (
    <main className="mx-auto flex min-h-screen max-w-6xl flex-col justify-center px-6 py-16">
      <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} className="space-y-8">
        <div className="flex items-center gap-3 text-cyan-400">
          <ShieldCheck className="h-8 w-8" />
          <span className="text-lg font-semibold">DEU Security Lab</span>
        </div>

        <div className="space-y-4">
          <h1 className="max-w-3xl text-4xl font-semibold tracking-tight sm:text-6xl">
            Internal web panel for safe security checks.
          </h1>
          <p className="max-w-2xl text-lg text-slate-400">
            Create a project, add a target URL or domain, run one whitelisted scan, and review reports from the browser.
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
      </motion.div>
    </main>
  );
}
