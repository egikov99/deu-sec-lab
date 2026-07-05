import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'DEU Security Platform',
  description: 'Internal security validation portal for projects and scans.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
