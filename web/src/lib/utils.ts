export function cn(...inputs: Array<string | undefined | false | null>) {
  return inputs.filter(Boolean).join(' ');
}

export function formatDate(value?: string | null) {
  if (!value) return '—';
  return new Date(value).toLocaleString();
}
