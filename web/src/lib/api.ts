const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || 'Request failed');
  }

  if (response.status === 204) return {} as T;
  return response.json() as Promise<T>;
}

export const api = {
  health: () => request<{ status: string }>('/health'),
  listProjects: () => request<any[]>('/api/projects'),
  createProject: (payload: unknown) => request<any>('/api/projects', { method: 'POST', body: JSON.stringify(payload) }),
  getProject: (id: number) => request<any>(`/api/projects/${id}`),
  startScan: (id: number) => request<any>(`/api/projects/${id}/scan`, { method: 'POST' }),
  getScan: (id: number) => request<any>(`/api/scans/${id}`),
  getReport: (id: number) => request<any>(`/api/reports/${id}`),
};
