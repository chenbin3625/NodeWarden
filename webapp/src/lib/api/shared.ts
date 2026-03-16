import { t } from '../i18n';
import type { SessionState, TokenError } from '../types';

export type AuthedFetch = (input: string, init?: RequestInit) => Promise<Response>;
export type SessionSetter = (next: SessionState | null) => void;

export const BULK_API_CHUNK_SIZE = 200;

export function chunkArray<T>(items: T[], size: number): T[][] {
  if (items.length <= size) return [items];
  const chunks: T[][] = [];
  for (let i = 0; i < items.length; i += size) {
    chunks.push(items.slice(i, i + size));
  }
  return chunks;
}

export async function parseJson<T>(response: Response): Promise<T | null> {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text) as T;
  } catch {
    return null;
  }
}

export function parseContentDispositionFileName(response: Response, fallback: string): string {
  const header = String(response.headers.get('Content-Disposition') || '').trim();
  if (!header) return fallback;

  const utf8Match = header.match(/filename\*\s*=\s*UTF-8''([^;]+)/i);
  if (utf8Match?.[1]) {
    try {
      return decodeURIComponent(utf8Match[1]);
    } catch {
      // Ignore malformed filename*= values and fall back to the plain filename.
    }
  }

  const plainMatch = header.match(/filename\s*=\s*"([^"]+)"|filename\s*=\s*([^;]+)/i);
  const raw = plainMatch?.[1] || plainMatch?.[2] || '';
  const normalized = String(raw).trim().replace(/^"+|"+$/g, '');
  return normalized || fallback;
}

export async function parseErrorMessage(resp: Response, fallback: string): Promise<string> {
  const body = await parseJson<TokenError>(resp);
  return body?.error_description || body?.error || fallback;
}

export function createApiError(message: string, status?: number): Error & { status?: number } {
  const error = new Error(message) as Error & { status?: number };
  if (status !== undefined) error.status = status;
  return error;
}

export function requiredError(messageKey: string): never {
  throw new Error(t(messageKey));
}
