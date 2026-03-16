import type { Cipher } from '../types';

type SafeBind = (stmt: D1PreparedStatement, ...values: any[]) => D1PreparedStatement;
type SqlChunkSize = (fixedBindCount: number) => number;
type UpdateRevisionDate = (userId: string) => Promise<string>;

export async function getCipher(db: D1Database, id: string): Promise<Cipher | null> {
  const row = await db.prepare('SELECT data FROM ciphers WHERE id = ?').bind(id).first<{ data: string }>();
  if (!row?.data) return null;
  try {
    return JSON.parse(row.data) as Cipher;
  } catch {
    console.error('Corrupted cipher data, id:', id);
    return null;
  }
}

export async function saveCipher(db: D1Database, safeBind: SafeBind, cipher: Cipher): Promise<void> {
  const data = JSON.stringify(cipher);
  const stmt = db.prepare(
    'INSERT INTO ciphers(id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, deleted_at) ' +
    'VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
    'ON CONFLICT(id) DO UPDATE SET ' +
    'user_id=excluded.user_id, type=excluded.type, folder_id=excluded.folder_id, name=excluded.name, notes=excluded.notes, favorite=excluded.favorite, data=excluded.data, reprompt=excluded.reprompt, key=excluded.key, updated_at=excluded.updated_at, deleted_at=excluded.deleted_at'
  );
  await safeBind(
    stmt,
    cipher.id,
    cipher.userId,
    Number(cipher.type) || 1,
    cipher.folderId,
    cipher.name,
    cipher.notes,
    cipher.favorite ? 1 : 0,
    data,
    cipher.reprompt ?? 0,
    cipher.key,
    cipher.createdAt,
    cipher.updatedAt,
    cipher.deletedAt
  ).run();
}

export async function deleteCipher(db: D1Database, id: string, userId: string): Promise<void> {
  await db.prepare('DELETE FROM ciphers WHERE id = ? AND user_id = ?').bind(id, userId).run();
}

export async function bulkSoftDeleteCiphers(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  updateRevisionDate: UpdateRevisionDate,
  ids: string[],
  userId: string
): Promise<string | null> {
  if (ids.length === 0) return null;
  const uniqueIds = Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
  if (!uniqueIds.length) return null;

  const now = new Date().toISOString();
  const patch = JSON.stringify({ deletedAt: now, updatedAt: now });
  const chunkSize = sqlChunkSize(4);

  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    await db
      .prepare(
        `UPDATE ciphers
         SET deleted_at = ?, updated_at = ?, data = json_patch(data, ?)
         WHERE user_id = ? AND id IN (${placeholders})`
      )
      .bind(now, now, patch, userId, ...chunk)
      .run();
  }

  return updateRevisionDate(userId);
}

export async function bulkRestoreCiphers(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  updateRevisionDate: UpdateRevisionDate,
  ids: string[],
  userId: string
): Promise<string | null> {
  if (ids.length === 0) return null;
  const uniqueIds = Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
  if (!uniqueIds.length) return null;

  const now = new Date().toISOString();
  const patch = JSON.stringify({ deletedAt: null, updatedAt: now });
  const chunkSize = sqlChunkSize(3);

  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    await db
      .prepare(
        `UPDATE ciphers
         SET deleted_at = NULL, updated_at = ?, data = json_patch(data, ?)
         WHERE user_id = ? AND id IN (${placeholders})`
      )
      .bind(now, patch, userId, ...chunk)
      .run();
  }

  return updateRevisionDate(userId);
}

export async function bulkDeleteCiphers(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  updateRevisionDate: UpdateRevisionDate,
  ids: string[],
  userId: string
): Promise<string | null> {
  if (ids.length === 0) return null;
  const uniqueIds = Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
  if (!uniqueIds.length) return null;

  const chunkSize = sqlChunkSize(1);
  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    await db.prepare(`DELETE FROM ciphers WHERE user_id = ? AND id IN (${placeholders})`).bind(userId, ...chunk).run();
  }

  return updateRevisionDate(userId);
}

export async function getAllCiphers(db: D1Database, userId: string): Promise<Cipher[]> {
  const res = await db.prepare('SELECT data FROM ciphers WHERE user_id = ? ORDER BY updated_at DESC').bind(userId).all<{ data: string }>();
  return (res.results || []).flatMap((r) => {
    try {
      return [JSON.parse(r.data) as Cipher];
    } catch {
      return [];
    }
  });
}

export async function getCiphersPage(
  db: D1Database,
  userId: string,
  includeDeleted: boolean,
  limit: number,
  offset: number
): Promise<Cipher[]> {
  const whereDeleted = includeDeleted ? '' : 'AND deleted_at IS NULL';
  const res = await db
    .prepare(
      `SELECT data FROM ciphers
       WHERE user_id = ?
       ${whereDeleted}
       ORDER BY updated_at DESC
       LIMIT ? OFFSET ?`
    )
    .bind(userId, limit, offset)
    .all<{ data: string }>();
  return (res.results || []).flatMap((r) => {
    try {
      return [JSON.parse(r.data) as Cipher];
    } catch {
      return [];
    }
  });
}

export async function getCiphersByIds(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  ids: string[],
  userId: string
): Promise<Cipher[]> {
  if (ids.length === 0) return [];
  const uniqueIds = Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
  if (!uniqueIds.length) return [];

  const chunkSize = sqlChunkSize(1);
  const out: Cipher[] = [];
  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    const stmt = db.prepare(`SELECT data FROM ciphers WHERE user_id = ? AND id IN (${placeholders})`);
    const res = await stmt.bind(userId, ...chunk).all<{ data: string }>();
    out.push(
      ...(res.results || []).flatMap((r) => {
        try {
          return [JSON.parse(r.data) as Cipher];
        } catch {
          return [];
        }
      })
    );
  }
  return out;
}

export async function bulkMoveCiphers(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  updateRevisionDate: UpdateRevisionDate,
  ids: string[],
  folderId: string | null,
  userId: string
): Promise<string | null> {
  if (ids.length === 0) return null;
  const now = new Date().toISOString();
  const uniqueIds = Array.from(new Set(ids));
  const patch = JSON.stringify({ folderId, updatedAt: now });
  const chunkSize = sqlChunkSize(4);

  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    await db
      .prepare(
        `UPDATE ciphers
         SET folder_id = ?, updated_at = ?, data = json_patch(data, ?)
         WHERE user_id = ? AND id IN (${placeholders})`
      )
      .bind(folderId, now, patch, userId, ...chunk)
      .run();
  }

  return updateRevisionDate(userId);
}
