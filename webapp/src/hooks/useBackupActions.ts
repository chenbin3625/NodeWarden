import { useMemo } from 'preact/hooks';
import {
  deleteRemoteBackup,
  downloadRemoteBackup,
  exportAdminBackup,
  getAdminBackupSettings,
  importAdminBackup,
  listRemoteBackups,
  restoreRemoteBackup,
  runAdminBackupNow,
  saveAdminBackupSettings,
} from '@/lib/api/backup';
import { downloadBytesAsFile } from '@/lib/download';
import type { AuthedFetch } from '@/lib/api/shared';

interface UseBackupActionsOptions {
  authedFetch: AuthedFetch;
  onImported?: () => void;
  onRestored?: () => void;
}

export default function useBackupActions(options: UseBackupActionsOptions) {
  const { authedFetch, onImported, onRestored } = options;

  return useMemo(
    () => ({
      async exportBackup() {
        const payload = await exportAdminBackup(authedFetch);
        downloadBytesAsFile(payload.bytes, payload.fileName, payload.mimeType);
      },

      async importBackup(file: File, replaceExisting: boolean = false) {
        const result = await importAdminBackup(authedFetch, file, replaceExisting);
        onImported?.();
        return result;
      },

      async loadSettings() {
        return getAdminBackupSettings(authedFetch);
      },

      async saveSettings(settings: Parameters<typeof saveAdminBackupSettings>[1]) {
        return saveAdminBackupSettings(authedFetch, settings);
      },

      async runRemoteBackup(destinationId?: string | null) {
        return runAdminBackupNow(authedFetch, destinationId);
      },

      async listRemoteBackups(destinationId: string, path: string) {
        return listRemoteBackups(authedFetch, destinationId, path);
      },

      async downloadRemoteBackup(destinationId: string, path: string, onProgress?: (percent: number | null) => void) {
        const payload = await downloadRemoteBackup(authedFetch, destinationId, path, onProgress);
        downloadBytesAsFile(payload.bytes, payload.fileName, payload.mimeType);
      },

      async deleteRemoteBackup(destinationId: string, path: string) {
        await deleteRemoteBackup(authedFetch, destinationId, path);
      },

      async restoreRemoteBackup(destinationId: string, path: string, replaceExisting: boolean = false) {
        const result = await restoreRemoteBackup(authedFetch, destinationId, path, replaceExisting);
        onRestored?.();
        return result;
      },
    }),
    [authedFetch, onImported, onRestored]
  );
}
