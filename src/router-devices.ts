import type { Env } from './types';
import {
  handleGetAuthorizedDevices,
  handleGetDevices,
  handleRevokeAllTrustedDevices,
  handleRevokeTrustedDevice,
  handleDeleteAllDevices,
  handleDeleteDevice,
  handleUpdateDeviceToken,
} from './handlers/devices';

export async function handleAuthenticatedDeviceRoute(
  request: Request,
  env: Env,
  userId: string,
  path: string,
  method: string
): Promise<Response | null> {
  if (path === '/api/devices') {
    if (method === 'GET') return handleGetDevices(request, env, userId);
    if (method === 'DELETE') return handleDeleteAllDevices(request, env, userId);
    return null;
  }

  if (path === '/api/devices/authorized') {
    if (method === 'GET') return handleGetAuthorizedDevices(request, env, userId);
    if (method === 'DELETE') return handleRevokeAllTrustedDevices(request, env, userId);
    return null;
  }

  const authorizedDeviceMatch = path.match(/^\/api\/devices\/authorized\/([^/]+)$/i);
  if (authorizedDeviceMatch && method === 'DELETE') {
    const deviceIdentifier = decodeURIComponent(authorizedDeviceMatch[1]);
    return handleRevokeTrustedDevice(request, env, userId, deviceIdentifier);
  }

  const deleteDeviceMatch = path.match(/^\/api\/devices\/([^/]+)$/i);
  if (deleteDeviceMatch && method === 'DELETE') {
    const deviceIdentifier = decodeURIComponent(deleteDeviceMatch[1]);
    return handleDeleteDevice(request, env, userId, deviceIdentifier);
  }

  const deviceTokenMatch = path.match(/^\/api\/devices\/identifier\/([^/]+)\/token$/i);
  if (deviceTokenMatch && (method === 'PUT' || method === 'POST')) {
    const deviceIdentifier = decodeURIComponent(deviceTokenMatch[1]);
    return handleUpdateDeviceToken(request, env, userId, deviceIdentifier);
  }

  return null;
}
