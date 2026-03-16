import {
  createAuthedFetch,
  deriveLoginHash,
  getProfile,
  getSetupStatus,
  getWebConfig,
  loadSession,
  loginWithPassword,
  refreshAccessToken,
  recoverTwoFactor,
  registerAccount,
  unlockVaultKey,
} from '@/lib/api/auth';
import type { AppPhase, Profile, SessionState } from '@/lib/types';

export interface PendingTotp {
  email: string;
  passwordHash: string;
  masterKey: Uint8Array;
}

export type JwtUnsafeReason = 'missing' | 'default' | 'too_short';

export interface BootstrapAppResult {
  setupRegistered: boolean;
  defaultKdfIterations: number;
  jwtWarning: { reason: JwtUnsafeReason; minLength: number } | null;
  session: SessionState | null;
  profile: Profile | null;
  phase: AppPhase;
}

export interface CompletedLogin {
  session: SessionState;
  profile: Profile;
}

export type PasswordLoginResult =
  | { kind: 'success'; login: CompletedLogin }
  | { kind: 'totp'; pendingTotp: PendingTotp }
  | { kind: 'error'; message: string };

export interface RecoverTwoFactorResult {
  login: CompletedLogin | null;
  newRecoveryCode: string | null;
}

function decodeJwtExp(accessToken: string): number | null {
  try {
    const parts = accessToken.split('.');
    if (parts.length < 2) return null;
    const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = payload.padEnd(Math.ceil(payload.length / 4) * 4, '=');
    const json = JSON.parse(atob(padded)) as { exp?: unknown };
    const exp = Number(json.exp);
    return Number.isFinite(exp) ? exp : null;
  } catch {
    return null;
  }
}

async function maybeRefreshSession(session: SessionState): Promise<SessionState | null> {
  if (!session.refreshToken) return session;
  const exp = decodeJwtExp(session.accessToken);
  const nowSeconds = Math.floor(Date.now() / 1000);

  if (exp !== null && exp - nowSeconds > 60) {
    return session;
  }

  const refreshed = await refreshAccessToken(session.refreshToken);
  if (!refreshed?.access_token) {
    return exp !== null && exp > nowSeconds ? session : null;
  }

  return {
    ...session,
    accessToken: refreshed.access_token,
    refreshToken: refreshed.refresh_token || session.refreshToken,
  };
}

export async function bootstrapAppSession(): Promise<BootstrapAppResult> {
  const [setup, config] = await Promise.all([getSetupStatus(), getWebConfig()]);
  const setupRegistered = setup.registered;
  const defaultKdfIterations = Number(config.defaultKdfIterations || 600000);
  const jwtUnsafeReason = config.jwtUnsafeReason || null;

  if (jwtUnsafeReason) {
    return {
      setupRegistered,
      defaultKdfIterations,
      jwtWarning: {
        reason: jwtUnsafeReason,
        minLength: Number(config.jwtSecretMinLength || 32),
      },
      session: null,
      profile: null,
      phase: 'login',
    };
  }

  const loaded = loadSession();
  if (!loaded) {
    return {
      setupRegistered,
      defaultKdfIterations,
      jwtWarning: null,
      session: null,
      profile: null,
      phase: setupRegistered ? 'login' : 'register',
    };
  }

  try {
    const session = await maybeRefreshSession(loaded);
    if (!session) {
      throw new Error('Session expired');
    }
    const profile = await getProfile(
      createAuthedFetch(
        () => session,
        () => {}
      )
    );
    return {
      setupRegistered,
      defaultKdfIterations,
      jwtWarning: null,
      session,
      profile,
      phase: 'locked',
    };
  } catch {
    return {
      setupRegistered,
      defaultKdfIterations,
      jwtWarning: null,
      session: null,
      profile: null,
      phase: setupRegistered ? 'login' : 'register',
    };
  }
}

export async function completeLogin(
  tokenAccess: string,
  tokenRefresh: string,
  email: string,
  masterKey: Uint8Array
): Promise<CompletedLogin> {
  const baseSession: SessionState = { accessToken: tokenAccess, refreshToken: tokenRefresh, email };
  const tempFetch = createAuthedFetch(
    () => baseSession,
    () => {}
  );
  const profile = await getProfile(tempFetch);
  const keys = await unlockVaultKey(profile.key, masterKey);
  return {
    session: { ...baseSession, ...keys },
    profile,
  };
}

export async function performPasswordLogin(
  email: string,
  password: string,
  fallbackIterations: number
): Promise<PasswordLoginResult> {
  const normalizedEmail = email.trim().toLowerCase();
  const derived = await deriveLoginHash(normalizedEmail, password, fallbackIterations);
  const token = await loginWithPassword(normalizedEmail, derived.hash, { useRememberToken: true });

  if ('access_token' in token && token.access_token) {
    return {
      kind: 'success',
      login: await completeLogin(token.access_token, token.refresh_token, normalizedEmail, derived.masterKey),
    };
  }

  const tokenError = token as { TwoFactorProviders?: unknown; error_description?: string; error?: string };
  if (tokenError.TwoFactorProviders) {
    return {
      kind: 'totp',
      pendingTotp: {
        email: normalizedEmail,
        passwordHash: derived.hash,
        masterKey: derived.masterKey,
      },
    };
  }

  return {
    kind: 'error',
    message: tokenError.error_description || tokenError.error || 'Login failed',
  };
}

export async function performTotpLogin(
  pendingTotp: PendingTotp,
  totpCode: string,
  rememberDevice: boolean
): Promise<CompletedLogin> {
  const token = await loginWithPassword(pendingTotp.email, pendingTotp.passwordHash, {
    totpCode: totpCode.trim(),
    rememberDevice,
  });
  if ('access_token' in token && token.access_token) {
    return completeLogin(token.access_token, token.refresh_token, pendingTotp.email, pendingTotp.masterKey);
  }
  const tokenError = token as { error_description?: string; error?: string };
  throw new Error(tokenError.error_description || tokenError.error || 'TOTP verify failed');
}

export async function performRecoverTwoFactorLogin(
  email: string,
  password: string,
  recoveryCode: string,
  fallbackIterations: number
): Promise<RecoverTwoFactorResult> {
  const normalizedEmail = email.trim().toLowerCase();
  const derived = await deriveLoginHash(normalizedEmail, password, fallbackIterations);
  const recovered = await recoverTwoFactor(normalizedEmail, derived.hash, recoveryCode.trim());
  const token = await loginWithPassword(normalizedEmail, derived.hash, { useRememberToken: false });

  if ('access_token' in token && token.access_token) {
    return {
      login: await completeLogin(token.access_token, token.refresh_token, normalizedEmail, derived.masterKey),
      newRecoveryCode: recovered.newRecoveryCode || null,
    };
  }

  return {
    login: null,
    newRecoveryCode: recovered.newRecoveryCode || null,
  };
}

export async function performRegistration(args: {
  email: string;
  name: string;
  password: string;
  inviteCode: string;
  fallbackIterations: number;
}) {
  return registerAccount({
    email: args.email.trim().toLowerCase(),
    name: args.name.trim(),
    password: args.password,
    inviteCode: args.inviteCode.trim(),
    fallbackIterations: args.fallbackIterations,
  });
}

export async function performUnlock(
  session: SessionState,
  profile: Profile,
  password: string,
  fallbackIterations: number
): Promise<SessionState> {
  const derived = await deriveLoginHash(profile.email || session.email, password, fallbackIterations);
  const keys = await unlockVaultKey(profile.key, derived.masterKey);
  const refreshedSession = await maybeRefreshSession(session);
  if (!refreshedSession) {
    throw new Error('Session expired');
  }
  return { ...refreshedSession, ...keys };
}
