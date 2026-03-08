import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { Link, Route, Switch, useLocation } from 'wouter';
import { useQuery } from '@tanstack/react-query';
import { ArrowUpDown, Cloud, Clock3, Folder, KeyRound, Lock, LogOut, Send as SendIcon, Settings as SettingsIcon, Shield, ShieldUser } from 'lucide-preact';
import AuthViews from '@/components/AuthViews';
import ConfirmDialog from '@/components/ConfirmDialog';
import ToastHost from '@/components/ToastHost';
import VaultPage from '@/components/VaultPage';
import SendsPage from '@/components/SendsPage';
import PublicSendPage from '@/components/PublicSendPage';
import RecoverTwoFactorPage from '@/components/RecoverTwoFactorPage';
import JwtWarningPage from '@/components/JwtWarningPage';
import SettingsPage from '@/components/SettingsPage';
import SecurityDevicesPage from '@/components/SecurityDevicesPage';
import AdminPage from '@/components/AdminPage';
import HelpPage from '@/components/HelpPage';
import ImportPage from '@/components/ImportPage';
import TotpCodesPage from '@/components/TotpCodesPage';
import type { ImportAttachmentFile, ImportResultSummary } from '@/components/ImportPage';
import {
  changeMasterPassword,
  createFolder,
  updateFolder,
  deleteCipherAttachment,
  deleteFolder,
  createCipher,
  createAuthedFetch,
  createInvite,
  downloadCipherAttachmentDecrypted,
  exportAdminBackup,
  importAdminBackup,
  importCiphers,
  createSend,
  deleteAllInvites,
  deleteCipher,
  deleteSend,
  deleteUser,
  deriveLoginHash,
  getAttachmentDownloadInfo,
  bulkMoveCiphers,
  getCiphers,
  getFolders,
  getPreloginKdfConfig,
  getProfile,
  getAuthorizedDevices,
  getCurrentDeviceIdentifier,
  getSetupStatus,
  getSends,
  getTotpStatus,
  getTotpRecoveryCode,
  getWebConfig,
  listAdminInvites,
  listAdminUsers,
  loadSession,
  loginWithPassword,
  registerAccount,
  recoverTwoFactor,
  revokeInvite,
  revokeAuthorizedDeviceTrust,
  revokeAllAuthorizedDeviceTrust,
  saveSession,
  setTotp,
  setUserStatus,
  deleteAllAuthorizedDevices,
  deleteAuthorizedDevice,
  uploadCipherAttachment,
  updateCipher,
  updateSend,
  buildSendShareKey,
  unlockVaultKey,
  verifyMasterPassword,
  type ImportedCipherMapEntry,
} from '@/lib/api';
import { base64ToBytes, decryptBw, decryptBwFileData, decryptStr, hkdf } from '@/lib/crypto';
import {
  attachNodeWardenEncryptedAttachmentPayload,
  buildAccountEncryptedBitwardenJsonString,
  buildBitwardenZipBytes,
  buildExportFileName,
  buildNodeWardenAttachmentRecords,
  buildNodeWardenPlainJsonDocument,
  buildPasswordProtectedBitwardenJsonString,
  buildPlainBitwardenJsonString,
  encryptZipBytesWithPassword,
  type ExportRequest,
  type ZipAttachmentEntry,
} from '@/lib/export-formats';
import { t } from '@/lib/i18n';
import type { CiphersImportPayload } from '@/lib/api';
import type { AppPhase, AuthorizedDevice, Cipher, Folder, Profile, Send, SendDraft, SessionState, ToastMessage, VaultDraft } from '@/lib/types';

interface PendingTotp {
  email: string;
  passwordHash: string;
  masterKey: Uint8Array;
}

type JwtUnsafeReason = 'missing' | 'default' | 'too_short';

const SEND_KEY_SALT = 'bitwarden-send';
const SEND_KEY_PURPOSE = 'send';
const IMPORT_ROUTE = '/help/import-export';
const IMPORT_ROUTE_ALIASES = new Set(['/tools/import', '/tools/import-export', '/tools/import-data', '/import', '/import-export']);
const SETTINGS_HOME_ROUTE = '/settings';
const SETTINGS_ACCOUNT_ROUTE = '/settings/account';

function looksLikeCipherString(value: string): boolean {
  return /^\d+\.[A-Za-z0-9+/=]+\|[A-Za-z0-9+/=]+(?:\|[A-Za-z0-9+/=]+)?$/.test(String(value || '').trim());
}

function asText(value: unknown): string {
  if (value === null || value === undefined) return '';
  return String(value);
}

function readInviteCodeFromUrl(): string {
  if (typeof window === 'undefined') return '';

  const searchInvite = new URLSearchParams(window.location.search || '').get('invite');
  if (searchInvite && searchInvite.trim()) return searchInvite.trim();

  const rawHash = String(window.location.hash || '');
  const queryIndex = rawHash.indexOf('?');
  if (queryIndex >= 0) {
    const hashInvite = new URLSearchParams(rawHash.slice(queryIndex + 1)).get('invite');
    if (hashInvite && hashInvite.trim()) return hashInvite.trim();
  }

  return '';
}

function summarizeImportResult(
  ciphers: Array<Record<string, unknown>>,
  folderCount: number,
  attachmentSummary?: {
    total: number;
    imported: number;
    failed: Array<{ fileName: string; reason: string }>;
  }
): ImportResultSummary {
  const typeLabel = (type: number): string => {
    if (type === 1) return t('txt_login');
    if (type === 2) return t('txt_secure_note');
    if (type === 3) return t('txt_card');
    if (type === 4) return t('txt_identity');
    if (type === 5) return t('txt_ssh_key');
    return t('txt_other');
  };
  const counter = new Map<number, number>();
  for (const raw of ciphers) {
    const cipherType = Number(raw?.type || 1) || 1;
    counter.set(cipherType, (counter.get(cipherType) || 0) + 1);
  }
  const order = [1, 2, 3, 4, 5];
  const seen = new Set<number>(order);
  const typeCounts = order
    .filter((type) => (counter.get(type) || 0) > 0)
    .map((type) => ({ label: typeLabel(type), count: counter.get(type) || 0 }));
  for (const [type, count] of counter.entries()) {
    if (!seen.has(type) && count > 0) typeCounts.push({ label: typeLabel(type), count });
  }
  return {
    totalItems: ciphers.length,
    folderCount: Math.max(0, folderCount),
    typeCounts,
    attachmentCount: Math.max(0, attachmentSummary?.total || 0),
    importedAttachmentCount: Math.max(0, attachmentSummary?.imported || 0),
    failedAttachments: attachmentSummary?.failed || [],
  };
}

function buildEmptyImportDraft(type: number): VaultDraft {
  return {
    type,
    favorite: false,
    name: '',
    folderId: '',
    notes: '',
    reprompt: false,
    loginUsername: '',
    loginPassword: '',
    loginTotp: '',
    loginUris: [''],
    loginFido2Credentials: [],
    cardholderName: '',
    cardNumber: '',
    cardBrand: '',
    cardExpMonth: '',
    cardExpYear: '',
    cardCode: '',
    identTitle: '',
    identFirstName: '',
    identMiddleName: '',
    identLastName: '',
    identUsername: '',
    identCompany: '',
    identSsn: '',
    identPassportNumber: '',
    identLicenseNumber: '',
    identEmail: '',
    identPhone: '',
    identAddress1: '',
    identAddress2: '',
    identAddress3: '',
    identCity: '',
    identState: '',
    identPostalCode: '',
    identCountry: '',
    sshPrivateKey: '',
    sshPublicKey: '',
    sshFingerprint: '',
    customFields: [],
  };
}

function importCipherToDraft(cipher: Record<string, unknown>, folderId: string | null): VaultDraft {
  const type = Number(cipher.type || 1) || 1;
  const draft = buildEmptyImportDraft(type);
  draft.name = asText(cipher.name).trim() || 'Untitled';
  draft.notes = asText(cipher.notes);
  draft.favorite = !!cipher.favorite;
  draft.reprompt = Number(cipher.reprompt || 0) === 1;
  draft.folderId = folderId || '';

  const customFieldsRaw = Array.isArray(cipher.fields) ? cipher.fields : [];
  draft.customFields = customFieldsRaw
    .map((raw) => {
      const field = (raw || {}) as Record<string, unknown>;
      const label = asText(field.name).trim();
      if (!label) return null;
      const parsedType = Number(field.type ?? 0);
      const fieldType = parsedType === 1 || parsedType === 2 || parsedType === 3 ? (parsedType as 1 | 2 | 3) : 0;
      return {
        type: fieldType,
        label,
        value: asText(field.value),
      };
    })
    .filter((x): x is VaultDraft['customFields'][number] => !!x);

  if (type === 1) {
    const login = (cipher.login || {}) as Record<string, unknown>;
    draft.loginUsername = asText(login.username);
    draft.loginPassword = asText(login.password);
    draft.loginTotp = asText(login.totp);
    draft.loginFido2Credentials = Array.isArray(login.fido2Credentials)
      ? login.fido2Credentials
          .filter((credential): credential is Record<string, unknown> => !!credential && typeof credential === 'object')
          .map((credential) => ({ ...credential }))
      : [];
    const urisRaw = Array.isArray(login.uris) ? login.uris : [];
    const uris = urisRaw
      .map((u) => asText((u as Record<string, unknown>)?.uri).trim())
      .filter((u) => !!u);
    draft.loginUris = uris.length ? uris : [''];
  } else if (type === 3) {
    const card = (cipher.card || {}) as Record<string, unknown>;
    draft.cardholderName = asText(card.cardholderName);
    draft.cardNumber = asText(card.number);
    draft.cardBrand = asText(card.brand);
    draft.cardExpMonth = asText(card.expMonth);
    draft.cardExpYear = asText(card.expYear);
    draft.cardCode = asText(card.code);
  } else if (type === 4) {
    const identity = (cipher.identity || {}) as Record<string, unknown>;
    draft.identTitle = asText(identity.title);
    draft.identFirstName = asText(identity.firstName);
    draft.identMiddleName = asText(identity.middleName);
    draft.identLastName = asText(identity.lastName);
    draft.identUsername = asText(identity.username);
    draft.identCompany = asText(identity.company);
    draft.identSsn = asText(identity.ssn);
    draft.identPassportNumber = asText(identity.passportNumber);
    draft.identLicenseNumber = asText(identity.licenseNumber);
    draft.identEmail = asText(identity.email);
    draft.identPhone = asText(identity.phone);
    draft.identAddress1 = asText(identity.address1);
    draft.identAddress2 = asText(identity.address2);
    draft.identAddress3 = asText(identity.address3);
    draft.identCity = asText(identity.city);
    draft.identState = asText(identity.state);
    draft.identPostalCode = asText(identity.postalCode);
    draft.identCountry = asText(identity.country);
  } else if (type === 5) {
    const sshKey = (cipher.sshKey || {}) as Record<string, unknown>;
    draft.sshPrivateKey = asText(sshKey.privateKey);
    draft.sshPublicKey = asText(sshKey.publicKey);
    draft.sshFingerprint = asText(sshKey.keyFingerprint ?? sshKey.fingerprint);
  }

  return draft;
}

function buildPublicSendUrl(origin: string, accessId: string, keyPart: string): string {
  return `${origin}/#/send/${accessId}/${keyPart}`;
}

async function deriveSendKeyParts(sendKeyMaterial: Uint8Array): Promise<{ enc: Uint8Array; mac: Uint8Array }> {
  if (sendKeyMaterial.length >= 64) {
    return { enc: sendKeyMaterial.slice(0, 32), mac: sendKeyMaterial.slice(32, 64) };
  }
  const derived = await hkdf(sendKeyMaterial, SEND_KEY_SALT, SEND_KEY_PURPOSE, 64);
  return { enc: derived.slice(0, 32), mac: derived.slice(32, 64) };
}

export default function App() {
  const [location, navigate] = useLocation();
  const [phase, setPhase] = useState<AppPhase>('loading');
  const [session, setSessionState] = useState<SessionState | null>(null);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [defaultKdfIterations, setDefaultKdfIterations] = useState(600000);
  const [setupRegistered, setSetupRegistered] = useState(true);
  const [jwtWarning, setJwtWarning] = useState<{ reason: JwtUnsafeReason; minLength: number } | null>(null);

  const [loginValues, setLoginValues] = useState({ email: '', password: '' });
  const [registerValues, setRegisterValues] = useState({
    name: '',
    email: '',
    password: '',
    password2: '',
    inviteCode: '',
  });
  const [inviteCodeFromUrl, setInviteCodeFromUrl] = useState('');
  const [unlockPassword, setUnlockPassword] = useState('');
  const [pendingTotp, setPendingTotp] = useState<PendingTotp | null>(null);
  const [totpCode, setTotpCode] = useState('');
  const [rememberDevice, setRememberDevice] = useState(true);

  const [disableTotpOpen, setDisableTotpOpen] = useState(false);
  const [disableTotpPassword, setDisableTotpPassword] = useState('');
  const [recoverValues, setRecoverValues] = useState({ email: '', password: '', recoveryCode: '' });

  const [confirm, setConfirm] = useState<{
    title: string;
    message: string;
    danger?: boolean;
    showIcon?: boolean;
    onConfirm: () => void;
  } | null>(null);

  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const [mobileLayout, setMobileLayout] = useState(false);
  const [decryptedFolders, setDecryptedFolders] = useState<Folder[]>([]);
  const [decryptedCiphers, setDecryptedCiphers] = useState<Cipher[]>([]);
  const [decryptedSends, setDecryptedSends] = useState<Send[]>([]);
  const migratedPlainFolderIdsRef = useRef<Set<string>>(new Set());

  useEffect(() => {
    const syncInviteFromUrl = () => {
      setInviteCodeFromUrl(readInviteCodeFromUrl());
    };
    syncInviteFromUrl();
    window.addEventListener('hashchange', syncInviteFromUrl);
    window.addEventListener('popstate', syncInviteFromUrl);
    return () => {
      window.removeEventListener('hashchange', syncInviteFromUrl);
      window.removeEventListener('popstate', syncInviteFromUrl);
    };
  }, []);

  useEffect(() => {
    if (!inviteCodeFromUrl) return;
    setRegisterValues((prev) => (prev.inviteCode === inviteCodeFromUrl ? prev : { ...prev, inviteCode: inviteCodeFromUrl }));
  }, [inviteCodeFromUrl]);

  useEffect(() => {
    if (!inviteCodeFromUrl) return;
    if (phase === 'loading' || phase === 'locked' || phase === 'app') return;
    setPhase('register');
    if (location !== '/register') navigate('/register');
    if (typeof window !== 'undefined' && typeof window.history?.replaceState === 'function') {
      window.history.replaceState(null, '', '/register');
    }
    setInviteCodeFromUrl('');
  }, [inviteCodeFromUrl, phase, location, navigate]);

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return;
    const media = window.matchMedia('(max-width: 900px)');
    const sync = () => setMobileLayout(media.matches);
    sync();
    if (typeof media.addEventListener === 'function') {
      media.addEventListener('change', sync);
      return () => media.removeEventListener('change', sync);
    }
    media.addListener(sync);
    return () => media.removeListener(sync);
  }, []);

  function setSession(next: SessionState | null) {
    setSessionState(next);
    saveSession(next);
  }

  function pushToast(type: ToastMessage['type'], text: string) {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    setToasts((prev) => [...prev.slice(-3), { id, type, text }]);
    window.setTimeout(() => {
      setToasts((prev) => prev.filter((x) => x.id !== id));
    }, 4500);
  }

  const authedFetch = useMemo(
    () =>
      createAuthedFetch(
        () => session,
        (next) => {
          setSession(next);
          if (!next) {
            setProfile(null);
            setPhase(setupRegistered ? 'login' : 'register');
          }
        }
      ),
    [session, setupRegistered]
  );

  useEffect(() => {
    let mounted = true;
    (async () => {
      const [setup, config] = await Promise.all([getSetupStatus(), getWebConfig()]);
      if (!mounted) return;
      setSetupRegistered(setup.registered);
      setDefaultKdfIterations(Number(config.defaultKdfIterations || 600000));
      const jwtUnsafeReason = config.jwtUnsafeReason || null;
      if (jwtUnsafeReason) {
        setJwtWarning({
          reason: jwtUnsafeReason,
          minLength: Number(config.jwtSecretMinLength || 32),
        });
        setSession(null);
        setProfile(null);
        setPhase('login');
        return;
      }
      setJwtWarning(null);

      const loaded = loadSession();
      if (!loaded) {
        setPhase(setup.registered ? 'login' : 'register');
        return;
      }
      setSession(loaded);

      try {
        const profileResp = await getProfile(
          createAuthedFetch(
            () => loaded,
            (next) => {
              if (!next) return;
              setSession(next);
            }
          )
        );
        if (!mounted) return;
        setProfile(profileResp);
        setPhase('locked');
      } catch {
        setSession(null);
        setPhase(setup.registered ? 'login' : 'register');
      }
    })();

    return () => {
      mounted = false;
    };
  }, []);

  async function finalizeLogin(tokenAccess: string, tokenRefresh: string, email: string, masterKey: Uint8Array) {
    const baseSession: SessionState = { accessToken: tokenAccess, refreshToken: tokenRefresh, email };
    const tempFetch = createAuthedFetch(
      () => baseSession,
      () => {}
    );
    const profileResp = await getProfile(tempFetch);
    const keys = await unlockVaultKey(profileResp.key, masterKey);
    const nextSession = { ...baseSession, ...keys };
    setSession(nextSession);
    setProfile(profileResp);
    setPendingTotp(null);
    setTotpCode('');
    setPhase('app');
    if (location === '/' || location === '/login' || location === '/register' || location === '/lock') {
      navigate('/vault');
    }
    pushToast('success', t('txt_login_success'));
  }

  async function handleLogin() {
    if (!loginValues.email || !loginValues.password) {
      pushToast('error', t('txt_please_input_email_and_password'));
      return;
    }
    try {
      const derived = await deriveLoginHash(loginValues.email, loginValues.password, defaultKdfIterations);
      const token = await loginWithPassword(loginValues.email, derived.hash, { useRememberToken: true });
      if ('access_token' in token && token.access_token) {
        await finalizeLogin(token.access_token, token.refresh_token, loginValues.email.toLowerCase(), derived.masterKey);
        return;
      }
      const tokenError = token as { TwoFactorProviders?: unknown; error_description?: string; error?: string };
      if (tokenError.TwoFactorProviders) {
        setPendingTotp({
          email: loginValues.email.toLowerCase(),
          passwordHash: derived.hash,
          masterKey: derived.masterKey,
        });
        setTotpCode('');
        setRememberDevice(true);
        return;
      }
      pushToast('error', tokenError.error_description || tokenError.error || t('txt_login_failed'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_login_failed'));
    }
  }

  async function handleTotpVerify() {
    if (!pendingTotp) return;
    if (!totpCode.trim()) {
      pushToast('error', t('txt_please_input_totp_code'));
      return;
    }
    const token = await loginWithPassword(pendingTotp.email, pendingTotp.passwordHash, {
      totpCode: totpCode.trim(),
      rememberDevice,
    });
    if ('access_token' in token && token.access_token) {
      await finalizeLogin(token.access_token, token.refresh_token, pendingTotp.email, pendingTotp.masterKey);
      return;
    }
    const tokenError = token as { error_description?: string; error?: string };
    pushToast('error', tokenError.error_description || tokenError.error || t('txt_totp_verify_failed'));
  }

  async function handleRecoverTwoFactorSubmit() {
    const email = recoverValues.email.trim().toLowerCase();
    const password = recoverValues.password;
    const recoveryCode = recoverValues.recoveryCode.trim();
    if (!email || !password || !recoveryCode) {
      pushToast('error', t('txt_email_password_and_recovery_code_are_required'));
      return;
    }
    try {
      const derived = await deriveLoginHash(email, password, defaultKdfIterations);
      const recovered = await recoverTwoFactor(email, derived.hash, recoveryCode);
      const token = await loginWithPassword(email, derived.hash, { useRememberToken: false });
      if ('access_token' in token && token.access_token) {
        await finalizeLogin(token.access_token, token.refresh_token, email, derived.masterKey);
        if (recovered.newRecoveryCode) {
          pushToast('success', t('txt_text_2fa_recovered_new_recovery_code_code', { code: recovered.newRecoveryCode }));
        } else {
          pushToast('success', t('txt_text_2fa_recovered'));
        }
        return;
      }
      pushToast('error', t('txt_recovered_but_auto_login_failed_please_sign_in'));
      navigate('/login');
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_recover_2fa_failed'));
    }
  }

  async function handleRegister() {
    if (!registerValues.email || !registerValues.password) {
      pushToast('error', t('txt_please_input_email_and_password'));
      return;
    }
    if (registerValues.password.length < 12) {
      pushToast('error', t('txt_master_password_must_be_at_least_12_chars'));
      return;
    }
    if (registerValues.password !== registerValues.password2) {
      pushToast('error', t('txt_passwords_do_not_match'));
      return;
    }
    const resp = await registerAccount({
      email: registerValues.email.toLowerCase(),
      name: registerValues.name.trim(),
      password: registerValues.password,
      inviteCode: registerValues.inviteCode.trim(),
      fallbackIterations: defaultKdfIterations,
    });
    if (!resp.ok) {
      pushToast('error', resp.message);
      return;
    }
    setLoginValues({ email: registerValues.email.toLowerCase(), password: '' });
    setPhase('login');
    navigate('/login');
    pushToast('success', t('txt_registration_succeeded_please_sign_in'));
  }

  async function handleUnlock() {
    if (!session || !profile) return;
    if (!unlockPassword) {
      pushToast('error', t('txt_please_input_master_password'));
      return;
    }
    try {
      const derived = await deriveLoginHash(profile.email || session.email, unlockPassword, defaultKdfIterations);
      const keys = await unlockVaultKey(profile.key, derived.masterKey);
      setSession({ ...session, ...keys });
      setUnlockPassword('');
      setPhase('app');
      if (location === '/' || location === '/lock') navigate('/vault');
      pushToast('success', t('txt_unlocked'));
    } catch {
      pushToast('error', t('txt_unlock_failed_master_password_is_incorrect'));
    }
  }

  function handleLock() {
    if (!session) return;
    const nextSession = { ...session };
    delete nextSession.symEncKey;
    delete nextSession.symMacKey;
    setSession(nextSession);
    setPhase('locked');
    navigate('/lock');
  }

  function logoutNow() {
    setConfirm(null);
    setSession(null);
    setProfile(null);
    setPendingTotp(null);
    setPhase(setupRegistered ? 'login' : 'register');
    navigate(setupRegistered ? '/login' : '/register');
  }

  function handleLogout() {
    setConfirm({
      title: t('txt_log_out'),
      message: t('txt_are_you_sure_you_want_to_log_out'),
      showIcon: false,
      onConfirm: () => {
        logoutNow();
      },
    });
  }

  const ciphersQuery = useQuery({
    queryKey: ['ciphers', session?.accessToken],
    queryFn: () => getCiphers(authedFetch),
    enabled: phase === 'app' && !!session?.symEncKey && !!session?.symMacKey,
  });
  const foldersQuery = useQuery({
    queryKey: ['folders', session?.accessToken],
    queryFn: () => getFolders(authedFetch),
    enabled: phase === 'app' && !!session?.symEncKey && !!session?.symMacKey,
  });
  const sendsQuery = useQuery({
    queryKey: ['sends', session?.accessToken],
    queryFn: () => getSends(authedFetch),
    enabled: phase === 'app' && !!session?.symEncKey && !!session?.symMacKey,
  });
  const usersQuery = useQuery({
    queryKey: ['admin-users', session?.accessToken],
    queryFn: () => listAdminUsers(authedFetch),
    enabled: phase === 'app' && profile?.role === 'admin',
  });
  const invitesQuery = useQuery({
    queryKey: ['admin-invites', session?.accessToken],
    queryFn: () => listAdminInvites(authedFetch),
    enabled: phase === 'app' && profile?.role === 'admin',
  });
  const totpStatusQuery = useQuery({
    queryKey: ['totp-status', session?.accessToken],
    queryFn: () => getTotpStatus(authedFetch),
    enabled: phase === 'app' && !!session?.accessToken,
  });
  const authorizedDevicesQuery = useQuery({
    queryKey: ['authorized-devices', session?.accessToken],
    queryFn: () => getAuthorizedDevices(authedFetch),
    enabled: phase === 'app' && !!session?.accessToken,
  });

  useEffect(() => {
    if (!session?.symEncKey || !session?.symMacKey) {
      setDecryptedFolders([]);
      setDecryptedCiphers([]);
      setDecryptedSends([]);
      return;
    }
    if (!foldersQuery.data || !ciphersQuery.data || !sendsQuery.data) return;

    let active = true;
    (async () => {
      try {
        const encKey = base64ToBytes(session.symEncKey!);
        const macKey = base64ToBytes(session.symMacKey!);
        const decryptField = async (
          value: string | null | undefined,
          fieldEnc: Uint8Array = encKey,
          fieldMac: Uint8Array = macKey
        ): Promise<string> => {
          if (!value || typeof value !== 'string') return '';
          try {
            return await decryptStr(value, fieldEnc, fieldMac);
          } catch {
            // Backward-compatibility: some records may already be plain text.
            return value;
          }
        };

        const folders = await Promise.all(
          foldersQuery.data.map(async (folder) => ({
            ...folder,
            decName: await decryptField(folder.name, encKey, macKey),
          }))
        );

        const ciphers = await Promise.all(
          ciphersQuery.data.map(async (cipher) => {
            let itemEnc = encKey;
            let itemMac = macKey;
            if (cipher.key) {
              try {
                const itemKey = await decryptBw(cipher.key, encKey, macKey);
                itemEnc = itemKey.slice(0, 32);
                itemMac = itemKey.slice(32, 64);
              } catch {
                // keep user key when item key decrypt fails
              }
            }

            const nextCipher: Cipher = {
              ...cipher,
              decName: await decryptField(cipher.name || '', itemEnc, itemMac),
              decNotes: await decryptField(cipher.notes || '', itemEnc, itemMac),
            };
            if (cipher.login) {
              nextCipher.login = {
                ...cipher.login,
                decUsername: await decryptField(cipher.login.username || '', itemEnc, itemMac),
                decPassword: await decryptField(cipher.login.password || '', itemEnc, itemMac),
                decTotp: await decryptField(cipher.login.totp || '', itemEnc, itemMac),
                fido2Credentials: Array.isArray(cipher.login.fido2Credentials)
                  ? cipher.login.fido2Credentials.map((credential) => ({ ...credential }))
                  : null,
                uris: await Promise.all(
                  (cipher.login.uris || []).map(async (u) => ({
                    ...u,
                    decUri: await decryptField(u.uri || '', itemEnc, itemMac),
                  }))
                ),
              };
            }
            if (cipher.card) {
              nextCipher.card = {
                ...cipher.card,
                decCardholderName: await decryptField(cipher.card.cardholderName || '', itemEnc, itemMac),
                decNumber: await decryptField(cipher.card.number || '', itemEnc, itemMac),
                decBrand: await decryptField(cipher.card.brand || '', itemEnc, itemMac),
                decExpMonth: await decryptField(cipher.card.expMonth || '', itemEnc, itemMac),
                decExpYear: await decryptField(cipher.card.expYear || '', itemEnc, itemMac),
                decCode: await decryptField(cipher.card.code || '', itemEnc, itemMac),
              };
            }
            if (cipher.identity) {
              nextCipher.identity = {
                ...cipher.identity,
                decTitle: await decryptField(cipher.identity.title || '', itemEnc, itemMac),
                decFirstName: await decryptField(cipher.identity.firstName || '', itemEnc, itemMac),
                decMiddleName: await decryptField(cipher.identity.middleName || '', itemEnc, itemMac),
                decLastName: await decryptField(cipher.identity.lastName || '', itemEnc, itemMac),
                decUsername: await decryptField(cipher.identity.username || '', itemEnc, itemMac),
                decCompany: await decryptField(cipher.identity.company || '', itemEnc, itemMac),
                decSsn: await decryptField(cipher.identity.ssn || '', itemEnc, itemMac),
                decPassportNumber: await decryptField(cipher.identity.passportNumber || '', itemEnc, itemMac),
                decLicenseNumber: await decryptField(cipher.identity.licenseNumber || '', itemEnc, itemMac),
                decEmail: await decryptField(cipher.identity.email || '', itemEnc, itemMac),
                decPhone: await decryptField(cipher.identity.phone || '', itemEnc, itemMac),
                decAddress1: await decryptField(cipher.identity.address1 || '', itemEnc, itemMac),
                decAddress2: await decryptField(cipher.identity.address2 || '', itemEnc, itemMac),
                decAddress3: await decryptField(cipher.identity.address3 || '', itemEnc, itemMac),
                decCity: await decryptField(cipher.identity.city || '', itemEnc, itemMac),
                decState: await decryptField(cipher.identity.state || '', itemEnc, itemMac),
                decPostalCode: await decryptField(cipher.identity.postalCode || '', itemEnc, itemMac),
                decCountry: await decryptField(cipher.identity.country || '', itemEnc, itemMac),
              };
            }
            if (cipher.sshKey) {
              const encryptedFingerprint = cipher.sshKey.keyFingerprint || cipher.sshKey.fingerprint || '';
              nextCipher.sshKey = {
                ...cipher.sshKey,
                decPrivateKey: await decryptField(cipher.sshKey.privateKey || '', itemEnc, itemMac),
                decPublicKey: await decryptField(cipher.sshKey.publicKey || '', itemEnc, itemMac),
                keyFingerprint: encryptedFingerprint || null,
                fingerprint: encryptedFingerprint || null,
                decFingerprint: await decryptField(encryptedFingerprint, itemEnc, itemMac),
              };
            }
            if (cipher.fields) {
              nextCipher.fields = await Promise.all(
                cipher.fields.map(async (field) => ({
                  ...field,
                  decName: await decryptField(field.name || '', itemEnc, itemMac),
                  decValue: await decryptField(field.value || '', itemEnc, itemMac),
                }))
              );
            }
            if (Array.isArray(cipher.attachments)) {
              nextCipher.attachments = await Promise.all(
                cipher.attachments.map(async (attachment) => ({
                  ...attachment,
                  decFileName: await decryptField(attachment.fileName || '', itemEnc, itemMac),
                }))
              );
            }
            return nextCipher;
          })
        );

        const sends = await Promise.all(
          sendsQuery.data.map(async (send) => {
            const nextSend: Send = { ...send };
            try {
              if (send.key) {
                const sendKeyRaw = await decryptBw(send.key, encKey, macKey);
                const derived = await deriveSendKeyParts(sendKeyRaw);
                nextSend.decName = await decryptField(send.name || '', derived.enc, derived.mac);
                nextSend.decNotes = await decryptField(send.notes || '', derived.enc, derived.mac);
                nextSend.decText = await decryptField(send.text?.text || '', derived.enc, derived.mac);
                if (send.file?.fileName) {
                  const decFileName = await decryptField(send.file.fileName, derived.enc, derived.mac);
                  nextSend.file = {
                    ...(send.file || {}),
                    fileName: decFileName || send.file.fileName,
                  };
                }
                const shareKey = await buildSendShareKey(send.key, session.symEncKey!, session.symMacKey!);
                nextSend.decShareKey = shareKey;
                nextSend.shareUrl = buildPublicSendUrl(window.location.origin, send.accessId, shareKey);
              } else {
                nextSend.decName = '';
                nextSend.decNotes = '';
                nextSend.decText = '';
              }
            } catch {
              nextSend.decName = t('txt_decrypt_failed');
            }
            return nextSend;
          })
        );

        if (!active) return;
        setDecryptedFolders(folders);
        setDecryptedCiphers(ciphers);
        setDecryptedSends(sends);
      } catch (error) {
        if (!active) return;
        pushToast('error', error instanceof Error ? error.message : t('txt_decrypt_failed_2'));
      }
    })();

    return () => {
      active = false;
    };
  }, [session?.symEncKey, session?.symMacKey, foldersQuery.data, ciphersQuery.data, sendsQuery.data]);

  useEffect(() => {
    if (!session?.symEncKey || !session?.symMacKey || !foldersQuery.data?.length) return;
    let cancelled = false;
    (async () => {
      const pending = foldersQuery.data.filter((folder) => {
        if (!folder?.id || !folder?.name) return false;
        if (migratedPlainFolderIdsRef.current.has(folder.id)) return false;
        return !looksLikeCipherString(String(folder.name));
      });
      if (!pending.length) return;
      for (const folder of pending) {
        try {
          await updateFolder(authedFetch, session, folder.id, String(folder.name));
          migratedPlainFolderIdsRef.current.add(folder.id);
        } catch {
          // keep silent; web still supports plaintext fallback display
        }
      }
      if (!cancelled) await foldersQuery.refetch();
    })();
    return () => {
      cancelled = true;
    };
  }, [session?.symEncKey, session?.symMacKey, foldersQuery.data, authedFetch]);

  async function changePasswordAction(currentPassword: string, nextPassword: string, nextPassword2: string) {
    if (!profile) return;
    if (!currentPassword || !nextPassword) {
      pushToast('error', t('txt_current_new_password_is_required'));
      return;
    }
    if (nextPassword.length < 12) {
      pushToast('error', t('txt_new_password_must_be_at_least_12_chars'));
      return;
    }
    if (nextPassword !== nextPassword2) {
      pushToast('error', t('txt_new_passwords_do_not_match'));
      return;
    }
    try {
      await changeMasterPassword(authedFetch, {
        email: profile.email,
        currentPassword,
        newPassword: nextPassword,
        currentIterations: defaultKdfIterations,
        profileKey: profile.key,
      });
      handleLogout();
      pushToast('success', t('txt_master_password_changed_please_login_again'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_change_password_failed'));
    }
  }

  async function enableTotpAction(secret: string, token: string) {
    if (!secret.trim() || !token.trim()) {
      const error = new Error(t('txt_secret_and_code_are_required'));
      pushToast('error', error.message);
      throw error;
    }
    try {
      await setTotp(authedFetch, { enabled: true, secret: secret.trim(), token: token.trim() });
      pushToast('success', t('txt_totp_enabled'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_enable_totp_failed'));
      throw error;
    }
  }

  async function disableTotpAction() {
    if (!profile) return;
    if (!disableTotpPassword) {
      pushToast('error', t('txt_please_input_master_password'));
      return;
    }
    try {
      const derived = await deriveLoginHash(profile.email, disableTotpPassword, defaultKdfIterations);
      await setTotp(authedFetch, { enabled: false, masterPasswordHash: derived.hash });
      if (profile?.id) localStorage.removeItem(`nodewarden.totp.secret.${profile.id}`);
      setDisableTotpOpen(false);
      setDisableTotpPassword('');
      await totpStatusQuery.refetch();
      pushToast('success', t('txt_totp_disabled'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_disable_totp_failed'));
    }
  }

  async function refreshVault() {
    await Promise.all([ciphersQuery.refetch(), foldersQuery.refetch(), sendsQuery.refetch()]);
    pushToast('success', t('txt_vault_synced'));
  }

  async function refreshAuthorizedDevices() {
    await authorizedDevicesQuery.refetch();
  }

  async function revokeDeviceTrustAction(device: AuthorizedDevice) {
    await revokeAuthorizedDeviceTrust(authedFetch, device.identifier);
    await authorizedDevicesQuery.refetch();
    pushToast('success', t('txt_device_authorization_revoked'));
  }

  async function revokeAllDeviceTrustAction() {
    await revokeAllAuthorizedDeviceTrust(authedFetch);
    await authorizedDevicesQuery.refetch();
    pushToast('success', t('txt_all_device_authorizations_revoked'));
  }

  async function removeDeviceAction(device: AuthorizedDevice) {
    await deleteAuthorizedDevice(authedFetch, device.identifier);
    if (device.identifier === getCurrentDeviceIdentifier()) {
      pushToast('success', t('txt_device_removed'));
      logoutNow();
      return;
    }
    await authorizedDevicesQuery.refetch();
    pushToast('success', t('txt_device_removed'));
  }

  async function removeAllDevicesAction() {
    await deleteAllAuthorizedDevices(authedFetch);
    pushToast('success', t('txt_all_devices_removed'));
    logoutNow();
  }

  async function createVaultItem(draft: VaultDraft, attachments: File[] = []) {
    if (!session) return;
    try {
      const created = await createCipher(authedFetch, session, draft);
      for (const file of attachments) {
        await uploadCipherAttachment(authedFetch, session, created.id, file);
      }
      await Promise.all([ciphersQuery.refetch(), foldersQuery.refetch()]);
      pushToast('success', t('txt_item_created'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_create_item_failed'));
      throw error;
    }
  }

  async function updateVaultItem(
    cipher: Cipher,
    draft: VaultDraft,
    options?: { addFiles?: File[]; removeAttachmentIds?: string[] }
  ) {
    if (!session) return;
    const addFiles = Array.isArray(options?.addFiles) ? options.addFiles : [];
    const removeAttachmentIds = Array.isArray(options?.removeAttachmentIds) ? options.removeAttachmentIds : [];
    try {
      await updateCipher(authedFetch, session, cipher, draft);
      for (const attachmentId of removeAttachmentIds) {
        const id = String(attachmentId || '').trim();
        if (!id) continue;
        await deleteCipherAttachment(authedFetch, cipher.id, id);
      }
      for (const file of addFiles) {
        await uploadCipherAttachment(authedFetch, session, cipher.id, file, cipher);
      }
      await Promise.all([ciphersQuery.refetch(), foldersQuery.refetch()]);
      pushToast('success', t('txt_item_updated'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_update_item_failed'));
      throw error;
    }
  }

  async function downloadVaultAttachment(cipher: Cipher, attachmentId: string) {
    if (!session) return;
    try {
      const file = await downloadCipherAttachmentDecrypted(authedFetch, session, cipher, attachmentId);
      const fileName = String(file.fileName || '').trim() || 'attachment.bin';
      const payload = new ArrayBuffer(file.bytes.byteLength);
      new Uint8Array(payload).set(file.bytes);
      const blob = new Blob([payload], { type: 'application/octet-stream' });
      const href = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = href;
      anchor.download = fileName;
      anchor.rel = 'noopener';
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(href);
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_download_failed'));
      throw error;
    }
  }

  async function deleteVaultItem(cipher: Cipher) {
    try {
      await deleteCipher(authedFetch, cipher.id);
      await Promise.all([ciphersQuery.refetch(), foldersQuery.refetch()]);
      pushToast('success', t('txt_item_deleted'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_delete_item_failed'));
      throw error;
    }
  }

  async function bulkDeleteVaultItems(ids: string[]) {
    try {
      for (const id of ids) {
        await deleteCipher(authedFetch, id);
      }
      await Promise.all([ciphersQuery.refetch(), foldersQuery.refetch()]);
      pushToast('success', t('txt_deleted_selected_items'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_bulk_delete_failed'));
      throw error;
    }
  }

  async function bulkMoveVaultItems(ids: string[], folderId: string | null) {
    try {
      await bulkMoveCiphers(authedFetch, ids, folderId);
      await Promise.all([ciphersQuery.refetch(), foldersQuery.refetch()]);
      pushToast('success', t('txt_moved_selected_items'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_bulk_move_failed'));
      throw error;
    }
  }

  async function getRecoveryCodeAction(masterPassword: string): Promise<string> {
    if (!profile) throw new Error(t('txt_profile_unavailable'));
    const normalized = String(masterPassword || '');
    if (!normalized) throw new Error(t('txt_master_password_is_required'));
    const derived = await deriveLoginHash(profile.email, normalized, defaultKdfIterations);
    const code = await getTotpRecoveryCode(authedFetch, derived.hash);
    if (!code) throw new Error(t('txt_recovery_code_is_empty'));
    return code;
  }

  async function createSendItem(draft: SendDraft, autoCopyLink: boolean) {
    if (!session) return;
    try {
      const created = await createSend(authedFetch, session, draft);
      await sendsQuery.refetch();
      if (autoCopyLink && created.key && session.symEncKey && session.symMacKey) {
        const keyPart = await buildSendShareKey(created.key, session.symEncKey, session.symMacKey);
        const shareUrl = buildPublicSendUrl(window.location.origin, created.accessId, keyPart);
        await navigator.clipboard.writeText(shareUrl);
      }
      pushToast('success', t('txt_send_created'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_create_send_failed'));
      throw error;
    }
  }

  async function updateSendItem(send: Send, draft: SendDraft, autoCopyLink: boolean) {
    if (!session) return;
    try {
      const updated = await updateSend(authedFetch, session, send, draft);
      await sendsQuery.refetch();
      if (autoCopyLink && updated.key && session.symEncKey && session.symMacKey) {
        const keyPart = await buildSendShareKey(updated.key, session.symEncKey, session.symMacKey);
        const shareUrl = buildPublicSendUrl(window.location.origin, updated.accessId, keyPart);
        await navigator.clipboard.writeText(shareUrl);
      }
      pushToast('success', t('txt_send_updated'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_update_send_failed'));
      throw error;
    }
  }

  async function deleteSendItem(send: Send) {
    try {
      await deleteSend(authedFetch, send.id);
      await sendsQuery.refetch();
      pushToast('success', t('txt_send_deleted'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_delete_send_failed'));
      throw error;
    }
  }

  async function bulkDeleteSendItems(ids: string[]) {
    try {
      for (const id of ids) {
        await deleteSend(authedFetch, id);
      }
      await sendsQuery.refetch();
      pushToast('success', t('txt_deleted_selected_sends'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_bulk_delete_sends_failed'));
      throw error;
    }
  }

  async function verifyMasterPasswordAction(email: string, password: string) {
    const derived = await deriveLoginHash(email, password, defaultKdfIterations);
    await verifyMasterPassword(authedFetch, derived.hash);
  }

  async function createFolderAction(name: string) {
    const folderName = name.trim();
    if (!folderName) {
      pushToast('error', t('txt_folder_name_is_required'));
      return;
    }
    try {
      if (!session) throw new Error(t('txt_vault_key_unavailable'));
      await createFolder(authedFetch, session, folderName);
      await foldersQuery.refetch();
      pushToast('success', t('txt_folder_created'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_create_folder_failed'));
      throw error;
    }
  }

  async function deleteFolderAction(folderId: string) {
    const id = String(folderId || '').trim();
    if (!id) {
      pushToast('error', t('txt_folder_not_found'));
      return;
    }
    try {
      await deleteFolder(authedFetch, id);
      await Promise.all([ciphersQuery.refetch(), foldersQuery.refetch()]);
      pushToast('success', t('txt_folder_deleted'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_delete_folder_failed'));
      throw error;
    }
  }

  function buildImportedCipherMaps(
    payloadCiphers: Array<Record<string, unknown>>,
    createdCipherIdsByIndex: Map<number, string>
  ): { byIndex: Map<number, string>; bySourceId: Map<string, string> } {
    const byIndex = new Map<number, string>(createdCipherIdsByIndex);
    const bySourceId = new Map<string, string>();
    for (const [index, id] of createdCipherIdsByIndex.entries()) {
      const raw = (payloadCiphers[index] || {}) as Record<string, unknown>;
      const sourceId = String(raw.id || '').trim();
      if (sourceId) bySourceId.set(sourceId, id);
    }
    return { byIndex, bySourceId };
  }

  async function uploadImportedAttachments(
    attachments: ImportAttachmentFile[],
    idMaps: { byIndex: Map<number, string>; bySourceId: Map<string, string> }
  ): Promise<{ total: number; imported: number; failed: Array<{ fileName: string; reason: string }> }> {
    if (!attachments.length) {
      return { total: 0, imported: 0, failed: [] };
    }
    if (!session?.symEncKey || !session?.symMacKey) throw new Error(t('txt_vault_key_unavailable'));

    const initialCiphers = (await ciphersQuery.refetch()).data || [];
    const cipherById = new Map(initialCiphers.map((cipher) => [String(cipher.id || ''), cipher]));
    const failed: Array<{ fileName: string; reason: string }> = [];
    let imported = 0;

    for (const attachment of attachments) {
      const sourceId = String(attachment.sourceCipherId || '').trim();
      const sourceIndex = Number(attachment.sourceCipherIndex);
      const byId = sourceId ? idMaps.bySourceId.get(sourceId) : null;
      const byIndex = Number.isFinite(sourceIndex) ? idMaps.byIndex.get(sourceIndex) : null;
      const targetCipherId = byId || byIndex || null;
      if (!targetCipherId) {
        failed.push({
          fileName: String(attachment.fileName || '').trim() || 'attachment.bin',
          reason: t('txt_import_attachment_target_not_found'),
        });
        continue;
      }

      const name = String(attachment.fileName || '').trim() || 'attachment.bin';
      const fileBytes = Uint8Array.from(attachment.bytes);
      const file = new File([fileBytes], name, { type: 'application/octet-stream' });
      const cipher = cipherById.get(targetCipherId) || null;
      try {
        await uploadCipherAttachment(authedFetch, session, targetCipherId, file, cipher);
        imported += 1;
      } catch (error) {
        failed.push({
          fileName: name,
          reason: error instanceof Error ? error.message : t('txt_upload_attachment_failed'),
        });
      }
    }

    await ciphersQuery.refetch();
    return {
      total: attachments.length,
      imported,
      failed,
    };
  }

  function toImportedCipherMapsFromResponse(
    cipherMap: ImportedCipherMapEntry[] | null
  ): { byIndex: Map<number, string>; bySourceId: Map<string, string> } {
    const byIndex = new Map<number, string>();
    const bySourceId = new Map<string, string>();
    for (const row of cipherMap || []) {
      const idx = Number(row?.index);
      const id = String(row?.id || '').trim();
      if (!Number.isFinite(idx) || !id) continue;
      byIndex.set(idx, id);
      const sourceId = String(row?.sourceId || '').trim();
      if (sourceId) bySourceId.set(sourceId, id);
    }
    return { byIndex, bySourceId };
  }

  async function handleImportAction(
    payload: CiphersImportPayload,
    options: { folderMode: 'original' | 'none' | 'target'; targetFolderId: string | null },
    attachments: ImportAttachmentFile[] = []
  ): Promise<ImportResultSummary> {
    if (!session?.symEncKey || !session?.symMacKey) throw new Error(t('txt_vault_key_unavailable'));

    const mode = options.folderMode || 'original';
    const targetFolderId = (options.targetFolderId || '').trim() || null;
    const folderIdByCipherIndex = new Map<number, string>();
    let createdFolderCount = 0;
    if (mode === 'original') {
      const folderIdByImportIndex = new Map<number, string>();
      const folderIdByLegacyId = new Map<string, string>();
      const folderIdByName = new Map<string, string>();
      const createdFolderIdByName = new Map<string, string>();
      for (let i = 0; i < payload.folders.length; i++) {
        const folderRaw = (payload.folders[i] || {}) as Record<string, unknown>;
        const name = String(folderRaw.name || '').trim();
        if (!name) continue;
        let folderId = createdFolderIdByName.get(name) || null;
        if (!folderId) {
          const created = await createFolder(authedFetch, session, name);
          folderId = created.id;
          createdFolderIdByName.set(name, folderId);
          createdFolderCount += 1;
        }
        folderIdByImportIndex.set(i, folderId);
        folderIdByName.set(name, folderId);
        const legacyId = String(folderRaw.id || '').trim();
        if (legacyId) folderIdByLegacyId.set(legacyId, folderId);
      }
      for (const relation of payload.folderRelationships || []) {
        const cipherIndex = Number(relation?.key);
        const folderIndex = Number(relation?.value);
        if (!Number.isFinite(cipherIndex) || !Number.isFinite(folderIndex)) continue;
        const folderId = folderIdByImportIndex.get(folderIndex);
        if (folderId) folderIdByCipherIndex.set(cipherIndex, folderId);
      }
      for (let i = 0; i < payload.ciphers.length; i++) {
        if (folderIdByCipherIndex.has(i)) continue;
        const raw = (payload.ciphers[i] || {}) as Record<string, unknown>;
        const rawFolderId = String(raw.folderId || '').trim();
        if (rawFolderId && folderIdByLegacyId.has(rawFolderId)) {
          folderIdByCipherIndex.set(i, folderIdByLegacyId.get(rawFolderId)!);
          continue;
        }
        const rawFolderName = String(raw.folder || '').trim();
        if (rawFolderName && folderIdByName.has(rawFolderName)) {
          folderIdByCipherIndex.set(i, folderIdByName.get(rawFolderName)!);
        }
      }
    } else if (mode === 'target' && targetFolderId) {
      for (let i = 0; i < payload.ciphers.length; i++) {
        folderIdByCipherIndex.set(i, targetFolderId);
      }
    }

    const createdCipherIdsByIndex = new Map<number, string>();
    for (let i = 0; i < payload.ciphers.length; i++) {
      const raw = (payload.ciphers[i] || {}) as Record<string, unknown>;
      const draft = importCipherToDraft(raw, null);
      const created = await createCipher(authedFetch, session, draft);
      createdCipherIdsByIndex.set(i, created.id);
    }

    const moveIdsByFolderId = new Map<string, string[]>();
    for (const [index, folderId] of folderIdByCipherIndex.entries()) {
      const cipherId = createdCipherIdsByIndex.get(index);
      if (!cipherId || !folderId) continue;
      const group = moveIdsByFolderId.get(folderId) || [];
      group.push(cipherId);
      moveIdsByFolderId.set(folderId, group);
    }
    for (const [folderId, ids] of moveIdsByFolderId.entries()) {
      await bulkMoveCiphers(authedFetch, ids, folderId);
    }

    const idMaps = buildImportedCipherMaps(payload.ciphers, createdCipherIdsByIndex);
    await foldersQuery.refetch();
    await ciphersQuery.refetch();
    const attachmentSummary = attachments.length
      ? await uploadImportedAttachments(attachments, idMaps)
      : undefined;
    return summarizeImportResult(payload.ciphers, mode === 'original' ? createdFolderCount : 0, attachmentSummary);
  }

  async function handleImportEncryptedRawAction(
    payload: CiphersImportPayload,
    options: { folderMode: 'original' | 'none' | 'target'; targetFolderId: string | null },
    attachments: ImportAttachmentFile[] = []
  ): Promise<ImportResultSummary> {
    const mode = options.folderMode || 'original';
    const targetFolderId = (options.targetFolderId || '').trim() || null;
    const nextPayload: CiphersImportPayload = {
      ciphers: payload.ciphers.map((raw) => ({ ...(raw as Record<string, unknown>) })),
      folders: mode === 'original' ? payload.folders : [],
      folderRelationships: mode === 'original' ? payload.folderRelationships : [],
    };
    if (mode === 'none') {
      for (const raw of nextPayload.ciphers) (raw as Record<string, unknown>).folderId = null;
    } else if (mode === 'target' && targetFolderId) {
      for (const raw of nextPayload.ciphers) (raw as Record<string, unknown>).folderId = targetFolderId;
    }

    const importedCipherMap = await importCiphers(authedFetch, nextPayload, {
      returnCipherMap: attachments.length > 0,
    });
    await Promise.all([ciphersQuery.refetch(), foldersQuery.refetch()]);
    const attachmentSummary = attachments.length
      ? await uploadImportedAttachments(attachments, toImportedCipherMapsFromResponse(importedCipherMap))
      : undefined;
    return summarizeImportResult(
      nextPayload.ciphers,
      mode === 'original' ? nextPayload.folders.length : 0,
      attachmentSummary
    );
  }

  async function handleExportAction(request: ExportRequest) {
    if (!session?.symEncKey || !session?.symMacKey) throw new Error(t('txt_vault_key_unavailable'));
    const masterPassword = String(request.masterPassword || '').trim();
    if (!masterPassword) throw new Error(t('txt_master_password_is_required'));
    const email = String(profile?.email || session.email || '').trim().toLowerCase();
    if (!email) throw new Error(t('txt_profile_unavailable'));
    const verifyDerived = await deriveLoginHash(email, masterPassword, defaultKdfIterations);
    await verifyMasterPassword(authedFetch, verifyDerived.hash);

    const rawFolders = foldersQuery.data || [];
    const rawCiphers = ciphersQuery.data || [];
    if (!rawFolders || !rawCiphers) throw new Error(t('txt_vault_not_ready'));

    let plainJsonCache: string | null = null;
    let plainJsonDocCache: Record<string, unknown> | null = null;
    let encryptedJsonCache: string | null = null;
    let nodeWardenAttachmentsCache: ReturnType<typeof buildNodeWardenAttachmentRecords> | null = null;
    const getPlainJson = async () => {
      if (!plainJsonCache) {
        plainJsonCache = await buildPlainBitwardenJsonString({
          folders: rawFolders,
          ciphers: rawCiphers,
          userEncB64: session.symEncKey!,
          userMacB64: session.symMacKey!,
        });
      }
      return plainJsonCache;
    };
    const getPlainJsonDoc = async () => {
      if (!plainJsonDocCache) {
        plainJsonDocCache = JSON.parse(await getPlainJson()) as Record<string, unknown>;
      }
      return plainJsonDocCache;
    };
    const getEncryptedJson = async () => {
      if (!encryptedJsonCache) {
        encryptedJsonCache = await buildAccountEncryptedBitwardenJsonString({
          folders: rawFolders,
          ciphers: rawCiphers,
          userEncB64: session.symEncKey!,
          userMacB64: session.symMacKey!,
        });
      }
      return encryptedJsonCache;
    };

    const zipAttachments = async (): Promise<ZipAttachmentEntry[]> => {
      const userEnc = base64ToBytes(session.symEncKey!);
      const userMac = base64ToBytes(session.symMacKey!);
      const out: ZipAttachmentEntry[] = [];
      const activeCiphers = rawCiphers.filter((cipher) => !cipher.deletedDate && !(cipher as { organizationId?: unknown }).organizationId);

      for (const cipher of activeCiphers) {
        const cipherId = String(cipher.id || '').trim();
        if (!cipherId) continue;
        const attachments = Array.isArray(cipher.attachments) ? cipher.attachments : [];
        if (!attachments.length) continue;

        let itemEnc = userEnc;
        let itemMac = userMac;
        const itemKey = String(cipher.key || '').trim();
        if (itemKey && looksLikeCipherString(itemKey)) {
          try {
            const rawItemKey = await decryptBw(itemKey, userEnc, userMac);
            if (rawItemKey.length >= 64) {
              itemEnc = rawItemKey.slice(0, 32);
              itemMac = rawItemKey.slice(32, 64);
            }
          } catch {
            // fallback to user key
          }
        }

        for (const attachment of attachments) {
          const attachmentId = String(attachment?.id || '').trim();
          if (!attachmentId) continue;
          const info = await getAttachmentDownloadInfo(authedFetch, cipherId, attachmentId);
          const fileResp = await fetch(info.url, { cache: 'no-store' });
          if (!fileResp.ok) throw new Error(`Failed to download attachment ${attachmentId}`);
          const encryptedBytes = new Uint8Array(await fileResp.arrayBuffer());

          let fileEnc = itemEnc;
          let fileMac = itemMac;
          const attachmentKeyCipher = String(info.key || attachment?.key || '').trim();
          if (attachmentKeyCipher && looksLikeCipherString(attachmentKeyCipher)) {
            try {
              const rawAttachmentKey = await decryptBw(attachmentKeyCipher, itemEnc, itemMac);
              if (rawAttachmentKey.length >= 64) {
                fileEnc = rawAttachmentKey.slice(0, 32);
                fileMac = rawAttachmentKey.slice(32, 64);
              }
            } catch {
              // fallback to item key
            }
          }

          const plainBytes = await decryptBwFileData(encryptedBytes, fileEnc, fileMac);

          const fileNameRaw = String(info.fileName || attachment?.fileName || '').trim();
          let fileName = fileNameRaw || `attachment-${attachmentId}`;
          if (fileNameRaw && looksLikeCipherString(fileNameRaw)) {
            try {
              fileName = (await decryptStr(fileNameRaw, itemEnc, itemMac)) || fileName;
            } catch {
              // fallback to raw encrypted name
            }
          }

          out.push({
            cipherId,
            fileName,
            bytes: plainBytes,
          });
        }
      }
      return out;
    };

    const getNodeWardenAttachmentRecords = async () => {
      if (nodeWardenAttachmentsCache) return nodeWardenAttachmentsCache;
      const [doc, attachments] = await Promise.all([getPlainJsonDoc(), zipAttachments()]);
      const cipherIndexById = new Map<string, number>();
      const items = Array.isArray(doc.items) ? (doc.items as Array<Record<string, unknown>>) : [];
      for (let i = 0; i < items.length; i++) {
        const id = String(items[i]?.id || '').trim();
        if (id) cipherIndexById.set(id, i);
      }
      nodeWardenAttachmentsCache = buildNodeWardenAttachmentRecords(attachments, cipherIndexById);
      return nodeWardenAttachmentsCache;
    };

    const format = request.format;
    if (format === 'bitwarden_json') {
      const bytes = new TextEncoder().encode(await getPlainJson());
      return {
        fileName: buildExportFileName(format),
        mimeType: 'application/json',
        bytes,
      };
    }

    if (format === 'bitwarden_encrypted_json') {
      if (request.encryptedJsonMode === 'password') {
        const plainJson = await getPlainJson();
        const kdf = await getPreloginKdfConfig(profile?.email || session.email, defaultKdfIterations);
        const encrypted = await buildPasswordProtectedBitwardenJsonString({
          plaintextJson: plainJson,
          password: String(request.filePassword || ''),
          kdf,
        });
        return {
          fileName: buildExportFileName(format),
          mimeType: 'application/json',
          bytes: new TextEncoder().encode(encrypted),
        };
      }
      const bytes = new TextEncoder().encode(await getEncryptedJson());
      return {
        fileName: buildExportFileName(format),
        mimeType: 'application/json',
        bytes,
      };
    }

    if (format === 'nodewarden_json') {
      const [plainDoc, attachments] = await Promise.all([getPlainJsonDoc(), getNodeWardenAttachmentRecords()]);
      const nodeWardenDoc = buildNodeWardenPlainJsonDocument(plainDoc, attachments);
      return {
        fileName: buildExportFileName(format),
        mimeType: 'application/json',
        bytes: new TextEncoder().encode(JSON.stringify(nodeWardenDoc, null, 2)),
      };
    }

    if (format === 'nodewarden_encrypted_json') {
      if (request.encryptedJsonMode === 'password') {
        const [plainDoc, attachments] = await Promise.all([getPlainJsonDoc(), getNodeWardenAttachmentRecords()]);
        const nodeWardenDoc = buildNodeWardenPlainJsonDocument(plainDoc, attachments);
        const kdf = await getPreloginKdfConfig(profile?.email || session.email, defaultKdfIterations);
        const encrypted = await buildPasswordProtectedBitwardenJsonString({
          plaintextJson: JSON.stringify(nodeWardenDoc, null, 2),
          password: String(request.filePassword || ''),
          kdf,
        });
        return {
          fileName: buildExportFileName(format),
          mimeType: 'application/json',
          bytes: new TextEncoder().encode(encrypted),
        };
      }

      const [encryptedJson, attachments] = await Promise.all([getEncryptedJson(), getNodeWardenAttachmentRecords()]);
      const withAttachments = await attachNodeWardenEncryptedAttachmentPayload(
        encryptedJson,
        attachments,
        session.symEncKey!,
        session.symMacKey!
      );
      return {
        fileName: buildExportFileName(format),
        mimeType: 'application/json',
        bytes: new TextEncoder().encode(withAttachments),
      };
    }

    if (format === 'bitwarden_json_zip' || format === 'bitwarden_encrypted_json_zip') {
      let dataJson = await getPlainJson();
      if (format === 'bitwarden_encrypted_json_zip') {
        if (request.encryptedJsonMode === 'password') {
          const kdf = await getPreloginKdfConfig(profile?.email || session.email, defaultKdfIterations);
          dataJson = await buildPasswordProtectedBitwardenJsonString({
            plaintextJson: await getPlainJson(),
            password: String(request.filePassword || ''),
            kdf,
          });
        } else {
          dataJson = await getEncryptedJson();
        }
      }
      const attachments = await zipAttachments();
      const zipBytes = buildBitwardenZipBytes(dataJson, attachments);
      const encryptedZip = await encryptZipBytesWithPassword(zipBytes, String(request.zipPassword || ''));
      return {
        fileName: buildExportFileName(format, encryptedZip.encrypted),
        mimeType: 'application/zip',
        bytes: encryptedZip.bytes,
      };
    }

    throw new Error(t('txt_unsupported_export_format'));
  }

  function downloadBytesAsFile(bytes: Uint8Array, fileName: string, mimeType: string) {
    const blob = new Blob([bytes], { type: mimeType || 'application/octet-stream' });
    const objectUrl = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = objectUrl;
    anchor.download = fileName || 'download.bin';
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 0);
  }

  async function handleBackupExportAction() {
    const payload = await exportAdminBackup(authedFetch);
    downloadBytesAsFile(payload.bytes, payload.fileName, payload.mimeType);
  }

  async function handleBackupImportAction(file: File, replaceExisting: boolean = false) {
    await importAdminBackup(authedFetch, file, replaceExisting);
    window.setTimeout(() => {
      logoutNow();
    }, 200);
  }

  const hashPathRaw = typeof window !== 'undefined' ? window.location.hash || '' : '';
  const hashPath = hashPathRaw.startsWith('#') ? hashPathRaw.slice(1) : hashPathRaw;
  const hashPathOnly = String(hashPath || '').split('?')[0].split('#')[0];
  const normalizedHashPath = `/${hashPathOnly.replace(/^\/+/, '').replace(/\/+$/, '')}`.replace(/^\/$/, '/');
  const isImportHashRoute = IMPORT_ROUTE_ALIASES.has(normalizedHashPath);
  const effectiveLocation = hashPath.startsWith('/send/') || hashPath === '/recover-2fa' ? hashPath : location;
  const publicSendMatch = effectiveLocation.match(/^\/send\/([^/]+)(?:\/([^/]+))?\/?$/i);
  const isRecoverTwoFactorRoute = effectiveLocation === '/recover-2fa';
  const isPublicSendRoute = !!publicSendMatch;
  const isImportRoute = location === IMPORT_ROUTE || IMPORT_ROUTE_ALIASES.has(location);
  const showSidebarToggle = mobileLayout && (location === '/vault' || location === '/sends');
  const sidebarToggleTitle = location === '/vault' ? t('txt_folders') : t('txt_type');
  const mobilePrimaryRoute =
    location === '/sends'
      ? '/sends'
      : location === '/vault/totp'
        ? '/vault/totp'
        : location === '/vault'
          ? '/vault'
          : '/settings';
  const currentPageTitle = (() => {
    if (location === '/vault/totp') return t('txt_verification_code');
    if (location === '/sends') return t('nav_sends');
    if (location === '/admin') return t('nav_admin_panel');
    if (location === '/security/devices') return t('nav_device_management');
    if (location === '/help') return t('nav_backup_strategy');
    if (isImportRoute) return t('nav_import_export');
    if (location === SETTINGS_ACCOUNT_ROUTE) return t('nav_account_settings');
    if (location === SETTINGS_HOME_ROUTE) return t('txt_settings');
    return t('nav_my_vault');
  })();

  useEffect(() => {
    if (phase === 'app' && location === '/' && !isPublicSendRoute) navigate('/vault');
  }, [phase, location, isPublicSendRoute, navigate]);

  useEffect(() => {
    if (phase === 'app' && isImportHashRoute && location !== IMPORT_ROUTE) {
      navigate(IMPORT_ROUTE);
    }
  }, [phase, isImportHashRoute, location, navigate]);

  useEffect(() => {
    if (phase === 'app' && profile?.role !== 'admin' && location === '/help') {
      navigate('/vault');
    }
  }, [phase, profile?.role, location, navigate]);

  useEffect(() => {
    if (phase === 'app' && !mobileLayout && location === SETTINGS_HOME_ROUTE) {
      navigate(SETTINGS_ACCOUNT_ROUTE);
    }
  }, [phase, mobileLayout, location, navigate]);

  if (jwtWarning) {
    return <JwtWarningPage reason={jwtWarning.reason} minLength={jwtWarning.minLength} />;
  }

  if (publicSendMatch) {
    return (
      <>
        <PublicSendPage accessId={decodeURIComponent(publicSendMatch[1])} keyPart={publicSendMatch[2] ? decodeURIComponent(publicSendMatch[2]) : null} />
        <ToastHost toasts={toasts} onClose={(id) => setToasts((prev) => prev.filter((x) => x.id !== id))} />
      </>
    );
  }

  if (isRecoverTwoFactorRoute && phase !== 'app') {
    return (
      <>
        <RecoverTwoFactorPage
          values={recoverValues}
          onChange={setRecoverValues}
          onSubmit={() => void handleRecoverTwoFactorSubmit()}
          onCancel={() => {
            setRecoverValues({ email: '', password: '', recoveryCode: '' });
            navigate('/login');
          }}
        />
        <ToastHost toasts={toasts} onClose={(id) => setToasts((prev) => prev.filter((x) => x.id !== id))} />
      </>
    );
  }

  if (phase === 'loading') {
    return (
      <>
        <div className="loading-screen">{t('txt_loading_nodewarden')}</div>
        <ToastHost toasts={toasts} onClose={(id) => setToasts((prev) => prev.filter((x) => x.id !== id))} />
      </>
    );
  }

  if (phase === 'register' || phase === 'login' || phase === 'locked') {
    return (
      <>
        <AuthViews
          mode={phase}
          loginValues={loginValues}
          registerValues={registerValues}
          unlockPassword={unlockPassword}
          emailForLock={profile?.email || session?.email || ''}
          onChangeLogin={setLoginValues}
          onChangeRegister={setRegisterValues}
          onChangeUnlock={setUnlockPassword}
          onSubmitLogin={() => void handleLogin()}
          onSubmitRegister={() => void handleRegister()}
          onSubmitUnlock={() => void handleUnlock()}
          onGotoLogin={() => {
            setPhase('login');
            navigate('/login');
          }}
          onGotoRegister={() => {
            if (inviteCodeFromUrl) {
              setRegisterValues((prev) => ({ ...prev, inviteCode: inviteCodeFromUrl }));
            }
            setPhase('register');
            navigate('/register');
          }}
          onLogout={logoutNow}
        />
        <ToastHost toasts={toasts} onClose={(id) => setToasts((prev) => prev.filter((x) => x.id !== id))} />

        <ConfirmDialog
          open={!!pendingTotp}
          title={t('txt_two_step_verification')}
          message={t('txt_password_is_already_verified')}
          confirmText={t('txt_verify')}
          cancelText={t('txt_cancel')}
          showIcon={false}
          onConfirm={() => void handleTotpVerify()}
          onCancel={() => {
            setPendingTotp(null);
            setTotpCode('');
            setRememberDevice(true);
          }}
          afterActions={(
            <div className="dialog-extra">
              <div className="dialog-divider" />
              <button
                type="button"
                className="btn btn-secondary dialog-btn"
                onClick={() => {
                  setPendingTotp(null);
                  setTotpCode('');
                  setRememberDevice(true);
                  navigate('/recover-2fa');
                }}
              >
                {t('txt_use_recovery_code')}
              </button>
            </div>
          )}
        >
          <label className="field">
            <span>{t('txt_totp_code')}</span>
            <input className="input" value={totpCode} onInput={(e) => setTotpCode((e.currentTarget as HTMLInputElement).value)} />
          </label>
          <label className="check-line" style={{ marginBottom: 0 }}>
            <input type="checkbox" checked={rememberDevice} onChange={(e) => setRememberDevice((e.currentTarget as HTMLInputElement).checked)} />
            <span>{t('txt_trust_this_device_for_30_days')}</span>
          </label>
        </ConfirmDialog>
      </>
    );
  }

  return (
    <>
      <div className="app-page">
        <div className="app-shell">
          <header className="topbar">
            <div className="brand">
              <img src="/logo-64.png" alt="NodeWarden logo" className="brand-logo" />
              <span className="brand-name">NodeWarden</span>
              <span className="mobile-page-title">{currentPageTitle}</span>
            </div>
            <div className="topbar-actions">
              <div className="user-chip">
                <ShieldUser size={16} />
                <span>{profile?.email}</span>
              </div>
              <button type="button" className="btn btn-secondary small" onClick={handleLock}>
                <Lock size={14} className="btn-icon" /> {t('txt_lock')}
              </button>
              {showSidebarToggle && (
                <button
                  type="button"
                  className="btn btn-secondary small mobile-sidebar-toggle"
                  aria-label={sidebarToggleTitle}
                  title={sidebarToggleTitle}
                  onClick={() => window.dispatchEvent(new CustomEvent('nodewarden:toggle-sidebar'))}
                >
                  <Folder size={16} className="btn-icon" />
                </button>
              )}
              <button type="button" className="btn btn-secondary small mobile-lock-btn" aria-label={t('txt_lock')} title={t('txt_lock')} onClick={handleLock}>
                <Lock size={14} className="btn-icon" />
              </button>
              <button type="button" className="btn btn-secondary small" onClick={handleLogout}>
                <LogOut size={14} className="btn-icon" /> {t('txt_sign_out')}
              </button>
            </div>
          </header>

          <div className="app-main">
            <aside className="app-side">
              <Link href="/vault" className={`side-link ${location === '/vault' ? 'active' : ''}`}>
                <KeyRound size={16} />
                <span>{t('nav_my_vault')}</span>
              </Link>
              <Link href="/vault/totp" className={`side-link ${location === '/vault/totp' ? 'active' : ''}`}>
                <Clock3 size={16} />
                <span>{t('txt_verification_code')}</span>
              </Link>
              <Link href="/sends" className={`side-link ${location === '/sends' ? 'active' : ''}`}>
                <SendIcon size={16} />
                <span>{t('nav_sends')}</span>
              </Link>
              {profile?.role === 'admin' && (
                <Link href="/admin" className={`side-link ${location === '/admin' ? 'active' : ''}`}>
                  <ShieldUser size={16} />
                  <span>{t('nav_admin_panel')}</span>
                </Link>
              )}
              <Link href={SETTINGS_ACCOUNT_ROUTE} className={`side-link ${location === SETTINGS_ACCOUNT_ROUTE ? 'active' : ''}`}>
                <SettingsIcon size={16} />
                <span>{t('nav_account_settings')}</span>
              </Link>
              <Link href="/security/devices" className={`side-link ${location === '/security/devices' ? 'active' : ''}`}>
                <Shield size={16} />
                <span>{t('nav_device_management')}</span>
              </Link>
              {profile?.role === 'admin' && (
                <Link href="/help" className={`side-link ${location === '/help' ? 'active' : ''}`}>
                  <Cloud size={16} />
                  <span>{t('nav_backup_strategy')}</span>
                </Link>
              )}
              <Link href={IMPORT_ROUTE} className={`side-link ${isImportRoute ? 'active' : ''}`}>
                <ArrowUpDown size={14} />
                <span>{t('nav_import_export')}</span>
              </Link>
            </aside>
            <main className="content">
              <Switch>
                <Route path="/sends">
                  <SendsPage
                    sends={decryptedSends}
                    loading={sendsQuery.isFetching}
                    onRefresh={refreshVault}
                    onCreate={createSendItem}
                    onUpdate={updateSendItem}
                    onDelete={deleteSendItem}
                    onBulkDelete={bulkDeleteSendItems}
                    onNotify={pushToast}
                  />
                </Route>
                <Route path="/vault/totp">
                  <TotpCodesPage ciphers={decryptedCiphers} loading={ciphersQuery.isFetching} onNotify={pushToast} />
                </Route>
                <Route path="/vault">
                  <VaultPage
                    ciphers={decryptedCiphers}
                    folders={decryptedFolders}
                    loading={ciphersQuery.isFetching || foldersQuery.isFetching}
                    emailForReprompt={profile?.email || session?.email || ''}
                    onRefresh={refreshVault}
                    onCreate={createVaultItem}
                    onUpdate={updateVaultItem}
                    onDelete={deleteVaultItem}
                    onBulkDelete={bulkDeleteVaultItems}
                    onBulkMove={bulkMoveVaultItems}
                    onVerifyMasterPassword={verifyMasterPasswordAction}
                    onNotify={pushToast}
                    onCreateFolder={createFolderAction}
                    onDeleteFolder={deleteFolderAction}
                    onDownloadAttachment={downloadVaultAttachment}
                  />
                </Route>
                <Route path={SETTINGS_ACCOUNT_ROUTE}>
                  {profile && (
                    <div className="stack">
                      {mobileLayout && (
                        <div className="mobile-settings-subhead">
                          <button type="button" className="btn btn-secondary small mobile-settings-back" onClick={() => navigate(SETTINGS_HOME_ROUTE)}>
                            <span className="btn-icon" aria-hidden="true">{"<"}</span>
                            {t('txt_back')}
                          </button>
                        </div>
                      )}
                      <SettingsPage
                        profile={profile}
                        totpEnabled={!!totpStatusQuery.data?.enabled}
                        onChangePassword={changePasswordAction}
                        onEnableTotp={async (secret, token) => {
                          await enableTotpAction(secret, token);
                          await totpStatusQuery.refetch();
                        }}
                        onOpenDisableTotp={() => setDisableTotpOpen(true)}
                        onGetRecoveryCode={getRecoveryCodeAction}
                        onNotify={pushToast}
                      />
                    </div>
                  )}
                </Route>
                <Route path="/settings">
                  {profile && (
                    <section className="card mobile-settings-card">
                      <div className="mobile-settings-links">
                        <Link href={SETTINGS_ACCOUNT_ROUTE} className="mobile-settings-link">
                          <SettingsIcon size={18} />
                          <span>{t('nav_account_settings')}</span>
                        </Link>
                        <Link href="/security/devices" className="mobile-settings-link">
                          <Shield size={18} />
                          <span>{t('nav_device_management')}</span>
                        </Link>
                        <Link href={IMPORT_ROUTE} className="mobile-settings-link">
                          <ArrowUpDown size={18} />
                          <span>{t('nav_import_export')}</span>
                        </Link>
                        {profile.role === 'admin' && (
                          <Link href="/admin" className="mobile-settings-link">
                            <ShieldUser size={18} />
                            <span>{t('nav_admin_panel')}</span>
                          </Link>
                        )}
                        {profile.role === 'admin' && (
                          <Link href="/help" className="mobile-settings-link">
                            <Cloud size={18} />
                            <span>{t('nav_backup_strategy')}</span>
                          </Link>
                        )}
                      </div>
                      <button type="button" className="btn btn-secondary mobile-settings-logout" onClick={handleLogout}>
                        <LogOut size={14} className="btn-icon" />
                        {t('txt_sign_out')}
                      </button>
                    </section>
                  )}
                </Route>
                <Route path="/security/devices">
                  <div className="stack">
                    {mobileLayout && (
                      <div className="mobile-settings-subhead">
                        <button type="button" className="btn btn-secondary small mobile-settings-back" onClick={() => navigate(SETTINGS_HOME_ROUTE)}>
                          <span className="btn-icon" aria-hidden="true">{"<"}</span>
                          {t('txt_back')}
                        </button>
                      </div>
                    )}
                    <SecurityDevicesPage
                      devices={authorizedDevicesQuery.data || []}
                      loading={authorizedDevicesQuery.isFetching}
                      onRefresh={() => void refreshAuthorizedDevices()}
                      onRevokeTrust={(device) => {
                        setConfirm({
                          title: t('txt_revoke_device_authorization'),
                          message: t('txt_revoke_30_day_totp_trust_for_name', { name: device.name }),
                          danger: true,
                          onConfirm: () => {
                            setConfirm(null);
                            void revokeDeviceTrustAction(device);
                          },
                        });
                      }}
                      onRemoveDevice={(device) => {
                        setConfirm({
                          title: t('txt_remove_device'),
                          message: t('txt_remove_device_and_sign_out_name', { name: device.name }),
                          danger: true,
                          onConfirm: () => {
                            setConfirm(null);
                            void removeDeviceAction(device);
                          },
                        });
                      }}
                      onRevokeAll={() => {
                        setConfirm({
                          title: t('txt_revoke_all_trusted_devices'),
                          message: t('txt_revoke_30_day_totp_trust_from_all_devices'),
                          danger: true,
                          onConfirm: () => {
                            setConfirm(null);
                            void revokeAllDeviceTrustAction();
                          },
                        });
                      }}
                      onRemoveAll={() => {
                        setConfirm({
                          title: t('txt_remove_all_devices'),
                          message: t('txt_remove_all_devices_and_sign_out_all_sessions'),
                          danger: true,
                          onConfirm: () => {
                            setConfirm(null);
                            void removeAllDevicesAction();
                          },
                        });
                      }}
                    />
                  </div>
                </Route>
                <Route path="/admin">
                  <div className="stack">
                    {mobileLayout && (
                      <div className="mobile-settings-subhead">
                        <button type="button" className="btn btn-secondary small mobile-settings-back" onClick={() => navigate(SETTINGS_HOME_ROUTE)}>
                          <span className="btn-icon" aria-hidden="true">{"<"}</span>
                          {t('txt_back')}
                        </button>
                      </div>
                    )}
                    <AdminPage
                      currentUserId={profile?.id || ''}
                      users={usersQuery.data || []}
                      invites={invitesQuery.data || []}
                      onRefresh={() => {
                        void usersQuery.refetch();
                        void invitesQuery.refetch();
                      }}
                      onCreateInvite={async (hours) => {
                        await createInvite(authedFetch, hours);
                        await invitesQuery.refetch();
                        pushToast('success', t('txt_invite_created'));
                      }}
                      onDeleteAllInvites={async () => {
                        setConfirm({
                          title: t('txt_delete_all_invites'),
                          message: t('txt_delete_all_invite_codes_active_inactive'),
                          danger: true,
                          onConfirm: () => {
                            setConfirm(null);
                            void (async () => {
                              await deleteAllInvites(authedFetch);
                              await invitesQuery.refetch();
                              pushToast('success', t('txt_all_invites_deleted'));
                            })();
                          },
                        });
                      }}
                      onToggleUserStatus={async (userId, status) => {
                        await setUserStatus(authedFetch, userId, status === 'active' ? 'banned' : 'active');
                        await usersQuery.refetch();
                        pushToast('success', t('txt_user_status_updated'));
                      }}
                      onDeleteUser={async (userId) => {
                        setConfirm({
                          title: t('txt_delete_user'),
                          message: t('txt_delete_this_user_and_all_user_data'),
                          danger: true,
                          onConfirm: () => {
                            setConfirm(null);
                            void (async () => {
                              await deleteUser(authedFetch, userId);
                              await usersQuery.refetch();
                              pushToast('success', t('txt_user_deleted'));
                            })();
                          },
                        });
                      }}
                      onRevokeInvite={async (code) => {
                        await revokeInvite(authedFetch, code);
                        await invitesQuery.refetch();
                        pushToast('success', t('txt_invite_revoked'));
                      }}
                    />
                  </div>
                </Route>
                <Route path={IMPORT_ROUTE}>
                  <div className="stack">
                    {mobileLayout && (
                      <div className="mobile-settings-subhead">
                        <button type="button" className="btn btn-secondary small mobile-settings-back" onClick={() => navigate(SETTINGS_HOME_ROUTE)}>
                          <span className="btn-icon" aria-hidden="true">{"<"}</span>
                          {t('txt_back')}
                        </button>
                      </div>
                    )}
                    <ImportPage
                      onImport={handleImportAction}
                      onImportEncryptedRaw={handleImportEncryptedRawAction}
                      accountKeys={session?.symEncKey && session?.symMacKey ? { encB64: session.symEncKey, macB64: session.symMacKey } : null}
                      onNotify={pushToast}
                      folders={decryptedFolders}
                      onExport={handleExportAction}
                    />
                  </div>
                </Route>
                <Route path="/tools/import">
                  <ImportPage
                    onImport={handleImportAction}
                    onImportEncryptedRaw={handleImportEncryptedRawAction}
                    accountKeys={session?.symEncKey && session?.symMacKey ? { encB64: session.symEncKey, macB64: session.symMacKey } : null}
                    onNotify={pushToast}
                    folders={decryptedFolders}
                    onExport={handleExportAction}
                  />
                </Route>
                <Route path="/tools/import-export">
                  <ImportPage
                    onImport={handleImportAction}
                    onImportEncryptedRaw={handleImportEncryptedRawAction}
                    accountKeys={session?.symEncKey && session?.symMacKey ? { encB64: session.symEncKey, macB64: session.symMacKey } : null}
                    onNotify={pushToast}
                    folders={decryptedFolders}
                    onExport={handleExportAction}
                  />
                </Route>
                <Route path="/tools/import-data">
                  <ImportPage
                    onImport={handleImportAction}
                    onImportEncryptedRaw={handleImportEncryptedRawAction}
                    accountKeys={session?.symEncKey && session?.symMacKey ? { encB64: session.symEncKey, macB64: session.symMacKey } : null}
                    onNotify={pushToast}
                    folders={decryptedFolders}
                    onExport={handleExportAction}
                  />
                </Route>
                <Route path="/import">
                  <ImportPage
                    onImport={handleImportAction}
                    onImportEncryptedRaw={handleImportEncryptedRawAction}
                    accountKeys={session?.symEncKey && session?.symMacKey ? { encB64: session.symEncKey, macB64: session.symMacKey } : null}
                    onNotify={pushToast}
                    folders={decryptedFolders}
                    onExport={handleExportAction}
                  />
                </Route>
                <Route path="/import-export">
                  <ImportPage
                    onImport={handleImportAction}
                    onImportEncryptedRaw={handleImportEncryptedRawAction}
                    accountKeys={session?.symEncKey && session?.symMacKey ? { encB64: session.symEncKey, macB64: session.symMacKey } : null}
                    onNotify={pushToast}
                    folders={decryptedFolders}
                    onExport={handleExportAction}
                  />
                </Route>
                <Route path="/help">
                  {profile?.role === 'admin' ? (
                    <div className="stack">
                      {mobileLayout && (
                        <div className="mobile-settings-subhead">
                          <button type="button" className="btn btn-secondary small mobile-settings-back" onClick={() => navigate(SETTINGS_HOME_ROUTE)}>
                            <span className="btn-icon" aria-hidden="true">{"<"}</span>
                            {t('txt_back')}
                          </button>
                        </div>
                      )}
                      <HelpPage onExport={handleBackupExportAction} onImport={handleBackupImportAction} onNotify={pushToast} />
                    </div>
                  ) : null}
                </Route>
              </Switch>
            </main>
          </div>

          <nav className="mobile-tabbar" aria-label={t('txt_menu')}>
            <Link href="/vault" className={`mobile-tab ${mobilePrimaryRoute === '/vault' ? 'active' : ''}`}>
              <KeyRound size={18} />
              <span>{t('nav_my_vault')}</span>
            </Link>
            <Link href="/vault/totp" className={`mobile-tab ${mobilePrimaryRoute === '/vault/totp' ? 'active' : ''}`}>
              <Clock3 size={18} />
              <span>{t('txt_verification_code')}</span>
            </Link>
            <Link href="/sends" className={`mobile-tab ${mobilePrimaryRoute === '/sends' ? 'active' : ''}`}>
              <SendIcon size={18} />
              <span>{t('nav_sends')}</span>
            </Link>
            <Link href="/settings" className={`mobile-tab ${mobilePrimaryRoute === '/settings' ? 'active' : ''}`}>
              <SettingsIcon size={18} />
              <span>{t('txt_settings')}</span>
            </Link>
          </nav>
        </div>
      </div>

      <ConfirmDialog
        open={!!confirm}
        title={confirm?.title || ''}
        message={confirm?.message || ''}
        danger={confirm?.danger}
        showIcon={confirm?.showIcon}
        onConfirm={() => confirm?.onConfirm()}
        onCancel={() => setConfirm(null)}
      />

      <ConfirmDialog
        open={disableTotpOpen}
        title={t('txt_disable_totp')}
        message={t('txt_enter_master_password_to_disable_two_step_verification')}
        confirmText={t('txt_disable_totp')}
        cancelText={t('txt_cancel')}
        danger
        showIcon={false}
        onConfirm={() => void disableTotpAction()}
        onCancel={() => {
          setDisableTotpOpen(false);
          setDisableTotpPassword('');
        }}
      >
        <label className="field">
          <span>{t('txt_master_password')}</span>
          <input
            className="input"
            type="password"
            value={disableTotpPassword}
            onInput={(e) => setDisableTotpPassword((e.currentTarget as HTMLInputElement).value)}
          />
        </label>
      </ConfirmDialog>

      <ToastHost toasts={toasts} onClose={(id) => setToasts((prev) => prev.filter((x) => x.id !== id))} />
    </>
  );
}
