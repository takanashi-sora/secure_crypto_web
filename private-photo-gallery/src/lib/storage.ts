import type { GallerySettings } from '../types';

export const DEFAULT_SETTINGS: GallerySettings = {
  token: '',
  owner: 'takanashi-sora',
  repo: 'photo-vault',
  branch: 'main',
  folder: 'photos',
  rememberToken: false,
};

const SETTINGS_KEY = 'soraPhotoVaultSettingsV2';
const TOKEN_KEY = 'soraPhotoVaultTokenV2';
const LEGACY_SETTINGS_KEY = 'privatePhotoVaultSettings';
const LEGACY_TOKEN_KEY = 'privatePhotoVaultToken';

function safeParse(value: string | null): Record<string, unknown> {
  if (!value) return {};
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

export function loadSettings(): GallerySettings {
  const stored = safeParse(localStorage.getItem(SETTINGS_KEY));
  const legacy = safeParse(localStorage.getItem(LEGACY_SETTINGS_KEY));
  const remembered = localStorage.getItem(TOKEN_KEY) || localStorage.getItem(LEGACY_TOKEN_KEY) || '';
  const session = sessionStorage.getItem(TOKEN_KEY) || '';
  const source = { ...legacy, ...stored };

  if (!localStorage.getItem(TOKEN_KEY) && localStorage.getItem(LEGACY_TOKEN_KEY)) {
    localStorage.setItem(TOKEN_KEY, remembered);
    localStorage.removeItem(LEGACY_TOKEN_KEY);
  }

  return {
    token: session || remembered,
    owner: typeof source.owner === 'string' ? source.owner : DEFAULT_SETTINGS.owner,
    repo: typeof source.repo === 'string' ? source.repo : DEFAULT_SETTINGS.repo,
    branch: typeof source.branch === 'string' ? source.branch : DEFAULT_SETTINGS.branch,
    folder: typeof source.folder === 'string' ? source.folder.replace(/^\/+|\/+$/g, '') : DEFAULT_SETTINGS.folder,
    rememberToken: Boolean(remembered),
  };
}

export function saveSettings(settings: GallerySettings) {
  const normalized = {
    owner: settings.owner.trim(),
    repo: settings.repo.trim(),
    branch: settings.branch.trim(),
    folder: settings.folder.trim().replace(/^\/+|\/+$/g, ''),
  };
  localStorage.setItem(SETTINGS_KEY, JSON.stringify(normalized));
  localStorage.removeItem(LEGACY_SETTINGS_KEY);

  if (settings.token) sessionStorage.setItem(TOKEN_KEY, settings.token);
  else sessionStorage.removeItem(TOKEN_KEY);

  if (settings.rememberToken && settings.token) localStorage.setItem(TOKEN_KEY, settings.token);
  else localStorage.removeItem(TOKEN_KEY);
}

export function clearStoredToken() {
  sessionStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(LEGACY_TOKEN_KEY);
}
