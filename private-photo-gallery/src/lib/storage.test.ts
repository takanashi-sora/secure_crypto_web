import { describe, expect, it } from 'vitest';
import { clearStoredToken, DEFAULT_SETTINGS, loadSettings, saveSettings } from './storage';

describe('gallery settings storage', () => {
  it('keeps a token in the current session by default', () => {
    saveSettings({ ...DEFAULT_SETTINGS, token: 'session-token' });

    expect(loadSettings()).toMatchObject({ token: 'session-token', rememberToken: false });
    expect(localStorage.getItem('soraPhotoVaultTokenV2')).toBeNull();
  });

  it('persists a token only when rememberToken is enabled', () => {
    saveSettings({ ...DEFAULT_SETTINGS, token: 'remembered-token', rememberToken: true });
    sessionStorage.clear();

    expect(loadSettings()).toMatchObject({ token: 'remembered-token', rememberToken: true });
  });

  it('migrates the original gallery keys without losing access', () => {
    localStorage.setItem('privatePhotoVaultToken', 'legacy-token');
    localStorage.setItem(
      'privatePhotoVaultSettings',
      JSON.stringify({ owner: 'legacy-owner', repo: 'legacy-repo', folder: '/memories/' }),
    );

    expect(loadSettings()).toMatchObject({
      token: 'legacy-token',
      owner: 'legacy-owner',
      repo: 'legacy-repo',
      folder: 'memories',
      rememberToken: true,
    });
  });

  it('clears current and legacy credentials when disconnecting', () => {
    saveSettings({ ...DEFAULT_SETTINGS, token: 'secret', rememberToken: true });
    clearStoredToken();

    expect(loadSettings().token).toBe('');
  });
});
