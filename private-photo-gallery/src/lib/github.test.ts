import { describe, expect, it, vi } from 'vitest';
import { GitHubApiError, GitHubRepositoryClient } from './github';
import { DEFAULT_SETTINGS } from './storage';

function response(body: unknown, init: ResponseInit = {}) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
    ...init,
  });
}

describe('GitHub repository client', () => {
  it('filters non-image blobs and orders photos newest-first by name', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        response({
          truncated: false,
          tree: [
            { type: 'blob', path: 'photos/2025-a.jpg', sha: 'old', size: 10 },
            { type: 'blob', path: 'photos/2026-b.webp', sha: 'new', size: 20 },
            { type: 'blob', path: 'photos/notes.txt', sha: 'text', size: 5 },
            { type: 'blob', path: 'elsewhere/hidden.jpg', sha: 'other', size: 30 },
          ],
        }),
      ),
    );

    const client = new GitHubRepositoryClient({ ...DEFAULT_SETTINGS, token: 'token' });
    const result = await client.listPhotos();

    expect(result.map((photo) => photo.path)).toEqual([
      'photos/2026-b.webp',
      'photos/2025-a.jpg',
    ]);
  });

  it('returns an empty manifest when the metadata file does not exist', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(response({ message: 'Not Found' }, { status: 404 })),
    );

    const client = new GitHubRepositoryClient({ ...DEFAULT_SETTINGS, token: 'token' });
    const snapshot = await client.loadManifest();

    expect(snapshot.sha).toBeUndefined();
    expect(snapshot.manifest).toMatchObject({ schemaVersion: 1, photos: {}, albums: [] });
  });

  it('surfaces authentication errors as structured API errors', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(response({ message: 'Bad credentials' }, { status: 401 })),
    );

    const client = new GitHubRepositoryClient({ ...DEFAULT_SETTINGS, token: 'expired' });

    await expect(client.listPhotos()).rejects.toEqual(
      expect.objectContaining<Partial<GitHubApiError>>({ status: 401, message: 'Bad credentials' }),
    );
  });
});
