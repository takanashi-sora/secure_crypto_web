import { createEmptyManifest, normalizeManifest } from './manifest';
import type {
  GallerySettings,
  ManifestSnapshot,
  PhotoAsset,
  PhotoRecord,
  RepositoryClient,
  UploadCandidate,
  VaultManifestV1,
} from '../types';

const IMAGE_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.avif', '.bmp'];

interface TreeEntry {
  path: string;
  type: 'blob' | 'tree';
  sha: string;
  size?: number;
}

interface ContentEntry {
  type: 'file' | 'dir';
  name: string;
  path: string;
  sha: string;
  size: number;
}

export class GitHubApiError extends Error {
  constructor(
    message: string,
    public status: number,
    public retryAfter?: string,
  ) {
    super(message);
    this.name = 'GitHubApiError';
  }
}

function encodePath(path: string) {
  return path.split('/').map(encodeURIComponent).join('/');
}

function isPhoto(path: string) {
  const lower = path.toLowerCase();
  return IMAGE_EXTENSIONS.some((extension) => lower.endsWith(extension));
}

function mimeFromName(name: string) {
  const extension = name.split('.').pop()?.toLowerCase();
  const mimes: Record<string, string> = {
    jpg: 'image/jpeg',
    jpeg: 'image/jpeg',
    png: 'image/png',
    gif: 'image/gif',
    webp: 'image/webp',
    avif: 'image/avif',
    bmp: 'image/bmp',
  };
  return mimes[extension ?? ''] ?? 'application/octet-stream';
}

function decodeBase64(base64: string) {
  const raw = atob(base64.replace(/\n/g, ''));
  const bytes = new Uint8Array(raw.length);
  for (let index = 0; index < raw.length; index += 1) bytes[index] = raw.charCodeAt(index);
  return bytes;
}

function decodeText(base64: string) {
  return new TextDecoder().decode(decodeBase64(base64));
}

async function fileToBase64(file: Blob) {
  const buffer = new Uint8Array(await file.arrayBuffer());
  let binary = '';
  const chunk = 0x8000;
  for (let index = 0; index < buffer.length; index += chunk) {
    binary += String.fromCharCode(...buffer.subarray(index, index + chunk));
  }
  return btoa(binary);
}

function encodeText(value: string) {
  const bytes = new TextEncoder().encode(value);
  let binary = '';
  for (let index = 0; index < bytes.length; index += 1) binary += String.fromCharCode(bytes[index]);
  return btoa(binary);
}

export class GitHubRepositoryClient implements RepositoryClient {
  private readonly baseUrl: string;
  private readonly folder: string;

  constructor(private readonly settings: GallerySettings) {
    this.baseUrl = `https://api.github.com/repos/${encodeURIComponent(settings.owner)}/${encodeURIComponent(settings.repo)}`;
    this.folder = settings.folder.replace(/^\/+|\/+$/g, '');
  }

  private async request<T>(url: string, init: RequestInit = {}): Promise<T> {
    const response = await fetch(url, {
      ...init,
      headers: {
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        ...(this.settings.token ? { Authorization: `Bearer ${this.settings.token}` } : {}),
        ...init.headers,
      },
    });
    const text = await response.text();
    let body: unknown;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      body = text;
    }

    if (!response.ok) {
      const apiMessage = body && typeof body === 'object' && 'message' in body ? String(body.message) : '';
      const rateLimited = response.status === 403 && response.headers.get('x-ratelimit-remaining') === '0';
      const message = rateLimited
        ? 'GitHub API 请求次数已用尽，请稍后重试。'
        : apiMessage || `${response.status} ${response.statusText}`;
      throw new GitHubApiError(message, response.status, response.headers.get('retry-after') ?? undefined);
    }
    return body as T;
  }

  private toPhoto(entry: Pick<TreeEntry, 'path' | 'sha' | 'size'>): PhotoRecord {
    return {
      path: entry.path,
      name: entry.path.split('/').pop() ?? entry.path,
      sha: entry.sha,
      size: entry.size ?? 0,
    };
  }

  private async listViaContents(): Promise<PhotoRecord[]> {
    const directories = [this.folder];
    const photos: PhotoRecord[] = [];
    while (directories.length) {
      const directory = directories.shift()!;
      const entries = await this.request<ContentEntry[]>(
        `${this.baseUrl}/contents/${encodePath(directory)}?ref=${encodeURIComponent(this.settings.branch)}`,
      );
      for (const entry of entries) {
        if (entry.type === 'dir' && !entry.path.includes('/.photo-vault')) directories.push(entry.path);
        if (entry.type === 'file' && isPhoto(entry.path)) photos.push(this.toPhoto(entry));
      }
    }
    return photos;
  }

  async listPhotos(): Promise<PhotoRecord[]> {
    const data = await this.request<{ tree: TreeEntry[]; truncated: boolean }>(
      `${this.baseUrl}/git/trees/${encodeURIComponent(this.settings.branch)}?recursive=1`,
    );
    const photos = data.truncated
      ? await this.listViaContents()
      : data.tree
          .filter(
            (entry) =>
              entry.type === 'blob' && entry.path.startsWith(`${this.folder}/`) && isPhoto(entry.path),
          )
          .map((entry) => this.toPhoto(entry));

    return photos.sort((left, right) => right.name.localeCompare(left.name, 'zh-Hans-CN'));
  }

  private get manifestPath() {
    return `${this.folder}/.photo-vault/manifest.json`;
  }

  async loadManifest(): Promise<ManifestSnapshot> {
    try {
      const data = await this.request<{ content: string; sha: string }>(
        `${this.baseUrl}/contents/${encodePath(this.manifestPath)}?ref=${encodeURIComponent(this.settings.branch)}`,
      );
      return { manifest: normalizeManifest(JSON.parse(decodeText(data.content))), sha: data.sha };
    } catch (error) {
      if (error instanceof GitHubApiError && error.status === 404) {
        return { manifest: createEmptyManifest() };
      }
      if (error instanceof SyntaxError) {
        throw new Error('相册元数据清单无法解析，请检查 manifest.json。');
      }
      throw error;
    }
  }

  private async saveManifest(manifest: VaultManifestV1, sha?: string): Promise<ManifestSnapshot> {
    const body = {
      message: sha ? 'Update photo vault metadata' : 'Create photo vault metadata',
      content: encodeText(JSON.stringify({ ...manifest, updatedAt: new Date().toISOString() }, null, 2)),
      branch: this.settings.branch,
      ...(sha ? { sha } : {}),
    };
    const data = await this.request<{ content: { sha: string } }>(
      `${this.baseUrl}/contents/${encodePath(this.manifestPath)}`,
      {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      },
    );
    return { manifest: { ...manifest, updatedAt: new Date().toISOString() }, sha: data.content.sha };
  }

  async updateManifest(
    mutate: (manifest: VaultManifestV1) => VaultManifestV1,
  ): Promise<ManifestSnapshot> {
    let lastError: unknown;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const snapshot = await this.loadManifest();
      try {
        return await this.saveManifest(mutate(structuredClone(snapshot.manifest)), snapshot.sha);
      } catch (error) {
        lastError = error;
        if (!(error instanceof GitHubApiError) || ![409, 422].includes(error.status)) throw error;
      }
    }
    throw lastError instanceof Error ? lastError : new Error('元数据发生并发冲突，请重新加载后再试。');
  }

  async loadPhotoAsset(photo: PhotoRecord): Promise<PhotoAsset> {
    const data = await this.request<{ content: string }>(`${this.baseUrl}/git/blobs/${photo.sha}`);
    const blob = new Blob([decodeBase64(data.content)], { type: mimeFromName(photo.name) });
    return { blob, url: URL.createObjectURL(blob) };
  }

  async uploadPhoto(candidate: UploadCandidate): Promise<PhotoRecord> {
    const path = `${this.folder}/${candidate.targetName}`;
    const data = await this.request<{ content: { sha: string; size?: number } }>(
      `${this.baseUrl}/contents/${encodePath(path)}`,
      {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: `Upload private photo: ${candidate.targetName}`,
          content: await fileToBase64(candidate.file),
          branch: this.settings.branch,
        }),
      },
    );
    return {
      path,
      name: candidate.targetName,
      sha: data.content.sha,
      size: data.content.size ?? candidate.file.size,
      capturedAt: candidate.capturedAt,
      width: candidate.width,
      height: candidate.height,
      title: candidate.file.name.replace(/\.[^.]+$/, ''),
    };
  }

  async deletePhoto(photo: PhotoRecord) {
    await this.request(`${this.baseUrl}/contents/${encodePath(photo.path)}`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message: `Delete private photo: ${photo.name}`,
        sha: photo.sha,
        branch: this.settings.branch,
      }),
    });
  }
}

export class PhotoAssetStore {
  private assets = new Map<string, Promise<PhotoAsset>>();
  private resolved = new Map<string, PhotoAsset>();
  private activeRequests = 0;
  private generation = 0;
  private readonly queue: Array<() => void> = [];

  constructor(
    private readonly client: RepositoryClient,
    private readonly concurrency = 4,
  ) {}

  private schedule<T>(task: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      this.queue.push(() => {
        this.activeRequests += 1;
        task()
          .then(resolve, reject)
          .finally(() => {
            this.activeRequests -= 1;
            this.drain();
          });
      });
      this.drain();
    });
  }

  private drain() {
    while (this.activeRequests < this.concurrency && this.queue.length) {
      this.queue.shift()?.();
    }
  }

  get(photo: PhotoRecord) {
    if (!this.assets.has(photo.sha)) {
      const generation = this.generation;
      const request = this.schedule(() => this.client.loadPhotoAsset(photo))
        .then((asset) => {
          if (generation !== this.generation) {
            URL.revokeObjectURL(asset.url);
            throw new Error('照片请求已取消');
          }
          this.resolved.set(photo.sha, asset);
          return asset;
        })
        .catch((error) => {
          this.assets.delete(photo.sha);
          throw error;
        });
      this.assets.set(photo.sha, request);
    }
    return this.assets.get(photo.sha)!;
  }

  clear() {
    this.generation += 1;
    for (const asset of this.resolved.values()) URL.revokeObjectURL(asset.url);
    this.assets.clear();
    this.resolved.clear();
  }
}
