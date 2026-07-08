import type { PhotoMetadata, PhotoRecord, VaultManifestV1 } from '../types';

export function createEmptyManifest(): VaultManifestV1 {
  return {
    schemaVersion: 1,
    updatedAt: new Date().toISOString(),
    albums: [],
    photos: {},
    heroPaths: [],
  };
}

export function normalizeManifest(value: unknown): VaultManifestV1 {
  if (!value || typeof value !== 'object') return createEmptyManifest();
  const raw = value as Partial<VaultManifestV1>;
  if (raw.schemaVersion !== 1) {
    throw new Error(`不支持的相册元数据版本：${String(raw.schemaVersion ?? '未知')}`);
  }

  return {
    schemaVersion: 1,
    updatedAt: typeof raw.updatedAt === 'string' ? raw.updatedAt : new Date().toISOString(),
    albums: Array.isArray(raw.albums)
      ? raw.albums.filter(
          (album) =>
            album &&
            typeof album.id === 'string' &&
            typeof album.title === 'string' &&
            typeof album.createdAt === 'string',
        )
      : [],
    photos: raw.photos && typeof raw.photos === 'object' ? raw.photos : {},
    heroPaths: Array.isArray(raw.heroPaths)
      ? raw.heroPaths.filter((path): path is string => typeof path === 'string')
      : [],
  };
}

export function mergePhotos(
  repositoryPhotos: PhotoRecord[],
  manifest: VaultManifestV1,
): PhotoRecord[] {
  return repositoryPhotos.map((photo) => ({
    ...photo,
    ...(manifest.photos[photo.path] ?? {}),
  }));
}

export function updatePhotoMetadata(
  manifest: VaultManifestV1,
  path: string,
  patch: PhotoMetadata,
): VaultManifestV1 {
  const current = manifest.photos[path] ?? {};
  const metadata = { ...current, ...patch };
  metadata.tags = [...new Set((metadata.tags ?? []).map((tag) => tag.trim()).filter(Boolean))];
  metadata.albumIds = [...new Set(metadata.albumIds ?? [])];

  return {
    ...manifest,
    updatedAt: new Date().toISOString(),
    photos: { ...manifest.photos, [path]: metadata },
  };
}

export function removePhotoMetadata(
  manifest: VaultManifestV1,
  path: string,
): VaultManifestV1 {
  const photos = { ...manifest.photos };
  delete photos[path];
  return {
    ...manifest,
    updatedAt: new Date().toISOString(),
    photos,
    heroPaths: manifest.heroPaths.filter((item) => item !== path),
    albums: manifest.albums.map((album) =>
      album.coverPath === path ? { ...album, coverPath: undefined } : album,
    ),
  };
}

export function getHeroPhotos(photos: PhotoRecord[], manifest: VaultManifestV1) {
  const byPath = new Map(photos.map((photo) => [photo.path, photo]));
  const curated = manifest.heroPaths.map((path) => byPath.get(path)).filter(Boolean) as PhotoRecord[];
  const fallback = photos.filter((photo) => !curated.some((item) => item.path === photo.path));
  return [...curated, ...fallback].slice(0, 5);
}
