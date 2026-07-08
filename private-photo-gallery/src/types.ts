export type ConnectionState = 'idle' | 'loading' | 'connected' | 'error';

export interface GallerySettings {
  token: string;
  owner: string;
  repo: string;
  branch: string;
  folder: string;
  rememberToken: boolean;
}

export interface AlbumRecord {
  id: string;
  title: string;
  description: string;
  coverPath?: string;
  createdAt: string;
}

export interface PhotoMetadata {
  title?: string;
  description?: string;
  location?: string;
  mood?: string;
  tags?: string[];
  favorite?: boolean;
  capturedAt?: string;
  albumIds?: string[];
  width?: number;
  height?: number;
  metadataPending?: boolean;
}

export interface PhotoRecord extends PhotoMetadata {
  path: string;
  name: string;
  sha: string;
  size: number;
}

export interface VaultManifestV1 {
  schemaVersion: 1;
  updatedAt: string;
  albums: AlbumRecord[];
  photos: Record<string, PhotoMetadata>;
  heroPaths: string[];
}

export interface ManifestSnapshot {
  manifest: VaultManifestV1;
  sha?: string;
}

export interface UploadCandidate {
  id: string;
  file: File;
  previewUrl: string;
  targetName: string;
  capturedAt?: string;
  width?: number;
  height?: number;
}

export interface UploadResult {
  candidate: UploadCandidate;
  photo?: PhotoRecord;
  error?: string;
}

export interface PhotoAsset {
  blob: Blob;
  url: string;
}

export interface RepositoryClient {
  listPhotos(): Promise<PhotoRecord[]>;
  loadManifest(): Promise<ManifestSnapshot>;
  updateManifest(
    mutate: (manifest: VaultManifestV1) => VaultManifestV1,
  ): Promise<ManifestSnapshot>;
  loadPhotoAsset(photo: PhotoRecord): Promise<PhotoAsset>;
  uploadPhoto(candidate: UploadCandidate): Promise<PhotoRecord>;
  deletePhoto(photo: PhotoRecord): Promise<void>;
}
