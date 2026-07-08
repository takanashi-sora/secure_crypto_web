import { describe, expect, it } from 'vitest';
import {
  createEmptyManifest,
  getHeroPhotos,
  mergePhotos,
  normalizeManifest,
  removePhotoMetadata,
  updatePhotoMetadata,
} from './manifest';
import type { PhotoRecord } from '../types';

const photos: PhotoRecord[] = [
  { path: 'photos/sea.jpg', name: 'sea.jpg', sha: 'sea', size: 100 },
  { path: 'photos/train.jpg', name: 'train.jpg', sha: 'train', size: 200 },
];

describe('vault manifest', () => {
  it('normalizes missing data and rejects unsupported manifest versions', () => {
    expect(normalizeManifest(null).schemaVersion).toBe(1);
    expect(() => normalizeManifest({ schemaVersion: 2 })).toThrow('不支持的相册元数据版本');
  });

  it('deduplicates tags and album ids when metadata changes', () => {
    const next = updatePhotoMetadata(createEmptyManifest(), photos[0].path, {
      title: '海边',
      tags: [' 沼津 ', '海边', '沼津'],
      albumIds: ['summer', 'summer'],
    });

    expect(next.photos[photos[0].path]).toMatchObject({
      title: '海边',
      tags: ['沼津', '海边'],
      albumIds: ['summer'],
    });
  });

  it('merges repository facts with editable metadata', () => {
    const manifest = updatePhotoMetadata(createEmptyManifest(), photos[1].path, {
      title: '海岸列车',
      location: '沼津站',
      mood: '终于抵达',
      favorite: true,
    });

    expect(mergePhotos(photos, manifest)[1]).toMatchObject({
      sha: 'train',
      title: '海岸列车',
      location: '沼津站',
      mood: '终于抵达',
      favorite: true,
    });
  });

  it('prefers curated hero paths and removes stale references on deletion', () => {
    const manifest = {
      ...createEmptyManifest(),
      heroPaths: [photos[1].path],
      photos: { [photos[1].path]: { title: '封面' } },
    };

    expect(getHeroPhotos(photos, manifest)[0].path).toBe(photos[1].path);
    expect(removePhotoMetadata(manifest, photos[1].path).heroPaths).toEqual([]);
  });
});
