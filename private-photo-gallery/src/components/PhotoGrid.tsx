import { CloudAlert, Heart, MapPin } from 'lucide-react';
import { displayDate } from '../lib/format';
import type { PhotoAssetStore } from '../lib/github';
import type { AlbumRecord, PhotoRecord } from '../types';
import { PhotoImage } from './PhotoImage';

export type GalleryMode = 'editorial' | 'archive';

interface PhotoGridProps {
  photos: PhotoRecord[];
  assets: PhotoAssetStore;
  albums?: AlbumRecord[];
  mode?: GalleryMode;
  onOpen: (photo: PhotoRecord) => void;
  emptyMessage?: string;
}

export function PhotoGrid({ photos, assets, albums = [], mode = 'editorial', onOpen, emptyMessage }: PhotoGridProps) {
  if (!photos.length) {
    return <div className="empty-state"><span>°｡⋆</span><h3>这里还没有照片</h3><p>{emptyMessage ?? '换个筛选条件，或加入一张新的照片。'}</p></div>;
  }

  const albumNames = new Map(albums.map((album) => [album.id, album.title]));

  return (
    <div className={`photo-grid ${mode}`}>
      {photos.map((photo, index) => {
        const chapter = photo.albumIds?.map((id) => albumNames.get(id)).find(Boolean);
        const title = photo.title || photo.name.replace(/\.[^.]+$/, '');
        const archiveDetails = [photo.location, chapter, photo.mood].filter(Boolean);
        return (
          <article className={`record-card card-shape-${index % 7}`} key={photo.path}>
            <button className="record-photo" onClick={() => onOpen(photo)} aria-label={`查看 ${title}`}>
              <PhotoImage photo={photo} assets={assets} />
              {photo.favorite && <Heart className="favorite-mark" size={17} fill="currentColor" />}
              {photo.metadataPending && <CloudAlert className="pending-mark" size={17} aria-label="元数据等待同步" />}
            </button>
            <div className="record-slip">
              <div className="record-title"><strong>{title}</strong>{photo.capturedAt && <span>{displayDate(photo.capturedAt)}</span>}</div>
              {mode === 'editorial' ? (
                !!photo.tags?.length && <div className="editorial-tags">{photo.tags.slice(0, 2).map((tag) => <span key={tag}>#{tag}</span>)}</div>
              ) : (
                !!archiveDetails.length && <div className="record-context">
                  {photo.location && <span><MapPin size={13} />{photo.location}</span>}
                  {chapter && <span>{chapter}</span>}
                  {photo.mood && <span className="mood-sticker">{photo.mood}</span>}
                </div>
              )}
            </div>
          </article>
        );
      })}
    </div>
  );
}
