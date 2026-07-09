import { CloudAlert, Heart, MapPin } from 'lucide-react';
import { displayDate } from '../lib/format';
import type { PhotoAssetStore } from '../lib/github';
import { DEFAULT_THEME, resolveTheme, type GalleryTheme } from '../themes';
import type { AlbumRecord, PhotoRecord } from '../types';
import { PhotoImage } from './PhotoImage';

export type GalleryMode = 'editorial' | 'archive';

interface PhotoGridProps {
  photos: PhotoRecord[];
  assets: PhotoAssetStore;
  albums?: AlbumRecord[];
  mode?: GalleryMode;
  theme?: GalleryTheme;
  onOpen: (photo: PhotoRecord) => void;
  emptyMessage?: string;
}

export function PhotoGrid({ photos, assets, albums = [], mode = 'editorial', theme = DEFAULT_THEME, onOpen, emptyMessage }: PhotoGridProps) {
  if (!photos.length) {
    return <div className="empty-state"><span>°｡⋆</span><h3>{theme.photoGrid.emptyTitle}</h3><p>{emptyMessage ?? theme.photoGrid.emptyDefault}</p></div>;
  }

  const albumNames = new Map(albums.map((album) => [album.id, album.title]));

  return (
    <div className={`photo-grid ${mode}`}>
      {photos.map((photo, index) => {
        const chapter = photo.albumIds?.map((id) => albumNames.get(id)).find(Boolean);
        const title = photo.title || photo.name.replace(/\.[^.]+$/, '');
        const photoTheme = resolveTheme(photo.themeId);
        const archiveDetails = [photo.location, chapter, photo.mood, photo.themeId].filter(Boolean);
        return (
          <article className={`record-card tone-${index % 4} card-shape-${index % 7}`} data-photo-theme={photoTheme.id} key={photo.path}>
            <span className="record-wall-pin" aria-hidden="true" />
            <button className="record-photo" onClick={() => onOpen(photo)} aria-label={`查看 ${title}`}>
              <PhotoImage photo={photo} assets={assets} />
              <span className="photo-washi" />
              <span className="record-glimmer" />
              <span className="memory-index">{mode === 'archive' ? String(index + 1).padStart(3, '0') : theme.photoGrid.memoryBadge}</span>
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
                  {photo.themeId && <span>{photoTheme.shortName}</span>}
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
