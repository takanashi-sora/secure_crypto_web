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
    return <div className="empty-state"><span>記</span><h3>这一页还没有巡礼记录</h3><p>{emptyMessage ?? '换个筛选条件，或把新的记忆收入档案柜。'}</p></div>;
  }

  const albumNames = new Map(albums.map((album) => [album.id, album.title]));

  return (
    <div className={`photo-grid ${mode}`}>
      {photos.map((photo, index) => {
        const chapter = photo.albumIds?.map((id) => albumNames.get(id)).find(Boolean);
        const frame = String(index + 1).padStart(3, '0');
        return (
          <article className={`record-card card-shape-${index % 7}`} key={photo.path}>
            <button className="record-photo" onClick={() => onOpen(photo)} aria-label={`查看 ${photo.title ?? photo.name}`}>
              <PhotoImage photo={photo} assets={assets} />
              <span className="frame-code">P-{frame}</span>
              {photo.favorite && <Heart className="favorite-mark" size={17} fill="currentColor" />}
              {photo.metadataPending && <CloudAlert className="pending-mark" size={17} aria-label="元数据等待同步" />}
            </button>
            <div className="record-slip">
              <div className="record-title"><strong>{photo.title || photo.name.replace(/\.[^.]+$/, '')}</strong><span>{displayDate(photo.capturedAt)}</span></div>
              <div className="record-context"><span><MapPin size={13} />{photo.location || '地点未记录'}</span>{photo.mood && <span className="mood-sticker">{photo.mood}</span>}</div>
              <div className="record-footer"><span>{chapter ? `旅程：${chapter}` : '未归入旅程章节'}</span><code>FRAME {frame}</code></div>
            </div>
          </article>
        );
      })}
    </div>
  );
}
