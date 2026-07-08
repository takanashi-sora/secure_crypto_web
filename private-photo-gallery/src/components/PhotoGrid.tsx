import { motion } from 'motion/react';
import { CloudAlert, Heart, Maximize2 } from 'lucide-react';
import { displayDate } from '../lib/format';
import type { PhotoAssetStore } from '../lib/github';
import type { PhotoRecord } from '../types';
import { PhotoImage } from './PhotoImage';

interface PhotoGridProps {
  photos: PhotoRecord[];
  assets: PhotoAssetStore;
  onOpen: (photo: PhotoRecord) => void;
  emptyMessage?: string;
}

export function PhotoGrid({ photos, assets, onOpen, emptyMessage }: PhotoGridProps) {
  if (!photos.length) {
    return (
      <div className="empty-state">
        <span>○</span>
        <h3>这一页还没有照片</h3>
        <p>{emptyMessage ?? '换个筛选条件，或上传一段新的记忆。'}</p>
      </div>
    );
  }

  return (
    <div className="photo-grid">
      {photos.map((photo, index) => (
        <motion.article
          layout
          className={`photo-card card-shape-${index % 7}`}
          key={photo.path}
          initial={{ opacity: 0, y: 22 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '120px' }}
          transition={{ duration: 0.45, delay: Math.min(index * 0.025, 0.25) }}
        >
          <button className="photo-card-button" onClick={() => onOpen(photo)} aria-label={`查看 ${photo.title ?? photo.name}`}>
            <PhotoImage photo={photo} assets={assets} />
            <span className="photo-card-shade" />
            <span className="photo-card-index">{String(index + 1).padStart(2, '0')}</span>
            {photo.favorite && <Heart className="favorite-mark" size={18} fill="currentColor" />}
            {photo.metadataPending && (
              <CloudAlert className="pending-mark" size={18} aria-label="元数据等待同步" />
            )}
            <span className="photo-card-copy">
              <strong>{photo.title || photo.name.replace(/\.[^.]+$/, '')}</strong>
              <small>{displayDate(photo.capturedAt)}</small>
            </span>
            <Maximize2 className="expand-mark" size={18} />
          </button>
        </motion.article>
      ))}
    </div>
  );
}
