import { AnimatePresence, motion } from 'motion/react';
import {
  ChevronLeft,
  ChevronRight,
  Download,
  Heart,
  Minus,
  Plus,
  Share2,
  Trash2,
  X,
} from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { displayDate, formatBytes } from '../lib/format';
import type { PhotoAssetStore } from '../lib/github';
import type { AlbumRecord, PhotoMetadata, PhotoRecord } from '../types';
import { PhotoImage } from './PhotoImage';

interface ViewerProps {
  photo?: PhotoRecord;
  photos: PhotoRecord[];
  albums: AlbumRecord[];
  assets: PhotoAssetStore;
  onClose: () => void;
  onSelect: (photo: PhotoRecord) => void;
  onSave: (photo: PhotoRecord, patch: PhotoMetadata) => Promise<void>;
  onDelete: (photo: PhotoRecord) => Promise<void>;
  notify: (message: string) => void;
}

export function Viewer({ photo, photos, albums, assets, onClose, onSelect, onSave, onDelete, notify }: ViewerProps) {
  const [editing, setEditing] = useState(false);
  const [scale, setScale] = useState(1);
  const pointerStart = useRef<number>();
  const [draft, setDraft] = useState<PhotoMetadata>({});

  useEffect(() => {
    if (!photo) return;
    setScale(1);
    setEditing(false);
    setDraft({
      title: photo.title ?? '',
      description: photo.description ?? '',
      tags: photo.tags ?? [],
      favorite: photo.favorite ?? false,
      capturedAt: photo.capturedAt ?? '',
      albumIds: photo.albumIds ?? [],
    });
  }, [photo]);

  useEffect(() => {
    if (!photo) return;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = previousOverflow;
    };
  }, [photo]);

  const move = (direction: number) => {
    if (!photo) return;
    const index = photos.findIndex((item) => item.path === photo.path);
    const next = photos[(index + direction + photos.length) % photos.length];
    if (next) onSelect(next);
  };

  useEffect(() => {
    if (!photo) return;
    const handler = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
      if (!editing && event.key === 'ArrowLeft') move(-1);
      if (!editing && event.key === 'ArrowRight') move(1);
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  });

  const share = async () => {
    if (!photo) return;
    try {
      const asset = await assets.get(photo);
      const file = new File([asset.blob], photo.name, { type: asset.blob.type });
      if (navigator.share && (!navigator.canShare || navigator.canShare({ files: [file] }))) {
        await navigator.share({ title: photo.title ?? photo.name, text: photo.description, files: [file] });
        return;
      }
      const link = document.createElement('a');
      link.href = asset.url;
      link.download = photo.name;
      link.click();
      notify('当前浏览器不支持系统分享，已改为下载照片。');
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') return;
      notify(error instanceof Error ? `分享失败：${error.message}` : '分享失败，请稍后重试。');
    }
  };

  const save = async () => {
    if (!photo) return;
    await onSave(photo, draft);
    setEditing(false);
  };

  return (
    <AnimatePresence>
      {photo && (
        <motion.div className="viewer" role="dialog" aria-modal="true" aria-label="照片预览" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
          <button className="viewer-backdrop" onClick={onClose} aria-label="关闭照片" />
          <div className="viewer-stage">
            <header className="viewer-topbar">
              <div>
                <small>{displayDate(photo.capturedAt)}</small>
                <strong>{photo.title || photo.name}</strong>
              </div>
              <div className="icon-row">
                <button onClick={() => setScale((value) => Math.max(1, value - 0.25))} aria-label="缩小"><Minus /></button>
                <button onClick={() => setScale((value) => Math.min(3, value + 0.25))} aria-label="放大"><Plus /></button>
                <button onClick={share} aria-label="分享"><Share2 /></button>
                <button onClick={onClose} aria-label="关闭"><X /></button>
              </div>
            </header>

            <div
              className="viewer-photo-wrap"
              onPointerDown={(event) => { pointerStart.current = event.clientX; }}
              onPointerUp={(event) => {
                if (pointerStart.current === undefined) return;
                const distance = event.clientX - pointerStart.current;
                if (Math.abs(distance) > 70) move(distance > 0 ? -1 : 1);
                pointerStart.current = undefined;
              }}
            >
              <motion.div animate={{ scale }} transition={{ type: 'spring', stiffness: 220, damping: 24 }}>
                <PhotoImage photo={photo} assets={assets} eager />
              </motion.div>
              {photos.length > 1 && (
                <>
                  <button className="viewer-arrow prev" onClick={() => move(-1)} aria-label="上一张"><ChevronLeft /></button>
                  <button className="viewer-arrow next" onClick={() => move(1)} aria-label="下一张"><ChevronRight /></button>
                </>
              )}
            </div>

            <aside className={`viewer-caption ${editing ? 'editing' : ''}`}>
              {editing ? (
                <div className="editor-form">
                  <label>标题<input value={draft.title ?? ''} onChange={(e) => setDraft({ ...draft, title: e.target.value })} /></label>
                  <label>说明<textarea value={draft.description ?? ''} onChange={(e) => setDraft({ ...draft, description: e.target.value })} /></label>
                  <label>标签<input value={(draft.tags ?? []).join(', ')} onChange={(e) => setDraft({ ...draft, tags: e.target.value.split(',').map((tag) => tag.trim()).filter(Boolean) })} placeholder="海岸, 沼津, 旅行" /></label>
                  <label>拍摄日期<input type="datetime-local" value={(draft.capturedAt ?? '').slice(0, 16)} onChange={(e) => setDraft({ ...draft, capturedAt: e.target.value ? new Date(e.target.value).toISOString() : '' })} /></label>
                  {!!albums.length && (
                    <fieldset>
                      <legend>加入相册</legend>
                      {albums.map((album) => (
                        <label className="check-row" key={album.id}>
                          <input
                            type="checkbox"
                            checked={(draft.albumIds ?? []).includes(album.id)}
                            onChange={(event) => setDraft({
                              ...draft,
                              albumIds: event.target.checked
                                ? [...(draft.albumIds ?? []), album.id]
                                : (draft.albumIds ?? []).filter((id) => id !== album.id),
                            })}
                          />
                          {album.title}
                        </label>
                      ))}
                    </fieldset>
                  )}
                  <div className="form-actions"><button className="button button-primary" onClick={save}>保存信息</button><button className="button button-ghost" onClick={() => setEditing(false)}>取消</button></div>
                </div>
              ) : (
                <>
                  <p className="caption-kicker">PRIVATE FRAME · {formatBytes(photo.size)}</p>
                  <h2>{photo.title || photo.name.replace(/\.[^.]+$/, '')}</h2>
                  <p>{photo.description || '这一帧还没有文字。给它留下一段只属于你的注释。'}</p>
                  <div className="tag-row">{photo.tags?.map((tag) => <span key={tag}>#{tag}</span>)}</div>
                  <div className="viewer-actions">
                    <button className="button button-light" onClick={() => setEditing(true)}>编辑照片信息</button>
                    <button className="round-action" onClick={() => onSave(photo, { favorite: !photo.favorite })} aria-label="收藏">
                      <Heart fill={photo.favorite ? 'currentColor' : 'none'} />
                    </button>
                    <button className="round-action" onClick={share} aria-label="下载或分享"><Download /></button>
                    <button className="round-action danger" onClick={() => onDelete(photo)} aria-label="删除"><Trash2 /></button>
                  </div>
                </>
              )}
            </aside>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
