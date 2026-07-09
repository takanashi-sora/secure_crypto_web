import { AnimatePresence, motion } from 'motion/react';
import { BookmarkCheck, ChevronLeft, ChevronRight, MapPin, Minus, Plus, Share2, Smile, Trash2, X } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { displayDate, formatBytes } from '../lib/format';
import type { PhotoAssetStore } from '../lib/github';
import { DEFAULT_THEME, resolveTheme, themeOptions, type GalleryTheme } from '../themes';
import type { AlbumRecord, PhotoMetadata, PhotoRecord } from '../types';
import { PhotoImage } from './PhotoImage';

interface ViewerProps {
  photo?: PhotoRecord;
  photos: PhotoRecord[];
  albums: AlbumRecord[];
  assets: PhotoAssetStore;
  theme?: GalleryTheme;
  onClose: () => void;
  onSelect: (photo: PhotoRecord) => void;
  onSave: (photo: PhotoRecord, patch: PhotoMetadata) => Promise<void>;
  onDelete: (photo: PhotoRecord) => Promise<void>;
  notify: (message: string) => void;
}

export function Viewer({ photo, photos, albums, assets, theme = DEFAULT_THEME, onClose, onSelect, onSave, onDelete, notify }: ViewerProps) {
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
      location: photo.location ?? '',
      mood: photo.mood ?? '',
      tags: photo.tags ?? [],
      favorite: photo.favorite ?? false,
      themeId: photo.themeId ?? theme.id,
      capturedAt: photo.capturedAt ?? '',
      albumIds: photo.albumIds ?? [],
    });
  }, [photo]);

  useEffect(() => {
    if (!photo) return;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => { document.body.style.overflow = previousOverflow; };
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

  const chapterNames = photo?.albumIds?.map((id) => albums.find((album) => album.id === id)?.title).filter(Boolean) ?? [];
  const photoTheme = resolveTheme(photo?.themeId ?? theme.id);

  return (
    <AnimatePresence>
      {photo && (
        <motion.div className="viewer" role="dialog" aria-modal="true" aria-label="照片详情" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
          <button className="viewer-backdrop" onClick={onClose} aria-label="关闭照片" />
          <div className="viewer-stage">
            <header className="viewer-topbar">
              <div><small>PRIVATE PHOTO · {formatBytes(photo.size)}</small><strong>{photo.title || photo.name}</strong></div>
              <div className="icon-row">
                <button onClick={() => setScale((value) => Math.max(1, value - .25))} aria-label="缩小"><Minus /></button>
                <button onClick={() => setScale((value) => Math.min(3, value + .25))} aria-label="放大"><Plus /></button>
                <button onClick={share} aria-label="分享"><Share2 /></button>
                <button onClick={onClose} aria-label="关闭"><X /></button>
              </div>
            </header>

            <div className="viewer-photo-wrap" onPointerDown={(event) => { pointerStart.current = event.clientX; }} onPointerUp={(event) => { if (pointerStart.current === undefined) return; const distance = event.clientX - pointerStart.current; if (Math.abs(distance) > 70) move(distance > 0 ? -1 : 1); pointerStart.current = undefined; }}>
              <motion.div animate={{ scale }} transition={{ type: 'spring', stiffness: 220, damping: 24 }}><PhotoImage photo={photo} assets={assets} eager /></motion.div>
              {photos.length > 1 && <><button className="viewer-arrow prev" onClick={() => move(-1)} aria-label="上一张"><ChevronLeft /></button><button className="viewer-arrow next" onClick={() => move(1)} aria-label="下一张"><ChevronRight /></button></>}
            </div>

            <aside className={`viewer-caption photo-back ${editing ? 'editing' : ''}`}>
              {editing ? (
                <div className="editor-form">
                  <p className="eyebrow">{theme.viewer.editEyebrow}</p>
                  <h2>{theme.viewer.editTitle}</h2>
                  <label>标题<input value={draft.title ?? ''} onChange={(event) => setDraft({ ...draft, title: event.target.value })} /></label>
                  <label>{theme.viewer.themeLabel}<select value={draft.themeId ?? theme.id} onChange={(event) => setDraft({ ...draft, themeId: event.target.value })}>{themeOptions.map((item) => <option value={item.id} key={item.id}>{item.name}</option>)}</select></label>
                  <label>地点<input value={draft.location ?? ''} onChange={(event) => setDraft({ ...draft, location: event.target.value })} placeholder={theme.viewer.locationPlaceholder} /></label>
                  <label>那天的心情<input value={draft.mood ?? ''} onChange={(event) => setDraft({ ...draft, mood: event.target.value })} placeholder={theme.viewer.moodPlaceholder} /></label>
                  <label>文字注记<textarea value={draft.description ?? ''} onChange={(event) => setDraft({ ...draft, description: event.target.value })} /></label>
                  <label>标签<input value={(draft.tags ?? []).join(', ')} onChange={(event) => setDraft({ ...draft, tags: event.target.value.split(',').map((tag) => tag.trim()).filter(Boolean) })} placeholder={theme.viewer.tagsPlaceholder} /></label>
                  <label>拍摄日期<input type="datetime-local" value={(draft.capturedAt ?? '').slice(0, 16)} onChange={(event) => setDraft({ ...draft, capturedAt: event.target.value ? new Date(event.target.value).toISOString() : '' })} /></label>
                  {!!albums.length && <fieldset><legend>加入旅程相册</legend>{albums.map((album) => <label className="check-row" key={album.id}><input type="checkbox" checked={(draft.albumIds ?? []).includes(album.id)} onChange={(event) => setDraft({ ...draft, albumIds: event.target.checked ? [...(draft.albumIds ?? []), album.id] : (draft.albumIds ?? []).filter((id) => id !== album.id) })} />{album.title}</label>)}</fieldset>}
                  <div className="form-actions"><button className="button button-primary" onClick={save}>保存注记</button><button className="button button-ghost" onClick={() => setEditing(false)}>取消</button></div>
                </div>
              ) : (
                <>
                  <div className="photo-back-stickers" aria-hidden="true"><span>✦</span><span>{photoTheme.shortName}</span></div>
                  {photo.capturedAt && <div className="photo-date-stamp"><small>CAPTURED</small><strong>{displayDate(photo.capturedAt)}</strong></div>}
                  <p className="caption-kicker">{theme.viewer.noteKicker}</p>
                  <h2>{photo.title || photo.name.replace(/\.[^.]+$/, '')}</h2>
                  {(photo.location || photo.mood) && <div className="back-meta">{photo.location && <span><MapPin />{photo.location}</span>}{photo.mood && <span><Smile />{photo.mood}</span>}</div>}
                  {photo.description && <div className="handwritten-note">{photo.description}</div>}
                  <div className="tag-row">{photo.tags?.map((tag) => <span key={tag}>#{tag}</span>)}</div>
                  {!!chapterNames.length && <div className="bound-chapters"><small>{theme.viewer.chaptersLabel}</small>{chapterNames.map((name) => <span key={name}>{name}</span>)}</div>}
                  <div className="viewer-actions">
                    <button className={`keepsake-button ${photo.favorite ? 'active' : ''}`} onClick={() => void onSave(photo, { favorite: !photo.favorite })}><BookmarkCheck />{photo.favorite ? theme.viewer.favoriteOn : theme.viewer.favoriteOff}</button>
                    <button className="button button-ghost" onClick={() => setEditing(true)}>{theme.viewer.editButton}</button>
                    <button className="round-action" onClick={share} aria-label="分享或下载"><Share2 /></button>
                  </div>
                  <button className="delete-record" onClick={() => void onDelete(photo)}><Trash2 />删除这张照片</button>
                </>
              )}
            </aside>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
