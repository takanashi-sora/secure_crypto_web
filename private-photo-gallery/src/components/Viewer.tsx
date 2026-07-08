import { AnimatePresence, motion } from 'motion/react';
import { BookmarkCheck, ChevronLeft, ChevronRight, MapPin, Minus, Plus, Share2, Smile, Trash2, X } from 'lucide-react';
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
      location: photo.location ?? '',
      mood: photo.mood ?? '',
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

  return (
    <AnimatePresence>
      {photo && (
        <motion.div className="viewer" role="dialog" aria-modal="true" aria-label="照片与背面注记" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
          <button className="viewer-backdrop" onClick={onClose} aria-label="关闭照片" />
          <div className="viewer-stage">
            <header className="viewer-topbar">
              <div><small>PRIVATE PILGRIMAGE RECORD · {formatBytes(photo.size)}</small><strong>{photo.title || photo.name}</strong></div>
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
                  <p className="eyebrow">EDIT BACK NOTE</p>
                  <h2>补写照片背面的注记</h2>
                  <label>标题<input value={draft.title ?? ''} onChange={(event) => setDraft({ ...draft, title: event.target.value })} /></label>
                  <label>巡礼地点<input value={draft.location ?? ''} onChange={(event) => setDraft({ ...draft, location: event.target.value })} placeholder="例如：内浦长井崎" /></label>
                  <label>那天的心情<input value={draft.mood ?? ''} onChange={(event) => setDraft({ ...draft, mood: event.target.value })} placeholder="例如：海风很舒服" /></label>
                  <label>手账注记<textarea value={draft.description ?? ''} onChange={(event) => setDraft({ ...draft, description: event.target.value })} /></label>
                  <label>贴纸标签<input value={(draft.tags ?? []).join(', ')} onChange={(event) => setDraft({ ...draft, tags: event.target.value.split(',').map((tag) => tag.trim()).filter(Boolean) })} placeholder="海岸, 车站, 联动" /></label>
                  <label>巡礼日期<input type="datetime-local" value={(draft.capturedAt ?? '').slice(0, 16)} onChange={(event) => setDraft({ ...draft, capturedAt: event.target.value ? new Date(event.target.value).toISOString() : '' })} /></label>
                  {!!albums.length && <fieldset><legend>装订进旅程章节</legend>{albums.map((album) => <label className="check-row" key={album.id}><input type="checkbox" checked={(draft.albumIds ?? []).includes(album.id)} onChange={(event) => setDraft({ ...draft, albumIds: event.target.checked ? [...(draft.albumIds ?? []), album.id] : (draft.albumIds ?? []).filter((id) => id !== album.id) })} />{album.title}</label>)}</fieldset>}
                  <div className="form-actions"><button className="button button-primary" onClick={save}>保存背面注记</button><button className="button button-ghost" onClick={() => setEditing(false)}>取消</button></div>
                </div>
              ) : (
                <>
                  <div className="photo-date-stamp"><small>VISITED</small><strong>{displayDate(photo.capturedAt)}</strong></div>
                  <p className="caption-kicker">PHOTO BACK NOTE</p>
                  <h2>{photo.title || photo.name.replace(/\.[^.]+$/, '')}</h2>
                  <div className="back-meta"><span><MapPin />{photo.location || '地点尚未记录'}</span><span><Smile />{photo.mood || '心情尚未记录'}</span></div>
                  <div className="handwritten-note">{photo.description || '这张照片背面还没有注记。写下那天为什么按下快门，或当时想到的事情。'}</div>
                  <div className="tag-row">{photo.tags?.map((tag) => <span key={tag}>#{tag}</span>)}</div>
                  {!!chapterNames.length && <div className="bound-chapters"><small>装订章节</small>{chapterNames.map((name) => <span key={name}>{name}</span>)}</div>}
                  <div className="viewer-actions">
                    <button className={`keepsake-button ${photo.favorite ? 'active' : ''}`} onClick={() => void onSave(photo, { favorite: !photo.favorite })}><BookmarkCheck />{photo.favorite ? '已收入纪念册' : '收入纪念册'}</button>
                    <button className="button button-ghost" onClick={() => setEditing(true)}>补写背面注记</button>
                    <button className="round-action" onClick={share} aria-label="分享或下载"><Share2 /></button>
                  </div>
                  <button className="delete-record" onClick={() => void onDelete(photo)}><Trash2 />从档案中删除这张照片</button>
                </>
              )}
            </aside>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
