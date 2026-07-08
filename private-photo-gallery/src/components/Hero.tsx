import { Archive, ArrowRight, CalendarDays, KeyRound, MapPinned } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { displayDate, formatBytes } from '../lib/format';
import type { PhotoAssetStore } from '../lib/github';
import type { ConnectionState, PhotoRecord } from '../types';
import { PhotoImage } from './PhotoImage';

interface HeroProps {
  photos: PhotoRecord[];
  assets: PhotoAssetStore;
  state: ConnectionState;
  totalSize: number;
  onOpen: (photo: PhotoRecord) => void;
}

export function Hero({ photos, assets, state, totalSize, onOpen }: HeroProps) {
  const [active, setActive] = useState(0);
  const current = photos[active % Math.max(photos.length, 1)];

  useEffect(() => setActive(0), [photos]);

  return (
    <section className="memory-hero">
      <div className="album-page photo-page">
        <div className="page-corner">NUMAZU / PRIVATE RECORD</div>
        {current ? (
          <button className="hero-photo-button" onClick={() => onOpen(current)}>
            <PhotoImage photo={current} assets={assets} eager />
            <span className="film-frame-number">巡礼格 {String(active + 1).padStart(2, '0')}</span>
          </button>
        ) : (
          <div className="coastline-art" aria-label="沼津海岸占位插画">
            <span className="sun-disc" />
            <span className="mountain mountain-one" />
            <span className="mountain mountain-two" />
            <span className="sea-line line-one" />
            <span className="sea-line line-two" />
          </div>
        )}
        <div className="photo-caption-strip">
          <MapPinned size={16} />
          <span>{current?.location || '地点尚未记录'}</span>
          <time>{displayDate(current?.capturedAt)}</time>
        </div>
      </div>

      <div className="album-page ledger-page">
        <div className="date-stamp"><CalendarDays size={16} /> PERSONAL PILGRIMAGE LOG</div>
        <p className="issue-line">MEMORY BOOK · FILE 01</p>
        <h1>沼津巡礼<br /><em>记忆簿</em></h1>
        <p className="hero-intro">把走过的海岸、车站、联动、周边与那天的心情，按旅程收进一本只属于自己的手账。</p>

        <div className="ticket-facts">
          <div><small>收录照片</small><strong>{photos.length}</strong></div>
          <div><small>档案容量</small><strong>{formatBytes(totalSize)}</strong></div>
          <div className={state === 'connected' ? 'connected' : ''}>
            {state === 'connected' ? <Archive size={18} /> : <KeyRound size={18} />}
            <span>{state === 'connected' ? '私有档案已开启' : '等待连接私有仓库'}</span>
          </div>
        </div>

        <div className="hero-actions">
          <Link className="button button-primary" to={state === 'connected' ? '/library' : '/settings'}>
            {state === 'connected' ? '打开档案柜' : '连接私有仓库'} <ArrowRight size={17} />
          </Link>
          <Link className="text-link" to="/upload">收入新照片</Link>
        </div>

        {photos.length > 1 && (
          <div className="chapter-tabs" aria-label="最近照片">
            {photos.map((photo, index) => (
              <button key={photo.path} className={index === active ? 'active' : ''} onClick={() => setActive(index)}>
                <span>{String(index + 1).padStart(2, '0')}</span>
                <em>{photo.location || photo.title || photo.name.replace(/\.[^.]+$/, '')}</em>
              </button>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
