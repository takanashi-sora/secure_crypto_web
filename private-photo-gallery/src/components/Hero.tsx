import { ArrowRight, CalendarDays, KeyRound, MapPin, Sparkles, Waves } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { displayDate } from '../lib/format';
import type { PhotoAssetStore } from '../lib/github';
import type { ConnectionState, PhotoRecord } from '../types';
import { PhotoImage } from './PhotoImage';

interface HeroProps {
  photos: PhotoRecord[];
  assets: PhotoAssetStore;
  state: ConnectionState;
  onOpen: (photo: PhotoRecord) => void;
}

export function Hero({ photos, assets, state, onOpen }: HeroProps) {
  const [active, setActive] = useState(0);
  const current = photos[active % Math.max(photos.length, 1)];
  const smallPhotos = photos.filter((photo) => photo.path !== current?.path).slice(0, 2);
  const latestLabel = current?.capturedAt ? displayDate(current.capturedAt) : 'today';

  useEffect(() => setActive(0), [photos]);

  return (
    <section className="memory-hero sora-cover">
      <div className="hero-scene" aria-hidden="true">
        <span className="hero-sky" />
        <span className="hero-mountain mountain-left" />
        <span className="hero-mountain mountain-right" />
        <span className="hero-sea" />
        <span className="hero-pier" />
        <span className="hero-wind hero-wind-a" />
        <span className="hero-wind hero-wind-b" />
        <span className="hero-star">✦</span>
      </div>
      <div className="hero-copy">
        <div className="soft-kicker"><span className="mikan-dot" /> takanashi.moe photo room <Sparkles size={14} /></div>
        <h1>海边的光，<br /><em>放进小相册。</em></h1>
        <p className="hero-intro">不是作品集，也不是后台。这里放着旅途中遇见的海风、车站旁的光、顺手买下的小东西，以及只有自己知道为什么会想念的照片。</p>
        <div className="hero-micro-notes" aria-label="照片空间氛围">
          <span>after school light</span>
          <span>sea breeze</span>
          <span>mikan memo</span>
        </div>
        <div className="hero-actions">
          <Link className="button button-primary" to={state === 'connected' ? '/library' : '/settings'}>
            {state === 'connected' ? '慢慢翻照片' : '连接私人空间'} <ArrowRight size={17} />
          </Link>
          <Link className="text-link" to="/upload">把今天也放进去</Link>
        </div>
        <div className={`privacy-chip ${state === 'connected' ? 'connected' : ''}`}>
          {state === 'connected' ? <Waves size={16} /> : <KeyRound size={16} />}
          <span>{state === 'connected' ? `${photos.length} 张照片 · 安静收在私有仓库` : '照片只从你的私有仓库读取'}</span>
        </div>
      </div>

      <div className="hero-gallery">
        <div className="cover-board">
          <div className="board-pin pin-a" />
          <div className="board-pin pin-b" />
        {current ? (
          <button className="hero-photo-button" onClick={() => onOpen(current)} aria-label={`查看 ${current.title ?? current.name}`}>
            <PhotoImage photo={current} assets={assets} eager />
            <span className="hero-photo-shine" />
            <span className="photo-caption-strip">
              <strong>{current.title || current.name.replace(/\.[^.]+$/, '')}</strong>
              <span>{[current.location, current.capturedAt ? displayDate(current.capturedAt) : ''].filter(Boolean).join(' · ')}</span>
            </span>
          </button>
        ) : (
          <div className="coastline-art" aria-label="海边相册占位插画">
            <span className="sun-disc" />
            <span className="mountain mountain-one" />
            <span className="mountain mountain-two" />
            <span className="sea-line line-one" />
            <span className="sea-line line-two" />
            <span className="pier-line" />
            <span className="empty-coast-copy"><MapPin size={16} /> 下一段海风，会从这里开始</span>
          </div>
        )}

          {!!smallPhotos.length && (
            <div className="mini-photo-stack" aria-label="最近照片缩略图">
              {smallPhotos.map((photo, index) => (
                <button key={photo.path} className={`hero-mini-photo mini-${index}`} onClick={() => onOpen(photo)} aria-label={`查看 ${photo.title ?? photo.name}`}>
                  <PhotoImage photo={photo} assets={assets} />
                </button>
              ))}
            </div>
          )}

          <div className="hero-note-card">
            <small><CalendarDays size={13} /> latest page</small>
            <strong>{latestLabel}</strong>
            <span>今天也把一点光留下。</span>
          </div>

        {photos.length > 1 && (
          <div className="chapter-tabs" aria-label="最近照片">
            {photos.slice(0, 5).map((photo, index) => (
              <button key={photo.path} className={index === active ? 'active' : ''} onClick={() => setActive(index)} aria-label={`切换到 ${photo.title ?? photo.name}`}>
                <PhotoImage photo={photo} assets={assets} />
              </button>
            ))}
          </div>
        )}
        </div>
      </div>
    </section>
  );
}
