import { ArrowRight, KeyRound, MapPin, Sparkles, Waves } from 'lucide-react';
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

  useEffect(() => setActive(0), [photos]);

  return (
    <section className="memory-hero">
      <div className="hero-copy">
        <div className="soft-kicker"><Sparkles size={14} /> PRIVATE PHOTO SPACE</div>
        <h1>海风经过，<br /><em>照片留下。</em></h1>
        <p className="hero-intro">这里收着海边的风、放学后的天空，还有旅途中偶然遇见的颜色。想念的时候，就回来慢慢翻一翻。</p>
        <div className="hero-actions">
          <Link className="button button-primary" to={state === 'connected' ? '/library' : '/settings'}>
            {state === 'connected' ? '翻看全部照片' : '连接私人空间'} <ArrowRight size={17} />
          </Link>
          <Link className="text-link" to="/upload">加入新照片</Link>
        </div>
        <div className={`privacy-chip ${state === 'connected' ? 'connected' : ''}`}>
          {state === 'connected' ? <Waves size={16} /> : <KeyRound size={16} />}
          <span>{state === 'connected' ? `${photos.length} 张照片 · 私密连接中` : '照片只从你的私有仓库读取'}</span>
        </div>
      </div>

      <div className="hero-gallery">
        <div className="hero-glow" />
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
    </section>
  );
}
