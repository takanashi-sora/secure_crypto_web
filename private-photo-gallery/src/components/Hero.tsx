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
        <span className="hero-coast-road" />
        <span className="hero-guardrail" />
        <span className="hero-stop-marker" />
        <span className="hero-slope-line" />
        <span className="hero-room-window" />
        <span className="hero-timetable-ghost" />
        <span className="hero-wind hero-wind-a" />
        <span className="hero-wind hero-wind-b" />
        <span className="hero-star">✦</span>
      </div>
      <div className="hero-copy">
        <div className="soft-kicker"><span className="mikan-dot" /> takanashi.moe private gate <Sparkles size={14} /></div>
        <h1>推开门，<br /><em>海风在放学后。</em></h1>
        <p className="hero-intro">这里不是官方主题页，也不是普通相册。它更像我自己的入口：把海边道路、站牌、练习后的光、顺手带回的小东西，和那些只属于自己的照片，一起贴进这个房间。</p>
        <div className="hero-micro-notes" aria-label="照片空间氛围">
          <span>放課後</span>
          <span>海辺の町</span>
          <span>route note</span>
        </div>
        <div className="hero-actions">
          <Link className="button button-primary" to={state === 'connected' ? '/library' : '/settings'}>
            {state === 'connected' ? '走进照片墙' : '连接私人入口'} <ArrowRight size={17} />
          </Link>
          <Link className="text-link" to="/upload">把今天带回房间</Link>
        </div>
        <div className={`privacy-chip ${state === 'connected' ? 'connected' : ''}`}>
          {state === 'connected' ? <Waves size={16} /> : <KeyRound size={16} />}
          <span>{state === 'connected' ? `${photos.length} 张照片 · 只在你的私有仓库里亮着` : '入口会从你的私有仓库读取照片'}</span>
        </div>
      </div>

      <div className="hero-gallery">
        <div className="cover-board">
          <div className="board-label"><span>club room wall</span><small>after school / sea breeze</small></div>
          <div className="clubroom-window" aria-hidden="true"><span /><span /></div>
          <div className="timetable-card" aria-hidden="true">
            <small>BUS STOP</small>
            <span>07:42</span>
            <span>16:18</span>
            <span>18:03</span>
          </div>
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
            <span className="empty-coast-copy"><MapPin size={16} /> 第一张照片会成为入口</span>
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
            <small><CalendarDays size={13} /> after school memo</small>
            <strong>{latestLabel}</strong>
            <span>练习后的风、海边路的白线，还有今天想留下的那一张。</span>
          </div>

          <div className="route-memo-card">
            <small>ROUTE NOTE</small>
            <strong>坂道 → 海边路 → 小码头</strong>
            <span>下一页从这里走进去。</span>
          </div>

        {photos.length > 1 && (
          <div className="chapter-tabs" aria-label="照片墙上的最近照片">
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
