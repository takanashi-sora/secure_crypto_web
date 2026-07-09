import { ArrowRight, CalendarDays, KeyRound, MapPin, Sparkles, Waves } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { displayDate } from '../lib/format';
import type { PhotoAssetStore } from '../lib/github';
import { themedAsset, type GalleryTheme } from '../themes';
import type { ConnectionState, PhotoRecord } from '../types';
import { PhotoImage } from './PhotoImage';

interface HeroProps {
  photos: PhotoRecord[];
  assets: PhotoAssetStore;
  state: ConnectionState;
  theme: GalleryTheme;
  onOpen: (photo: PhotoRecord) => void;
}

export function Hero({ photos, assets, state, theme, onOpen }: HeroProps) {
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
        <div className="soft-kicker"><span className="mikan-dot" /> {theme.hero.kicker} <Sparkles size={14} /></div>
        <h1>{theme.hero.title}<br /><em>{theme.hero.emphasis}</em></h1>
        <p className="hero-intro">{theme.hero.intro}</p>
        <div className="hero-micro-notes" aria-label="照片空间氛围">
          {theme.hero.notes.map((note) => <span key={note}>{note}</span>)}
        </div>
        <div className="hero-actions">
          <Link className="button button-primary" to={state === 'connected' ? '/library' : '/settings'}>
            {state === 'connected' ? theme.hero.ctaConnected : theme.hero.ctaDisconnected} <ArrowRight size={17} />
          </Link>
          <Link className="text-link" to="/upload">{theme.hero.secondaryCta}</Link>
        </div>
        <div className={`privacy-chip ${state === 'connected' ? 'connected' : ''}`}>
          {state === 'connected' ? <Waves size={16} /> : <KeyRound size={16} />}
          <span>{state === 'connected' ? theme.hero.connectedStatus(photos.length) : theme.hero.idleStatus}</span>
        </div>
      </div>

      <div className="hero-gallery">
        <div className="cover-board">
          <img className="theme-map-line" src={themedAsset(theme.assets.mapLine)} alt="" aria-hidden="true" />
          <div className="board-label"><span>{theme.hero.boardLabel}</span><small>{theme.hero.boardSubLabel}</small></div>
          <div className="clubroom-window" aria-hidden="true"><span /><span /></div>
          <div className="timetable-card" aria-hidden="true">
            <small>{theme.hero.timetableLabel}</small>
            {theme.hero.timetableItems.map((item) => <span key={item}>{item}</span>)}
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
            <span className="empty-coast-copy"><MapPin size={16} /> {theme.hero.emptyHero}</span>
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
            <small><CalendarDays size={13} /> {theme.hero.noteLabel}</small>
            <strong>{latestLabel}</strong>
            <span>{theme.hero.noteText}</span>
          </div>

          <div className="route-memo-card">
            <small>ROUTE NOTE</small>
            <strong>{theme.hero.routeTitle}</strong>
            <span>{theme.hero.routeText}</span>
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
