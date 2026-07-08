import { AnimatePresence, motion, useReducedMotion } from 'motion/react';
import { ArrowDownRight, KeyRound, Waves } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { formatBytes } from '../lib/format';
import type { PhotoAssetStore } from '../lib/github';
import type { ConnectionState, PhotoRecord } from '../types';
import { PhotoImage } from './PhotoImage';

interface HeroProps {
  photos: PhotoRecord[];
  assets: PhotoAssetStore;
  state: ConnectionState;
  totalSize: number;
}

export function Hero({ photos, assets, state, totalSize }: HeroProps) {
  const [active, setActive] = useState(0);
  const reducedMotion = useReducedMotion();
  const current = photos[active % Math.max(photos.length, 1)];

  useEffect(() => {
    if (photos.length < 2 || reducedMotion) return;
    const timer = window.setInterval(() => setActive((value) => (value + 1) % photos.length), 6500);
    return () => window.clearInterval(timer);
  }, [photos.length, reducedMotion]);

  return (
    <section className={`editorial-hero ${current ? 'has-photo' : ''}`}>
      <div className="hero-visual" aria-hidden={!current}>
        {current ? (
          <AnimatePresence mode="wait">
            <motion.div
              key={current.sha}
              className="hero-photo"
              initial={{ opacity: 0, scale: 1.035 }}
              animate={{ opacity: 1, scale: reducedMotion ? 1 : 1.1 }}
              exit={{ opacity: 0 }}
              transition={{ opacity: { duration: 1.1 }, scale: { duration: 8, ease: 'linear' } }}
            >
              <PhotoImage photo={current} assets={assets} eager />
            </motion.div>
          </AnimatePresence>
        ) : (
          <div className="coastline-art">
            <span className="sun-disc" />
            <span className="mountain mountain-one" />
            <span className="mountain mountain-two" />
            <span className="sea-line line-one" />
            <span className="sea-line line-two" />
          </div>
        )}
        <div className="film-grain" />
      </div>

      <div className="hero-copy">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7 }}
        >
          <p className="issue-line">ISSUE 01 — PRIVATE MEMORIES</p>
          <h1>把海风，<br /><em>留在照片里。</em></h1>
          <p className="hero-intro">
            不是文件管理器，而是只属于你的旅行写真志。照片从私有仓库抵达浏览器，
            在离开页面时重新沉入海面之下。
          </p>
          <div className="hero-actions">
            <Link className="button button-primary" to={state === 'connected' ? '/library' : '/settings'}>
              {state === 'connected' ? '翻阅写真' : '连接私有仓库'} <ArrowDownRight size={18} />
            </Link>
            <Link className="text-link" to="/upload">上传新记忆</Link>
          </div>
        </motion.div>

        <div className="hero-facts">
          <div><strong>{photos.length}</strong><span>PHOTOGRAPHS</span></div>
          <div><strong>{formatBytes(totalSize)}</strong><span>PRIVATE VOLUME</span></div>
          <div className={`connection-pill ${state}`}>
            {state === 'connected' ? <Waves size={17} /> : <KeyRound size={17} />}
            <span>{state === 'connected' ? 'PRIVATE LINK ACTIVE' : 'AWAITING TOKEN'}</span>
          </div>
        </div>
      </div>

      {photos.length > 1 && (
        <div className="hero-pagination" aria-label="封面照片选择">
          {photos.map((photo, index) => (
            <button
              key={photo.path}
              className={index === active ? 'active' : ''}
              onClick={() => setActive(index)}
              aria-label={`显示第 ${index + 1} 张封面`}
            />
          ))}
        </div>
      )}
    </section>
  );
}
