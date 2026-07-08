import { useEffect, useRef, useState } from 'react';
import type { PhotoAssetStore } from '../lib/github';
import type { PhotoRecord } from '../types';

interface PhotoImageProps {
  photo: PhotoRecord;
  assets: PhotoAssetStore;
  className?: string;
  eager?: boolean;
  alt?: string;
  onReady?: () => void;
}

export function PhotoImage({ photo, assets, className, eager, alt, onReady }: PhotoImageProps) {
  const ref = useRef<HTMLImageElement>(null);
  const [url, setUrl] = useState('');
  const [visible, setVisible] = useState(Boolean(eager));
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    if (eager || !ref.current || !('IntersectionObserver' in window)) {
      setVisible(true);
      return;
    }
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting)) {
          setVisible(true);
          observer.disconnect();
        }
      },
      { rootMargin: '320px' },
    );
    observer.observe(ref.current);
    return () => observer.disconnect();
  }, [eager]);

  useEffect(() => {
    let active = true;
    if (!visible) return;
    assets
      .get(photo)
      .then((asset) => {
        if (active) setUrl(asset.url);
      })
      .catch(() => {
        if (active) setFailed(true);
      });
    return () => {
      active = false;
    };
  }, [assets, photo, visible]);

  return (
    <span className={`photo-image-shell ${failed ? 'is-failed' : ''}`}>
      <img
        ref={ref}
        className={className}
        src={url || undefined}
        alt={alt ?? photo.title ?? photo.name}
        loading={eager ? 'eager' : 'lazy'}
        onLoad={onReady}
      />
      {!url && <span className="photo-skeleton" aria-label={failed ? '照片读取失败' : '照片加载中'} />}
    </span>
  );
}
