import { AnimatePresence, motion } from 'motion/react';
import { BookOpen, Heart, Plus, Search, SlidersHorizontal, X } from 'lucide-react';
import { useMemo, useState } from 'react';
import type { PhotoAssetStore } from '../lib/github';
import type { AlbumRecord, ConnectionState, PhotoRecord } from '../types';
import { Hero } from './Hero';
import { PhotoGrid, type GalleryMode } from './PhotoGrid';
import { PhotoImage } from './PhotoImage';

interface HomeProps {
  heroPhotos: PhotoRecord[];
  allPhotos: PhotoRecord[];
  albums: AlbumRecord[];
  assets: PhotoAssetStore;
  state: ConnectionState;
  onOpen: (photo: PhotoRecord) => void;
}

export function HomeView({ heroPhotos, allPhotos, albums, assets, state, onOpen }: HomeProps) {
  return (
    <div className="home-page">
      <Hero photos={heroPhotos} assets={assets} state={state} onOpen={onOpen} />
      <section className="recent-ledger">
        <header>
          <div><p className="eyebrow">RECENT MOMENTS</p><h2>最近留下的片刻</h2><p className="section-note">像翻开个人主页的一角，先看看离现在最近的光。</p></div>
          <div className="ledger-summary"><span>{albums.length} 个旅程</span><span>{allPhotos.length} 张照片</span></div>
        </header>
        <PhotoGrid photos={allPhotos.slice(0, 6)} assets={assets} albums={albums} mode="editorial" onOpen={onOpen} emptyMessage={state === 'connected' ? '加入第一张照片，让这一页从喜欢的风景开始。' : '连接私有仓库后，最近的照片会在这里出现。'} />
      </section>
    </div>
  );
}

interface LibraryProps {
  photos: PhotoRecord[];
  albums: AlbumRecord[];
  assets: PhotoAssetStore;
  onOpen: (photo: PhotoRecord) => void;
}

type SortMode = 'newest' | 'name' | 'size';

export function LibraryView({ photos, albums, assets, onOpen }: LibraryProps) {
  const [query, setQuery] = useState('');
  const [sort, setSort] = useState<SortMode>('newest');
  const [favoritesOnly, setFavoritesOnly] = useState(false);
  const [selectedTag, setSelectedTag] = useState('');
  const [mode, setMode] = useState<GalleryMode>('editorial');
  const tags = useMemo(() => [...new Set(photos.flatMap((photo) => photo.tags ?? []))].sort(), [photos]);
  const filtered = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return photos
      .filter((photo) => !favoritesOnly || photo.favorite)
      .filter((photo) => !selectedTag || photo.tags?.includes(selectedTag))
      .filter((photo) => !normalized || [photo.name, photo.title, photo.description, photo.location, photo.mood, ...(photo.tags ?? [])].some((value) => value?.toLowerCase().includes(normalized)))
      .sort((left, right) => {
        if (sort === 'name') return (left.title ?? left.name).localeCompare(right.title ?? right.name, 'zh-Hans-CN');
        if (sort === 'size') return right.size - left.size;
        return (right.capturedAt ?? right.name).localeCompare(left.capturedAt ?? left.name);
      });
  }, [favoritesOnly, photos, query, selectedTag, sort]);

  return (
    <section className="page library-page">
      <header className="page-heading library-heading"><div><p className="eyebrow">MY PHOTO SPACE</p><h1>全部照片</h1><p className="heading-note">自由翻看，或切换到整理模式查找地点与旅程。</p></div><p><strong>{filtered.length}</strong> / {photos.length} PHOTOS</p></header>
      <div className="library-toolbar">
        <label className="search-box"><Search /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索地点、标题、心情或标签" />{query && <button onClick={() => setQuery('')} aria-label="清空搜索"><X /></button>}</label>
        <label className="select-box"><SlidersHorizontal /><select value={sort} onChange={(event) => setSort(event.target.value as SortMode)}><option value="newest">最近拍摄</option><option value="name">按名称</option><option value="size">按文件大小</option></select></label>
        <button className={`filter-button ${favoritesOnly ? 'active' : ''}`} onClick={() => setFavoritesOnly((value) => !value)}><Heart fill={favoritesOnly ? 'currentColor' : 'none'} /> 珍藏</button>
      </div>
      <div className="view-mode-bar" aria-label="照片库浏览模式">
        <div><button className={mode === 'editorial' ? 'active' : ''} onClick={() => setMode('editorial')}>写真浏览</button><button className={mode === 'archive' ? 'active' : ''} onClick={() => setMode('archive')}>整理模式</button></div>
        <p>{mode === 'archive' ? '规整、少裁切，只在有内容时显示地点与旅程。' : '让照片优先，只保留标题、日期与少量标签。'}</p>
      </div>
      {!!tags.length && <div className="tag-filter"><button className={!selectedTag ? 'active' : ''} onClick={() => setSelectedTag('')}>全部标签</button>{tags.map((tag) => <button className={selectedTag === tag ? 'active' : ''} key={tag} onClick={() => setSelectedTag(tag)}>#{tag}</button>)}</div>}
      <PhotoGrid photos={filtered} assets={assets} albums={albums} mode={mode} onOpen={onOpen} />
    </section>
  );
}

interface AlbumsProps {
  albums: AlbumRecord[];
  photos: PhotoRecord[];
  assets: PhotoAssetStore;
  onOpen: (photo: PhotoRecord) => void;
  onCreate: (title: string, description: string) => Promise<void>;
}

export function AlbumsView({ albums, photos, assets, onOpen, onCreate }: AlbumsProps) {
  const [selected, setSelected] = useState<AlbumRecord>();
  const [creating, setCreating] = useState(false);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const albumPhotos = selected ? photos.filter((photo) => photo.albumIds?.includes(selected.id)) : [];

  return (
    <section className="page albums-page">
      <header className="page-heading split-heading"><div><p className="eyebrow">ALBUMS & JOURNEYS</p><h1>旅程与相册</h1><p className="heading-note">按一次出行、一个夏天，或某段想单独收藏的日子来整理。</p></div><button className="button button-primary" onClick={() => setCreating(true)}><Plus /> 新建相册</button></header>
      <div className="album-grid">
        {albums.map((album, index) => {
          const items = photos.filter((photo) => photo.albumIds?.includes(album.id));
          const cover = photos.find((photo) => photo.path === album.coverPath) ?? items[0];
          return (
            <button key={album.id} className="album-card" onClick={() => setSelected(album)}>
              <span className="album-cover">{cover ? <PhotoImage photo={cover} assets={assets} /> : <span className="album-placeholder"><BookOpen /></span>}</span>
              <span className="album-copy"><small>{String(index + 1).padStart(2, '0')} · {items.length} PHOTOS</small><strong>{album.title}</strong><em>{album.description || '还没有写下这段旅程的说明。'}</em></span>
            </button>
          );
        })}
        {!albums.length && <div className="empty-state album-empty"><span>☁</span><h3>还没有旅程相册</h3><p>新建一个相册，再从照片注记里把喜欢的片刻放进去。</p></div>}
      </div>

      <AnimatePresence>
        {selected && <motion.div className="album-drawer" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}><header><div><small>JOURNEY ALBUM</small><h2>{selected.title}</h2><p>{selected.description}</p></div><button onClick={() => setSelected(undefined)} aria-label="关闭旅程相册"><X /></button></header><PhotoGrid photos={albumPhotos} assets={assets} albums={albums} mode="editorial" onOpen={onOpen} emptyMessage="编辑照片注记时，可以把照片加入这个相册。" /></motion.div>}
      </AnimatePresence>

      <AnimatePresence>
        {creating && <motion.div className="dialog-wrap" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}><button className="dialog-backdrop" onClick={() => setCreating(false)} aria-label="取消" /><form className="dialog" onSubmit={(event) => { event.preventDefault(); void onCreate(title, description).then(() => { setCreating(false); setTitle(''); setDescription(''); }); }}><p className="eyebrow">NEW ALBUM</p><h2>创建新的旅程相册</h2><label>相册名称<input autoFocus required value={title} onChange={(event) => setTitle(event.target.value)} placeholder="例如：内浦的夏日傍晚" /></label><label>相册说明<textarea value={description} onChange={(event) => setDescription(event.target.value)} placeholder="那天去了哪里，又留下了什么" /></label><div className="form-actions"><button className="button button-primary" type="submit">创建相册</button><button className="button button-ghost" type="button" onClick={() => setCreating(false)}>取消</button></div></form></motion.div>}
      </AnimatePresence>
    </section>
  );
}
