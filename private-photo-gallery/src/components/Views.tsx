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
  const totalSize = allPhotos.reduce((sum, photo) => sum + photo.size, 0);
  return (
    <div className="home-page">
      <Hero photos={heroPhotos} assets={assets} state={state} totalSize={totalSize} onOpen={onOpen} />
      <section className="recent-ledger">
        <header>
          <div><p className="eyebrow">LATEST ENTRIES · 最近整理</p><h2>刚收进档案柜的记忆</h2></div>
          <div className="ledger-summary"><span>{albums.length} 个旅程章节</span><span>{allPhotos.length} 张巡礼照片</span></div>
        </header>
        <PhotoGrid photos={allPhotos.slice(0, 6)} assets={assets} albums={albums} mode="editorial" onOpen={onOpen} emptyMessage={state === 'connected' ? '收入第一张巡礼照片，为这本记忆簿写下开页。' : '连接私有仓库后，最近的旅程会在这里展开。'} />
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
  const [mode, setMode] = useState<GalleryMode>('archive');
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
      <header className="page-heading library-heading"><div><p className="eyebrow">PRIVATE INDEX</p><h1>巡礼档案柜</h1><p className="heading-note">按地点、日期、心情和旅程章节整理私人记录。</p></div><p><strong>{filtered.length}</strong> / {photos.length} RECORDS</p></header>
      <div className="library-toolbar">
        <label className="search-box"><Search /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索地点、标题、心情或标签" />{query && <button onClick={() => setQuery('')} aria-label="清空搜索"><X /></button>}</label>
        <label className="select-box"><SlidersHorizontal /><select value={sort} onChange={(event) => setSort(event.target.value as SortMode)}><option value="newest">最近巡礼</option><option value="name">按名称</option><option value="size">按文件大小</option></select></label>
        <button className={`filter-button ${favoritesOnly ? 'active' : ''}`} onClick={() => setFavoritesOnly((value) => !value)}><Heart fill={favoritesOnly ? 'currentColor' : 'none'} /> 纪念册</button>
      </div>
      <div className="view-mode-bar" aria-label="照片库浏览模式">
        <div><button className={mode === 'archive' ? 'active' : ''} onClick={() => setMode('archive')}>档案柜模式</button><button className={mode === 'editorial' ? 'active' : ''} onClick={() => setMode('editorial')}>写真志模式</button></div>
        <p>{mode === 'archive' ? '规整索引、少裁切，适合长期整理与查找。' : '大图编排，适合翻阅一段旅程。'}</p>
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
      <header className="page-heading split-heading"><div><p className="eyebrow">JOURNEY CHAPTERS</p><h1>旅程章节</h1><p className="heading-note">一次巡礼、一个联动日，或一段想单独装订的记忆。</p></div><button className="button button-primary" onClick={() => setCreating(true)}><Plus /> 新建旅程章节</button></header>
      <div className="album-grid">
        {albums.map((album, index) => {
          const items = photos.filter((photo) => photo.albumIds?.includes(album.id));
          const cover = photos.find((photo) => photo.path === album.coverPath) ?? items[0];
          return (
            <button key={album.id} className="album-card" onClick={() => setSelected(album)}>
              <span className="album-cover">{cover ? <PhotoImage photo={cover} assets={assets} /> : <span className="album-placeholder"><BookOpen /></span>}</span>
              <span className="album-copy"><small>CHAPTER {String(index + 1).padStart(2, '0')} · {items.length} RECORDS</small><strong>{album.title}</strong><em>{album.description || '还没有写下这段旅程的扉页说明。'}</em><code>旅程章</code></span>
            </button>
          );
        })}
        {!albums.length && <div className="empty-state album-empty"><span>旅</span><h3>还没有旅程章节</h3><p>新建一个章节，再从照片背面的注记里把记录装订进去。</p></div>}
      </div>

      <AnimatePresence>
        {selected && <motion.div className="album-drawer" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}><header><div><small>JOURNEY CHAPTER</small><h2>{selected.title}</h2><p>{selected.description}</p></div><button onClick={() => setSelected(undefined)} aria-label="关闭旅程章节"><X /></button></header><PhotoGrid photos={albumPhotos} assets={assets} albums={albums} mode="editorial" onOpen={onOpen} emptyMessage="从照片背面的注记里把照片收入这一章节。" /></motion.div>}
      </AnimatePresence>

      <AnimatePresence>
        {creating && <motion.div className="dialog-wrap" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}><button className="dialog-backdrop" onClick={() => setCreating(false)} aria-label="取消" /><form className="dialog" onSubmit={(event) => { event.preventDefault(); void onCreate(title, description).then(() => { setCreating(false); setTitle(''); setDescription(''); }); }}><p className="eyebrow">NEW JOURNEY CHAPTER</p><h2>装订新的旅程章节</h2><label>章节名称<input autoFocus required value={title} onChange={(event) => setTitle(event.target.value)} placeholder="例如：内浦夏日巡礼" /></label><label>扉页注记<textarea value={description} onChange={(event) => setDescription(event.target.value)} placeholder="那天去了哪里，又留下了什么" /></label><div className="form-actions"><button className="button button-primary" type="submit">收入章节</button><button className="button button-ghost" type="button" onClick={() => setCreating(false)}>取消</button></div></form></motion.div>}
      </AnimatePresence>
    </section>
  );
}
