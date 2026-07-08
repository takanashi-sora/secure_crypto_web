import { AnimatePresence, motion } from 'motion/react';
import { ArrowRight, CalendarDays, Heart, Plus, Search, SlidersHorizontal, X } from 'lucide-react';
import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import type { PhotoAssetStore } from '../lib/github';
import type { AlbumRecord, ConnectionState, PhotoRecord } from '../types';
import { Hero } from './Hero';
import { PhotoGrid } from './PhotoGrid';

interface HomeProps {
  heroPhotos: PhotoRecord[];
  allPhotos: PhotoRecord[];
  assets: PhotoAssetStore;
  state: ConnectionState;
  onOpen: (photo: PhotoRecord) => void;
}

export function HomeView({ heroPhotos, allPhotos, assets, state, onOpen }: HomeProps) {
  const totalSize = allPhotos.reduce((sum, photo) => sum + photo.size, 0);
  return (
    <div className="home-page">
      <Hero photos={heroPhotos} assets={assets} state={state} totalSize={totalSize} />
      <section className="home-intro">
        <p className="vertical-note">THE SEA REMEMBERS</p>
        <div><p className="eyebrow">RECENT FRAMES · 最近的画面</p><h2>沿着时间，<br />重新走过那一天。</h2></div>
        <div><p>从最近上传的照片中挑出几帧。这里没有公开点赞，也没有算法推荐，只有你愿意留下的瞬间。</p><Link className="text-link" to="/library">查看全部照片 <ArrowRight size={16} /></Link></div>
      </section>
      <section className="home-frames">
        <PhotoGrid photos={allPhotos.slice(0, 6)} assets={assets} onOpen={onOpen} emptyMessage={state === 'connected' ? '上传第一张照片，让这本写真志开始呼吸。' : '连接私有仓库后，照片会在这里出现。'} />
      </section>
    </div>
  );
}

interface LibraryProps {
  photos: PhotoRecord[];
  assets: PhotoAssetStore;
  onOpen: (photo: PhotoRecord) => void;
}

type SortMode = 'newest' | 'name' | 'size';

export function LibraryView({ photos, assets, onOpen }: LibraryProps) {
  const [query, setQuery] = useState('');
  const [sort, setSort] = useState<SortMode>('newest');
  const [favoritesOnly, setFavoritesOnly] = useState(false);
  const [selectedTag, setSelectedTag] = useState('');
  const tags = useMemo(() => [...new Set(photos.flatMap((photo) => photo.tags ?? []))].sort(), [photos]);
  const filtered = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return photos
      .filter((photo) => !favoritesOnly || photo.favorite)
      .filter((photo) => !selectedTag || photo.tags?.includes(selectedTag))
      .filter((photo) => !normalized || [photo.name, photo.title, photo.description, ...(photo.tags ?? [])].some((value) => value?.toLowerCase().includes(normalized)))
      .sort((left, right) => {
        if (sort === 'name') return (left.title ?? left.name).localeCompare(right.title ?? right.name, 'zh-Hans-CN');
        if (sort === 'size') return right.size - left.size;
        return (right.capturedAt ?? right.name).localeCompare(left.capturedAt ?? left.name);
      });
  }, [favoritesOnly, photos, query, selectedTag, sort]);

  return (
    <section className="page library-page">
      <header className="page-heading library-heading"><div><p className="eyebrow">ALL PHOTOGRAPHS</p><h1>私人照片库</h1></div><p><strong>{filtered.length}</strong> / {photos.length} FRAMES</p></header>
      <div className="library-toolbar">
        <label className="search-box"><Search /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="搜索标题、标签或文件名" />{query && <button onClick={() => setQuery('')} aria-label="清空搜索"><X /></button>}</label>
        <label className="select-box"><SlidersHorizontal /><select value={sort} onChange={(e) => setSort(e.target.value as SortMode)}><option value="newest">最近拍摄</option><option value="name">按名称</option><option value="size">按文件大小</option></select></label>
        <button className={`filter-button ${favoritesOnly ? 'active' : ''}`} onClick={() => setFavoritesOnly((value) => !value)}><Heart fill={favoritesOnly ? 'currentColor' : 'none'} /> 收藏</button>
      </div>
      {!!tags.length && <div className="tag-filter"><button className={!selectedTag ? 'active' : ''} onClick={() => setSelectedTag('')}>全部标签</button>{tags.map((tag) => <button className={selectedTag === tag ? 'active' : ''} key={tag} onClick={() => setSelectedTag(tag)}>#{tag}</button>)}</div>}
      <PhotoGrid photos={filtered} assets={assets} onOpen={onOpen} />
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
      <header className="page-heading split-heading"><div><p className="eyebrow">CURATED STORIES</p><h1>把照片，编成一段故事。</h1></div><button className="button button-primary" onClick={() => setCreating(true)}><Plus /> 新建相册</button></header>
      <div className="album-grid">
        {albums.map((album, index) => {
          const items = photos.filter((photo) => photo.albumIds?.includes(album.id));
          const cover = photos.find((photo) => photo.path === album.coverPath) ?? items[0];
          return (
            <motion.button key={album.id} className="album-card" onClick={() => setSelected(album)} initial={{ opacity: 0, y: 25 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: index * 0.06 }}>
              <span className="album-cover">{cover ? <PhotoGrid photos={[cover]} assets={assets} onOpen={() => setSelected(album)} /> : <span className="album-placeholder"><CalendarDays /></span>}</span>
              <span className="album-copy"><small>{String(index + 1).padStart(2, '0')} · {items.length} FRAMES</small><strong>{album.title}</strong><em>{album.description || '尚未写下相册说明'}</em></span>
            </motion.button>
          );
        })}
        {!albums.length && <div className="empty-state album-empty"><span>冊</span><h3>还没有相册</h3><p>新建一本相册，再从照片详情中把喜欢的画面收入其中。</p></div>}
      </div>

      <AnimatePresence>
        {selected && <motion.div className="album-drawer" initial={{ opacity: 0, y: '100%' }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: '100%' }}><header><div><small>CURATED ALBUM</small><h2>{selected.title}</h2><p>{selected.description}</p></div><button onClick={() => setSelected(undefined)} aria-label="关闭相册"><X /></button></header><PhotoGrid photos={albumPhotos} assets={assets} onOpen={onOpen} emptyMessage="从照片详情里把照片加入这本相册。" /></motion.div>}
      </AnimatePresence>

      <AnimatePresence>
        {creating && <motion.div className="dialog-wrap" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}><button className="dialog-backdrop" onClick={() => setCreating(false)} aria-label="取消" /><form className="dialog" onSubmit={(event) => { event.preventDefault(); void onCreate(title, description).then(() => { setCreating(false); setTitle(''); setDescription(''); }); }}><p className="eyebrow">NEW ALBUM</p><h2>新建一本写真集</h2><label>相册名称<input autoFocus required value={title} onChange={(e) => setTitle(e.target.value)} placeholder="例如：沼津的夏天" /></label><label>一句说明<textarea value={description} onChange={(e) => setDescription(e.target.value)} placeholder="写下这本相册的开场白" /></label><div className="form-actions"><button className="button button-primary" type="submit">创建相册</button><button className="button button-ghost" type="button" onClick={() => setCreating(false)}>取消</button></div></form></motion.div>}
      </AnimatePresence>
    </section>
  );
}
