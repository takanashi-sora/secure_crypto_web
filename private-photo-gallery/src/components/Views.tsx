import { AnimatePresence, motion } from 'motion/react';
import { BookOpen, Heart, Plus, Search, SlidersHorizontal, X } from 'lucide-react';
import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
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
      <section className="room-entrances" aria-label="记忆房间入口">
        <header>
          <p className="eyebrow">ROOM MAP</p>
          <h2>今天从哪扇门进去？</h2>
          <p className="section-note">这里不是应用菜单，更像房间里的路线图：照片贴在墙上，出行写进路线本，今天带回来的东西先放到门口。</p>
        </header>
        <div className="room-grid">
          <Link className="room-card room-card-photo" to="/library">
            <span className="room-card-mark">01</span>
            <strong>照片墙</strong>
            <em>{allPhotos.length ? `${allPhotos.length} 张记忆贴在墙上` : '等第一张照片亮起来'}</em>
          </Link>
          <Link className="room-card room-card-route" to="/albums">
            <span className="room-card-mark">02</span>
            <strong>路线本</strong>
            <em>{albums.length ? `${albums.length} 段小镇路线` : '把一次出行写成章节'}</em>
          </Link>
          <Link className="room-card room-card-keepsake" to="/library">
            <span className="room-card-mark">★</span>
            <strong>反复翻看的东西</strong>
            <em>在照片墙里点亮珍藏。</em>
          </Link>
          <Link className="room-card room-card-upload" to="/upload">
            <span className="room-card-mark">＋</span>
            <strong>把今天带回房间</strong>
            <em>新照片会先安静收进私有仓库。</em>
          </Link>
        </div>
      </section>
      <section className="recent-ledger">
        <header>
          <div><p className="eyebrow">ON THE WALL</p><h2>墙上刚贴好的片刻</h2><p className="section-note">像部室公告板旁边随手贴上的照片：不急着分类，先让它们带着当天的光留在这里。</p></div>
          <div className="ledger-summary"><span>{albums.length} 段路线</span><span>{allPhotos.length} 张照片</span></div>
        </header>
        <PhotoGrid photos={allPhotos.slice(0, 6)} assets={assets} albums={albums} mode="editorial" onOpen={onOpen} emptyMessage={state === 'connected' ? '把第一张照片贴上来，这个房间就会开始有声音。' : '连接私有仓库后，墙上会出现最近带回来的照片。'} />
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
      <header className="page-heading library-heading"><div><p className="eyebrow">MEMORY WALL</p><h1>照片墙</h1><p className="heading-note">像走进海边部室后看到的一面墙：照片、日期、地点和小标签都贴在这里；需要查找时，再把它切成索引板。</p></div><p><strong>{filtered.length}</strong> / {photos.length} PHOTOS</p></header>
      <div className="library-toolbar">
        <label className="search-box"><Search /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="找某一天、某段坡道、某张海边照片" />{query && <button onClick={() => setQuery('')} aria-label="清空搜索"><X /></button>}</label>
        <label className="select-box"><SlidersHorizontal /><select value={sort} onChange={(event) => setSort(event.target.value as SortMode)}><option value="newest">按最近的光</option><option value="name">按名字翻</option><option value="size">按文件大小</option></select></label>
        <button className={`filter-button ${favoritesOnly ? 'active' : ''}`} onClick={() => setFavoritesOnly((value) => !value)}><Heart fill={favoritesOnly ? 'currentColor' : 'none'} /> 珍藏</button>
      </div>
      <div className="view-mode-bar" aria-label="照片库浏览模式">
        <div><button className={mode === 'editorial' ? 'active' : ''} onClick={() => setMode('editorial')}>照片墙</button><button className={mode === 'archive' ? 'active' : ''} onClick={() => setMode('archive')}>索引板</button></div>
        <p>{mode === 'archive' ? '像把墙上的照片取下来排成索引板，方便找地点、章节和心情。' : '像贴在墙上的照片，大小和角度有一点生活感，先保留现场的空气。'}</p>
      </div>
      {!!tags.length && <div className="tag-filter"><button className={!selectedTag ? 'active' : ''} onClick={() => setSelectedTag('')}>墙上的全部标签</button>{tags.map((tag) => <button className={selectedTag === tag ? 'active' : ''} key={tag} onClick={() => setSelectedTag(tag)}>#{tag}</button>)}</div>}
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
      <header className="page-heading split-heading"><div><p className="eyebrow">ROUTE NOTEBOOK</p><h1>路线本</h1><p className="heading-note">把一次出行写成一条小镇路线：坡道、海边道路、车站、码头和那天的心情，都可以收进同一章。</p></div><button className="button button-primary" onClick={() => setCreating(true)}><Plus /> 写下新路线</button></header>
      <div className="album-grid">
        {albums.map((album, index) => {
          const items = photos.filter((photo) => photo.albumIds?.includes(album.id));
          const cover = photos.find((photo) => photo.path === album.coverPath) ?? items[0];
          return (
            <button key={album.id} className="album-card" onClick={() => setSelected(album)}>
              <span className="album-cover">{cover ? <PhotoImage photo={cover} assets={assets} /> : <span className="album-placeholder"><BookOpen /></span>}</span>
              <span className="album-copy"><small>{String(index + 1).padStart(2, '0')} · {items.length} PHOTOS</small><strong>{album.title}</strong><em>{album.description || '还没有写下这段路线的说明。'}</em></span>
            </button>
          );
        })}
        {!albums.length && <div className="empty-state album-empty"><span>☁</span><h3>路线本还空着</h3><p>先写下一条路线，再从照片注记里把喜欢的片刻放进去。</p></div>}
      </div>

      <AnimatePresence>
        {selected && <motion.div className="album-drawer" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}><header><div><small>ROUTE NOTEBOOK</small><h2>{selected.title}</h2><p>{selected.description}</p></div><button onClick={() => setSelected(undefined)} aria-label="关闭路线本"><X /></button></header><PhotoGrid photos={albumPhotos} assets={assets} albums={albums} mode="editorial" onOpen={onOpen} emptyMessage="编辑照片注记时，可以把照片贴进这条路线。" /></motion.div>}
      </AnimatePresence>

      <AnimatePresence>
        {creating && <motion.div className="dialog-wrap" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}><button className="dialog-backdrop" onClick={() => setCreating(false)} aria-label="取消" /><form className="dialog" onSubmit={(event) => { event.preventDefault(); void onCreate(title, description).then(() => { setCreating(false); setTitle(''); setDescription(''); }); }}><p className="eyebrow">NEW ROUTE</p><h2>写下一条新的路线</h2><label>路线名称<input autoFocus required value={title} onChange={(event) => setTitle(event.target.value)} placeholder="例如：夏日傍晚的海边路" /></label><label>路线说明<textarea value={description} onChange={(event) => setDescription(event.target.value)} placeholder="那天经过了哪里，又把什么带回来了" /></label><div className="form-actions"><button className="button button-primary" type="submit">写进路线本</button><button className="button button-ghost" type="button" onClick={() => setCreating(false)}>取消</button></div></form></motion.div>}
      </AnimatePresence>
    </section>
  );
}
