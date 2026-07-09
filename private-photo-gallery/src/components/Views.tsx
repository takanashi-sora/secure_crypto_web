import { AnimatePresence, motion } from 'motion/react';
import { BookOpen, Heart, Plus, Search, SlidersHorizontal, X } from 'lucide-react';
import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import type { PhotoAssetStore } from '../lib/github';
import type { GalleryTheme } from '../themes';
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
  theme: GalleryTheme;
  onOpen: (photo: PhotoRecord) => void;
}

export function HomeView({ heroPhotos, allPhotos, albums, assets, state, theme, onOpen }: HomeProps) {
  const counts = { photos: allPhotos.length, albums: albums.length };
  return (
    <div className="home-page">
      <Hero photos={heroPhotos} assets={assets} state={state} theme={theme} onOpen={onOpen} />
      <section className="room-entrances" aria-label="记忆房间入口">
        <header>
          <p className="eyebrow">{theme.home.roomEyebrow}</p>
          <h2>{theme.home.roomTitle}</h2>
          <p className="section-note">{theme.home.roomNote}</p>
        </header>
        <div className="room-grid">
          {theme.home.rooms.map((room) => (
            <Link className={`room-card room-card-${room.key}`} to={room.to} key={room.key}>
              <span className="room-card-mark">{room.mark}</span>
              <strong>{room.title}</strong>
              <em>{room.summary(counts)}</em>
            </Link>
          ))}
        </div>
      </section>
      <section className="recent-ledger">
        <header>
          <div><p className="eyebrow">{theme.home.latestEyebrow}</p><h2>{theme.home.latestTitle}</h2><p className="section-note">{theme.home.latestNote}</p></div>
          <div className="ledger-summary"><span>{albums.length} {theme.home.albumUnit}</span><span>{allPhotos.length} {theme.home.photoUnit}</span></div>
        </header>
        <PhotoGrid photos={allPhotos.slice(0, 6)} assets={assets} albums={albums} theme={theme} mode="editorial" onOpen={onOpen} emptyMessage={state === 'connected' ? '把第一张照片贴上来，这个主题馆就会开始有声音。' : '连接私有仓库后，当前主题馆会出现最近带回来的照片。'} />
      </section>
    </div>
  );
}

interface LibraryProps {
  photos: PhotoRecord[];
  albums: AlbumRecord[];
  assets: PhotoAssetStore;
  theme: GalleryTheme;
  onOpen: (photo: PhotoRecord) => void;
}

type SortMode = 'newest' | 'name' | 'size';

export function LibraryView({ photos, albums, assets, theme, onOpen }: LibraryProps) {
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
      .filter((photo) => !normalized || [photo.name, photo.title, photo.description, photo.location, photo.mood, photo.themeId, ...(photo.tags ?? [])].some((value) => value?.toLowerCase().includes(normalized)))
      .sort((left, right) => {
        if (sort === 'name') return (left.title ?? left.name).localeCompare(right.title ?? right.name, 'zh-Hans-CN');
        if (sort === 'size') return right.size - left.size;
        return (right.capturedAt ?? right.name).localeCompare(left.capturedAt ?? left.name);
      });
  }, [favoritesOnly, photos, query, selectedTag, sort]);

  return (
    <section className="page library-page">
      <header className="page-heading library-heading"><div><p className="eyebrow">{theme.library.eyebrow}</p><h1>{theme.library.title}</h1><p className="heading-note">{theme.library.note}</p></div><p><strong>{filtered.length}</strong> / {photos.length} PHOTOS</p></header>
      <div className="library-toolbar">
        <label className="search-box"><Search /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={theme.library.searchPlaceholder} />{query && <button onClick={() => setQuery('')} aria-label="清空搜索"><X /></button>}</label>
        <label className="select-box"><SlidersHorizontal /><select value={sort} onChange={(event) => setSort(event.target.value as SortMode)}><option value="newest">{theme.library.newestSort}</option><option value="name">{theme.library.nameSort}</option><option value="size">{theme.library.sizeSort}</option></select></label>
        <button className={`filter-button ${favoritesOnly ? 'active' : ''}`} onClick={() => setFavoritesOnly((value) => !value)}><Heart fill={favoritesOnly ? 'currentColor' : 'none'} /> {theme.library.favorite}</button>
      </div>
      <div className="view-mode-bar" aria-label="照片库浏览模式">
        <div><button className={mode === 'editorial' ? 'active' : ''} onClick={() => setMode('editorial')}>{theme.library.editorialMode}</button><button className={mode === 'archive' ? 'active' : ''} onClick={() => setMode('archive')}>{theme.library.archiveMode}</button></div>
        <p>{mode === 'archive' ? theme.library.archiveNote : theme.library.editorialNote}</p>
      </div>
      {!!tags.length && <div className="tag-filter"><button className={!selectedTag ? 'active' : ''} onClick={() => setSelectedTag('')}>{theme.library.allTags}</button>{tags.map((tag) => <button className={selectedTag === tag ? 'active' : ''} key={tag} onClick={() => setSelectedTag(tag)}>#{tag}</button>)}</div>}
      <PhotoGrid photos={filtered} assets={assets} albums={albums} theme={theme} mode={mode} onOpen={onOpen} />
    </section>
  );
}

interface AlbumsProps {
  albums: AlbumRecord[];
  photos: PhotoRecord[];
  assets: PhotoAssetStore;
  theme: GalleryTheme;
  onOpen: (photo: PhotoRecord) => void;
  onCreate: (title: string, description: string) => Promise<void>;
}

export function AlbumsView({ albums, photos, assets, theme, onOpen, onCreate }: AlbumsProps) {
  const [selected, setSelected] = useState<AlbumRecord>();
  const [creating, setCreating] = useState(false);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const albumPhotos = selected ? photos.filter((photo) => photo.albumIds?.includes(selected.id)) : [];

  return (
    <section className="page albums-page">
      <header className="page-heading split-heading"><div><p className="eyebrow">{theme.albums.eyebrow}</p><h1>{theme.albums.title}</h1><p className="heading-note">{theme.albums.note}</p></div><button className="button button-primary" onClick={() => setCreating(true)}><Plus /> {theme.albums.create}</button></header>
      <div className="album-grid">
        {albums.map((album, index) => {
          const items = photos.filter((photo) => photo.albumIds?.includes(album.id));
          const cover = photos.find((photo) => photo.path === album.coverPath) ?? items[0];
          return (
            <button key={album.id} className="album-card" onClick={() => setSelected(album)}>
              <span className="album-cover">{cover ? <PhotoImage photo={cover} assets={assets} /> : <span className="album-placeholder"><BookOpen /></span>}</span>
              <span className="album-copy"><small>{String(index + 1).padStart(2, '0')} · {items.length} PHOTOS · {album.themeId ?? theme.id}</small><strong>{album.title}</strong><em>{album.description || theme.albums.untitledDescription}</em></span>
            </button>
          );
        })}
        {!albums.length && <div className="empty-state album-empty"><span>☁</span><h3>{theme.albums.emptyTitle}</h3><p>{theme.albums.emptyNote}</p></div>}
      </div>

      <AnimatePresence>
        {selected && <motion.div className="album-drawer" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}><header><div><small>{theme.albums.drawerLabel}</small><h2>{selected.title}</h2><p>{selected.description}</p></div><button onClick={() => setSelected(undefined)} aria-label="关闭路线本"><X /></button></header><PhotoGrid photos={albumPhotos} assets={assets} albums={albums} theme={theme} mode="editorial" onOpen={onOpen} emptyMessage="编辑照片注记时，可以把照片贴进这条路线。" /></motion.div>}
      </AnimatePresence>

      <AnimatePresence>
        {creating && <motion.div className="dialog-wrap" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}><button className="dialog-backdrop" onClick={() => setCreating(false)} aria-label="取消" /><form className="dialog" onSubmit={(event) => { event.preventDefault(); void onCreate(title, description).then(() => { setCreating(false); setTitle(''); setDescription(''); }); }}><p className="eyebrow">{theme.albums.createEyebrow}</p><h2>{theme.albums.createTitle}</h2><label>{theme.albums.titleLabel}<input autoFocus required value={title} onChange={(event) => setTitle(event.target.value)} placeholder={theme.albums.titlePlaceholder} /></label><label>{theme.albums.descriptionLabel}<textarea value={description} onChange={(event) => setDescription(event.target.value)} placeholder={theme.albums.descriptionPlaceholder} /></label><div className="form-actions"><button className="button button-primary" type="submit">{theme.albums.submit}</button><button className="button button-ghost" type="button" onClick={() => setCreating(false)}>取消</button></div></form></motion.div>}
      </AnimatePresence>
    </section>
  );
}
