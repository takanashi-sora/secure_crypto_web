import { AnimatePresence, motion } from 'motion/react';
import { AlertTriangle, LoaderCircle, RefreshCw, X } from 'lucide-react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import { AlbumsView, HomeView, LibraryView } from './components/Views';
import { SettingsView } from './components/SettingsView';
import { Shell } from './components/Shell';
import { UploadView } from './components/UploadView';
import { Viewer } from './components/Viewer';
import { GitHubApiError, GitHubRepositoryClient, PhotoAssetStore } from './lib/github';
import { createEmptyManifest, getHeroPhotos, mergePhotos, removePhotoMetadata, updatePhotoMetadata } from './lib/manifest';
import { clearStoredToken, loadSettings, saveSettings } from './lib/storage';
import type {
  AlbumRecord,
  ConnectionState,
  GallerySettings,
  PhotoMetadata,
  PhotoRecord,
  UploadCandidate,
  UploadResult,
  VaultManifestV1,
} from './types';

function errorMessage(error: unknown) {
  if (error instanceof GitHubApiError) {
    if (error.status === 401) return 'Token 无效或已经过期，请重新生成后再试。';
    if (error.status === 403) return error.message;
    if (error.status === 404) return '找不到私有仓库、分支或照片目录，请检查设置与 Token 权限。';
  }
  return error instanceof Error ? error.message : '发生了未知错误。';
}

export default function App() {
  const [settings, setSettings] = useState<GallerySettings>(() => loadSettings());
  const [repositoryPhotos, setRepositoryPhotos] = useState<PhotoRecord[]>([]);
  const [manifest, setManifest] = useState<VaultManifestV1>(() => createEmptyManifest());
  const [connection, setConnection] = useState<ConnectionState>('idle');
  const [connectionError, setConnectionError] = useState('');
  const [selectedPath, setSelectedPath] = useState('');
  const [toast, setToast] = useState('');
  const location = useLocation();
  const navigate = useNavigate();

  const client = useMemo(() => new GitHubRepositoryClient(settings), [settings]);
  const assets = useMemo(() => new PhotoAssetStore(client), [client]);
  const photos = useMemo(() => mergePhotos(repositoryPhotos, manifest), [repositoryPhotos, manifest]);
  const selected = photos.find((photo) => photo.path === selectedPath);
  const heroPhotos = useMemo(() => getHeroPhotos(photos, manifest), [photos, manifest]);

  const notify = useCallback((message: string) => {
    setToast(message);
    window.setTimeout(() => setToast(''), 3600);
  }, []);

  useEffect(() => () => assets.clear(), [assets]);

  const loadVault = useCallback(async () => {
    if (!settings.token) {
      setConnection('idle');
      setRepositoryPhotos([]);
      setManifest(createEmptyManifest());
      return;
    }
    setConnection('loading');
    setConnectionError('');
    try {
      const [nextPhotos, snapshot] = await Promise.all([client.listPhotos(), client.loadManifest()]);
      setRepositoryPhotos(nextPhotos);
      setManifest(snapshot.manifest);
      setConnection('connected');
    } catch (error) {
      setConnection('error');
      setConnectionError(errorMessage(error));
    }
  }, [client, settings.token]);

  useEffect(() => {
    if (settings.token) void loadVault();
  }, []); // Existing credentials connect once on startup.

  const saveConnection = async (next: GallerySettings, connect: boolean) => {
    const clean = { ...next, owner: next.owner.trim(), repo: next.repo.trim(), branch: next.branch.trim(), folder: next.folder.trim().replace(/^\/+|\/+$/g, ''), token: next.token.trim() };
    saveSettings(clean);
    setSettings(clean);
    notify(connect ? '连接设置已保存，正在读取私有照片。' : '设置已保存。');
    if (connect) {
      setConnection('loading');
      setConnectionError('');
      const nextClient = new GitHubRepositoryClient(clean);
      try {
        const [nextPhotos, snapshot] = await Promise.all([nextClient.listPhotos(), nextClient.loadManifest()]);
        setRepositoryPhotos(nextPhotos);
        setManifest(snapshot.manifest);
        setConnection('connected');
        notify(`已连接 ${clean.owner}/${clean.repo}，发现 ${nextPhotos.length} 张照片。`);
      } catch (error) {
        setConnection('error');
        setConnectionError(errorMessage(error));
      }
    }
  };

  const disconnect = () => {
    clearStoredToken();
    assets.clear();
    setSettings((current) => ({ ...current, token: '', rememberToken: false }));
    setRepositoryPhotos([]);
    setManifest(createEmptyManifest());
    setConnection('idle');
    setConnectionError('');
    notify('已从私有仓库断开，照片缓存已释放。');
  };

  const savePhoto = async (photo: PhotoRecord, patch: PhotoMetadata) => {
    const optimistic = updatePhotoMetadata(manifest, photo.path, patch);
    setManifest(optimistic);
    try {
      const snapshot = await client.updateManifest((latest) => updatePhotoMetadata(latest, photo.path, patch));
      setManifest(snapshot.manifest);
      notify('照片信息已写回私有仓库。');
    } catch (error) {
      setManifest(updatePhotoMetadata(optimistic, photo.path, { metadataPending: true }));
      notify(`照片仍然安全，但元数据待同步：${errorMessage(error)}`);
    }
  };

  const deletePhoto = async (photo: PhotoRecord) => {
    if (!window.confirm(`确认永久删除这张照片？\n${photo.title ?? photo.name}`)) return;
    try {
      await client.deletePhoto(photo);
      setRepositoryPhotos((current) => current.filter((item) => item.path !== photo.path));
      setManifest((current) => removePhotoMetadata(current, photo.path));
      setSelectedPath('');
      try {
        const snapshot = await client.updateManifest((latest) => removePhotoMetadata(latest, photo.path));
        setManifest(snapshot.manifest);
      } catch {
        notify('照片已删除；清单中的旧记录会在下次成功同步时清理。');
        return;
      }
      notify('照片已从私有仓库删除。');
    } catch (error) {
      notify(`删除失败：${errorMessage(error)}`);
    }
  };

  const upload = async (
    candidates: UploadCandidate[],
    progress: (done: number) => void,
  ): Promise<UploadResult[]> => {
    const results: UploadResult[] = [];
    const uploaded: PhotoRecord[] = [];
    for (const candidate of candidates) {
      try {
        const photo = await client.uploadPhoto(candidate);
        uploaded.push(photo);
        results.push({ candidate, photo });
      } catch (error) {
        results.push({ candidate, error: errorMessage(error) });
      }
      progress(results.length);
    }

    if (uploaded.length) {
      setRepositoryPhotos((current) => [...uploaded, ...current]);
      try {
        const snapshot = await client.updateManifest((latest) =>
          uploaded.reduce(
            (next, photo) =>
              updatePhotoMetadata(next, photo.path, {
                title: photo.title,
                capturedAt: photo.capturedAt,
                width: photo.width,
                height: photo.height,
              }),
            latest,
          ),
        );
        setManifest(snapshot.manifest);
      } catch (error) {
        setManifest((current) =>
          uploaded.reduce(
            (next, photo) =>
              updatePhotoMetadata(next, photo.path, {
                title: photo.title,
                capturedAt: photo.capturedAt,
                width: photo.width,
                height: photo.height,
                metadataPending: true,
              }),
            current,
          ),
        );
        notify(`照片已上传，元数据将在稍后同步：${errorMessage(error)}`);
      }
    }
    const failures = results.filter((result) => result.error).length;
    notify(failures ? `${uploaded.length} 张上传成功，${failures} 张失败。` : `${uploaded.length} 张照片已收入私密写真志。`);
    return results;
  };

  const createAlbum = async (title: string, description: string) => {
    const album: AlbumRecord = { id: crypto.randomUUID(), title: title.trim(), description: description.trim(), createdAt: new Date().toISOString() };
    const optimistic = { ...manifest, updatedAt: new Date().toISOString(), albums: [...manifest.albums, album] };
    setManifest(optimistic);
    try {
      const snapshot = await client.updateManifest((latest) => ({ ...latest, updatedAt: new Date().toISOString(), albums: [...latest.albums, album] }));
      setManifest(snapshot.manifest);
      notify('新相册已经创建。');
    } catch (error) {
      setManifest(manifest);
      notify(`相册创建失败：${errorMessage(error)}`);
    }
  };

  return (
    <Shell>
      <AnimatePresence mode="wait">
        <motion.div key={location.pathname} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: 0.32 }}>
          {connection === 'loading' && <div className="connection-banner"><LoaderCircle className="spin" /> 正在从私有仓库整理照片…</div>}
          {connection === 'error' && location.pathname !== '/settings' && <div className="connection-banner error"><AlertTriangle /> <span>{connectionError}</span><button onClick={() => navigate('/settings')}>检查设置</button><button onClick={() => void loadVault()} aria-label="重试"><RefreshCw /></button></div>}
          <Routes location={location}>
            <Route path="/" element={<HomeView heroPhotos={heroPhotos} allPhotos={photos} assets={assets} state={connection} onOpen={(photo) => setSelectedPath(photo.path)} />} />
            <Route path="/library" element={<LibraryView photos={photos} assets={assets} onOpen={(photo) => setSelectedPath(photo.path)} />} />
            <Route path="/albums" element={<AlbumsView albums={manifest.albums} photos={photos} assets={assets} onOpen={(photo) => setSelectedPath(photo.path)} onCreate={createAlbum} />} />
            <Route path="/upload" element={<UploadView connected={connection === 'connected'} onUpload={upload} />} />
            <Route path="/settings" element={<SettingsView settings={settings} state={connection} error={connectionError} onSave={saveConnection} onDisconnect={disconnect} />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </motion.div>
      </AnimatePresence>
      <Viewer photo={selected} photos={photos} albums={manifest.albums} assets={assets} onClose={() => setSelectedPath('')} onSelect={(photo) => setSelectedPath(photo.path)} onSave={savePhoto} onDelete={deletePhoto} notify={notify} />
      <AnimatePresence>{toast && <motion.div className="toast" initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: 16 }}><span>{toast}</span><button onClick={() => setToast('')} aria-label="关闭提示"><X /></button></motion.div>}</AnimatePresence>
    </Shell>
  );
}
