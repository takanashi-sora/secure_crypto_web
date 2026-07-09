import { Camera, Check, ImagePlus, LoaderCircle, Trash2, UploadCloud } from 'lucide-react';
import { useRef, useState } from 'react';
import { formatBytes, safeFileName } from '../lib/format';
import type { GalleryTheme } from '../themes';
import type { UploadCandidate, UploadResult } from '../types';

interface UploadViewProps {
  connected: boolean;
  theme: GalleryTheme;
  onUpload: (candidates: UploadCandidate[], progress: (done: number) => void) => Promise<UploadResult[]>;
}

async function dimensions(file: File) {
  const url = URL.createObjectURL(file);
  try {
    const image = new Image();
    image.src = url;
    await image.decode();
    return { width: image.naturalWidth, height: image.naturalHeight };
  } finally {
    URL.revokeObjectURL(url);
  }
}

export function UploadView({ connected, theme, onUpload }: UploadViewProps) {
  const input = useRef<HTMLInputElement>(null);
  const [queue, setQueue] = useState<UploadCandidate[]>([]);
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [done, setDone] = useState(0);
  const [results, setResults] = useState<UploadResult[]>([]);

  const addFiles = async (files: FileList | File[]) => {
    const images = [...files].filter((file) => file.type.startsWith('image/'));
    const { default: exifr } = await import('exifr');
    const candidates = await Promise.all(
      images.map(async (file) => {
        const [exif, size] = await Promise.all([
          exifr.parse(file, { pick: ['DateTimeOriginal'] }).catch(() => undefined),
          dimensions(file).catch(() => ({ width: undefined, height: undefined })),
        ]);
        return {
          id: crypto.randomUUID(),
          file,
          previewUrl: URL.createObjectURL(file),
          targetName: safeFileName(file.name),
          capturedAt:
            exif?.DateTimeOriginal instanceof Date
              ? exif.DateTimeOriginal.toISOString()
              : new Date(file.lastModified).toISOString(),
          ...size,
        } satisfies UploadCandidate;
      }),
    );
    setQueue((current) => [...current, ...candidates]);
    setResults([]);
  };

  const remove = (id: string) => {
    setQueue((current) => {
      const target = current.find((item) => item.id === id);
      if (target) URL.revokeObjectURL(target.previewUrl);
      return current.filter((item) => item.id !== id);
    });
  };

  const start = async () => {
    if (!queue.length || !connected) return;
    setUploading(true);
    setDone(0);
    const nextResults = await onUpload(queue, setDone);
    setResults(nextResults);
    const successful = new Set(nextResults.filter((result) => result.photo).map((result) => result.candidate.id));
    setQueue((current) => {
      current.filter((item) => successful.has(item.id)).forEach((item) => URL.revokeObjectURL(item.previewUrl));
      return current.filter((item) => !successful.has(item.id));
    });
    setUploading(false);
  };

  return (
    <section className="page upload-page">
      <header className="page-heading split-heading">
        <div><p className="eyebrow">{theme.upload.eyebrow}</p><h1>{theme.upload.title.split('\n').map((line, index) => <span key={line}>{line}{index < theme.upload.title.split('\n').length - 1 && <br />}</span>)}</h1></div>
        <p>{theme.upload.note}</p>
      </header>

      <div className="upload-layout">
        <div>
          <button
            className={`drop-studio ${dragging ? 'dragging' : ''}`}
            onClick={() => input.current?.click()}
            onDragEnter={(event) => { event.preventDefault(); setDragging(true); }}
            onDragOver={(event) => event.preventDefault()}
            onDragLeave={() => setDragging(false)}
            onDrop={(event) => { event.preventDefault(); setDragging(false); void addFiles(event.dataTransfer.files); }}
          >
            <span className="drop-camera"><Camera /></span>
            <strong>{theme.upload.dropTitle}</strong>
            <small>拖拽或点击选择多张照片 · JPEG / PNG / WEBP / AVIF</small>
            <span className="button button-light"><ImagePlus size={17} /> 选择照片</span>
          </button>
          <input ref={input} hidden type="file" accept="image/*" multiple onChange={(event) => { if (event.target.files) void addFiles(event.target.files); event.target.value = ''; }} />

          {!!queue.length && (
            <div className="upload-queue">
              {queue.map((item, index) => (
                <article key={item.id}>
                  <img src={item.previewUrl} alt="" />
                  <div><small>PHOTO {String(index + 1).padStart(2, '0')}</small><strong>{item.file.name}</strong><span>{formatBytes(item.file.size)} · {item.width ?? '—'} × {item.height ?? '—'}</span></div>
                  <button onClick={() => remove(item.id)} aria-label={`移除 ${item.file.name}`}><Trash2 size={18} /></button>
                </article>
              ))}
            </div>
          )}
        </div>

        <aside className="upload-ticket">
          <p>{theme.upload.checkinLabel}</p>
          <h2>{theme.upload.checkinTitle.split('\n').map((line, index) => <span key={line}>{line}{index < theme.upload.checkinTitle.split('\n').length - 1 && <br />}</span>)}</h2>
          <dl><div><dt>照片</dt><dd>{queue.length} 张</dd></div><div><dt>总大小</dt><dd>{formatBytes(queue.reduce((sum, item) => sum + item.file.size, 0))}</dd></div><div><dt>可见范围</dt><dd>仅自己</dd></div></dl>
          {!connected && <div className="notice warning">请先到设置连接私有仓库。</div>}
          <button className="button button-primary wide" disabled={!connected || !queue.length || uploading} onClick={start}>
            {uploading ? <><LoaderCircle className="spin" /> {theme.upload.submitting} {done}/{queue.length}</> : <><UploadCloud /> {theme.upload.submit}</>}
          </button>
          {uploading && <div className="progress"><span style={{ width: `${queue.length ? (done / queue.length) * 100 : 0}%` }} /></div>}
          {!!results.length && (
            <div className="upload-results">
              {results.map((result) => <p key={result.candidate.id} className={result.error ? 'error' : ''}>{result.error ? '×' : <Check size={14} />} {result.candidate.file.name}{result.error ? `：${result.error}` : ''}</p>)}
            </div>
          )}
        </aside>
      </div>
    </section>
  );
}
