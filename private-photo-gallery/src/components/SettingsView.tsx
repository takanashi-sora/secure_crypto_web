import { Eye, EyeOff, KeyRound, LockKeyhole, RefreshCw, ShieldCheck, Unplug } from 'lucide-react';
import { useEffect, useState } from 'react';
import type { ConnectionState, GallerySettings } from '../types';

interface SettingsViewProps {
  settings: GallerySettings;
  state: ConnectionState;
  error?: string;
  onSave: (settings: GallerySettings, connect: boolean) => Promise<void>;
  onDisconnect: () => void;
}

export function SettingsView({ settings, state, error, onSave, onDisconnect }: SettingsViewProps) {
  const [draft, setDraft] = useState(settings);
  const [showToken, setShowToken] = useState(false);
  useEffect(() => setDraft(settings), [settings]);

  const field = (key: keyof GallerySettings, value: string | boolean) => setDraft({ ...draft, [key]: value });

  return (
    <section className="page settings-page">
      <header className="page-heading split-heading">
        <div><p className="eyebrow">PRIVATE CONNECTION</p><h1>连接你的<br />私人照片空间。</h1></div>
        <p>默认只保存到当前浏览器会话。只有开启“在可信设备记住我”，Token 才会长期保留。</p>
      </header>

      <div className="settings-layout">
        <form className="settings-form" onSubmit={(event) => { event.preventDefault(); void onSave(draft, true); }}>
          <div className="settings-status"><span className={state}><ShieldCheck /></span><div><small>CONNECTION STATUS</small><strong>{state === 'connected' ? '私密通道已连接' : state === 'loading' ? '正在连接 GitHub…' : state === 'error' ? '连接遇到问题' : '等待连接'}</strong>{error && <p>{error}</p>}</div></div>
          <label className="field full">GitHub Fine-grained Token<span className="password-field"><KeyRound /><input required type={showToken ? 'text' : 'password'} value={draft.token} onChange={(e) => field('token', e.target.value)} autoComplete="off" placeholder="github_pat_…" /><button type="button" onClick={() => setShowToken((value) => !value)} aria-label={showToken ? '隐藏 Token' : '显示 Token'}>{showToken ? <EyeOff /> : <Eye />}</button></span></label>
          <div className="form-grid">
            <label className="field">Owner<input required value={draft.owner} onChange={(e) => field('owner', e.target.value)} /></label>
            <label className="field">Private repository<input required value={draft.repo} onChange={(e) => field('repo', e.target.value)} /></label>
            <label className="field">Branch<input required value={draft.branch} onChange={(e) => field('branch', e.target.value)} /></label>
            <label className="field">Photo folder<input required value={draft.folder} onChange={(e) => field('folder', e.target.value)} /></label>
          </div>
          <label className="remember-row"><input type="checkbox" checked={draft.rememberToken} onChange={(e) => field('rememberToken', e.target.checked)} /><span><strong>在可信设备记住我</strong><small>关闭浏览器后仍保留 Token。请勿在公共设备开启。</small></span></label>
          <div className="form-actions"><button className="button button-primary" type="submit" disabled={state === 'loading'}><RefreshCw className={state === 'loading' ? 'spin' : ''} /> 保存并连接</button><button className="button button-ghost" type="button" onClick={() => void onSave(draft, false)}>仅保存</button>{settings.token && <button className="button button-danger" type="button" onClick={onDisconnect}><Unplug /> 断开</button>}</div>
        </form>

        <aside className="security-notes">
          <LockKeyhole size={28} />
          <p className="eyebrow">SECURITY NOTES</p>
          <h2>私密，是这个空间安静的底色。</h2>
          <ol><li><span>01</span>Token 仅需授权 photo-vault 仓库。</li><li><span>02</span>权限只开启 Contents: Read and write。</li><li><span>03</span>预览由浏览器创建临时 Blob URL。</li><li><span>04</span>分享调用系统面板，不发布到互联网。</li></ol>
        </aside>
      </div>
    </section>
  );
}
