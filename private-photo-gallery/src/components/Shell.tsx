import { Aperture, Images, LibraryBig, Settings, Sparkles, UploadCloud } from 'lucide-react';
import { NavLink } from 'react-router-dom';
import type { PropsWithChildren } from 'react';

const navigation = [
  { to: '/', label: '封面', icon: Sparkles },
  { to: '/library', label: '照片库', icon: Images },
  { to: '/albums', label: '相册', icon: LibraryBig },
  { to: '/upload', label: '上传', icon: UploadCloud },
  { to: '/settings', label: '设置', icon: Settings },
];

export function Shell({ children }: PropsWithChildren) {
  return (
    <div className="site-shell">
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />
      <header className="masthead">
        <NavLink to="/" className="brand" aria-label="返回封面">
          <span className="brand-mark"><Aperture size={21} /></span>
          <span>
            <strong>SORA COASTAL ARCHIVE</strong>
            <small>沼津海岸写真志 · PRIVATE EDITION</small>
          </span>
        </NavLink>
        <nav className="desktop-nav" aria-label="主导航">
          {navigation.map(({ to, label }) => (
            <NavLink key={to} to={to} end={to === '/'}>{label}</NavLink>
          ))}
        </nav>
      </header>
      <main>{children}</main>
      <nav className="mobile-nav" aria-label="移动端主导航">
        {navigation.map(({ to, label, icon: Icon }) => (
          <NavLink key={to} to={to} end={to === '/'} aria-label={label}>
            <Icon size={19} />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>
      <footer className="footer">
        <span>NUMAZU · SHIZUOKA</span>
        <span>Photos remain inside your private repository.</span>
        <span>© {new Date().getFullYear()} SORA</span>
      </footer>
    </div>
  );
}
