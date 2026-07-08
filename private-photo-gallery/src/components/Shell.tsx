import { Aperture, CloudSun, Images, Library, Settings, UploadCloud } from 'lucide-react';
import { NavLink } from 'react-router-dom';
import type { PropsWithChildren } from 'react';

const navigation = [
  { to: '/', label: '首页', icon: CloudSun },
  { to: '/library', label: '照片', icon: Library },
  { to: '/albums', label: '旅程', icon: Images },
  { to: '/upload', label: '上传', icon: UploadCloud },
  { to: '/settings', label: '设置', icon: Settings },
];

export function Shell({ children }: PropsWithChildren) {
  return (
    <div className="site-shell">
      <header className="masthead">
        <NavLink to="/" className="brand" aria-label="返回首页">
          <span className="brand-mark"><Aperture size={20} /></span>
          <span>
            <strong>SORA'S PHOTO SPACE</strong>
            <small>takanashi.moe · private memories</small>
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
        <span>SORA'S PRIVATE PHOTO SPACE</span>
        <span>光、海风，以及想要记住的普通一天。</span>
        <span>takanashi.moe · {new Date().getFullYear()}</span>
      </footer>
    </div>
  );
}
