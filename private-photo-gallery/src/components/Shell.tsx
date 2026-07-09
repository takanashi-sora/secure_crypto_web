import { CloudSun, Images, Library, Settings, UploadCloud } from 'lucide-react';
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
      <div className="coastal-atmosphere" aria-hidden="true">
        <span className="sky-bloom bloom-one" />
        <span className="sky-bloom bloom-two" />
        <span className="distant-sun" />
        <span className="distant-mountain mountain-a" />
        <span className="distant-mountain mountain-b" />
        <span className="sea-horizon" />
        <span className="water-glint glint-one" />
        <span className="water-glint glint-two" />
        <span className="breakwater-line" />
        <span className="wind-line wind-one" />
        <span className="wind-line wind-two" />
        <span className="sora-star star-one">✦</span>
        <span className="sora-star star-two">✧</span>
        <span className="sora-dot dot-one" />
        <span className="sora-dot dot-two" />
      </div>
      <header className="masthead">
        <NavLink to="/" className="brand" aria-label="返回首页">
          <span className="brand-mark">
            <span className="brand-wave" />
            <span className="brand-star">✦</span>
          </span>
          <span>
            <strong>SORA PHOTO ROOM</strong>
            <small>takanashi.moe / sea-side memories</small>
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
        <span>SORA PHOTO ROOM</span>
        <span>海边的光、很小的收藏、还有普通一天的心情。</span>
        <span>takanashi.moe · {new Date().getFullYear()}</span>
      </footer>
    </div>
  );
}
