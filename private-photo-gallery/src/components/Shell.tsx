import { Archive, BookOpen, Images, Settings, Stamp, TicketPlus } from 'lucide-react';
import { NavLink } from 'react-router-dom';
import type { PropsWithChildren } from 'react';

const navigation = [
  { to: '/', label: '扉页', icon: BookOpen },
  { to: '/library', label: '档案柜', icon: Archive },
  { to: '/albums', label: '旅程章节', icon: Images },
  { to: '/upload', label: '收入照片', icon: TicketPlus },
  { to: '/settings', label: '设置', icon: Settings },
];

export function Shell({ children }: PropsWithChildren) {
  return (
    <div className="site-shell">
      <header className="masthead">
        <NavLink to="/" className="brand" aria-label="返回封面">
          <span className="brand-mark"><Stamp size={21} /></span>
          <span>
            <strong>NUMAZU PILGRIMAGE NOTES</strong>
            <small>沼津巡礼记忆库 · PRIVATE COLLECTION</small>
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
        <span>沼津 · 内浦 · 旅程记录</span>
        <span>车票、照片与心情，只收进自己的档案柜。</span>
        <span>PRIVATE ARCHIVE · {new Date().getFullYear()}</span>
      </footer>
    </div>
  );
}
