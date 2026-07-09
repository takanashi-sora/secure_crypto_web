import { CloudSun, Images, Library, Settings, UploadCloud } from 'lucide-react';
import { NavLink } from 'react-router-dom';
import type { PropsWithChildren } from 'react';
import { themedAsset, themeStyle, type GalleryTheme } from '../themes';

interface ShellProps extends PropsWithChildren {
  theme: GalleryTheme;
}

export function Shell({ children, theme }: ShellProps) {
  const navigation = [
    { to: '/', label: theme.navigation.home, icon: CloudSun },
    { to: '/library', label: theme.navigation.library, icon: Library },
    { to: '/albums', label: theme.navigation.albums, icon: Images },
    { to: '/upload', label: theme.navigation.upload, icon: UploadCloud },
    { to: '/settings', label: theme.navigation.settings, icon: Settings },
  ];

  return (
    <div className={`site-shell ${theme.className}`} data-theme={theme.id} style={themeStyle(theme)}>
      <div className="coastal-atmosphere" aria-hidden="true">
        <img className="theme-backdrop" src={themedAsset(theme.assets.roomBg)} alt="" />
        <span className="sky-bloom bloom-one" />
        <span className="sky-bloom bloom-two" />
        <span className="distant-sun" />
        <span className="distant-mountain mountain-a" />
        <span className="distant-mountain mountain-b" />
        <span className="sea-horizon" />
        <span className="water-glint glint-one" />
        <span className="water-glint glint-two" />
        <span className="breakwater-line" />
        <span className="coast-road-line" />
        <span className="bay-railing-line" />
        <span className="little-stop-sign" />
        <span className="school-slope-line" />
        <span className="club-window-line" />
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
            <img className="theme-motif" src={themedAsset(theme.assets.motif)} alt="" />
            <span className="brand-bay" />
            <span className="brand-mikan" />
            <span className="brand-wave" />
            <span className="brand-coast" />
            <span className="brand-star">✦</span>
          </span>
          <span>
            <strong>{theme.site.brand}</strong>
            <small>{theme.site.tagline}</small>
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
        <span>{theme.shortName}</span>
        <span>{theme.site.footer}</span>
        <span>takanashi.moe · {new Date().getFullYear()}</span>
      </footer>
    </div>
  );
}
