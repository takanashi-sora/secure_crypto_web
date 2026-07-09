import type { CSSProperties } from 'react';
import type { ThemeId } from './types';

type Counts = {
  photos: number;
  albums: number;
};

export interface GalleryTheme {
  id: ThemeId;
  name: string;
  shortName: string;
  className: string;
  description: string;
  colors: {
    deep: string;
    accent: string;
    accentSoft: string;
    water: string;
    sky: string;
    violet: string;
    cream: string;
  };
  assets: {
    heroBg: string;
    roomBg: string;
    motif: string;
    mapLine: string;
    scenes: {
      home: string;
      library: string;
      albums: string;
      upload: string;
      viewer: string;
    };
  };
  motifs: string[];
  navigation: {
    home: string;
    library: string;
    albums: string;
    upload: string;
    settings: string;
  };
  site: {
    brand: string;
    tagline: string;
    footer: string;
  };
  hero: {
    kicker: string;
    title: string;
    emphasis: string;
    intro: string;
    notes: string[];
    ctaConnected: string;
    ctaDisconnected: string;
    secondaryCta: string;
    connectedStatus: (photos: number) => string;
    idleStatus: string;
    boardLabel: string;
    boardSubLabel: string;
    timetableLabel: string;
    timetableItems: string[];
    noteLabel: string;
    noteText: string;
    routeTitle: string;
    routeText: string;
    emptyHero: string;
  };
  home: {
    roomEyebrow: string;
    roomTitle: string;
    roomNote: string;
    rooms: Array<{
      key: string;
      to: string;
      mark: string;
      title: string;
      summary: (counts: Counts) => string;
    }>;
    latestEyebrow: string;
    latestTitle: string;
    latestNote: string;
    albumUnit: string;
    photoUnit: string;
  };
  library: {
    eyebrow: string;
    title: string;
    note: string;
    searchPlaceholder: string;
    newestSort: string;
    nameSort: string;
    sizeSort: string;
    favorite: string;
    editorialMode: string;
    archiveMode: string;
    editorialNote: string;
    archiveNote: string;
    allTags: string;
  };
  albums: {
    eyebrow: string;
    title: string;
    note: string;
    create: string;
    emptyTitle: string;
    emptyNote: string;
    drawerLabel: string;
    untitledDescription: string;
    createEyebrow: string;
    createTitle: string;
    titleLabel: string;
    titlePlaceholder: string;
    descriptionLabel: string;
    descriptionPlaceholder: string;
    submit: string;
  };
  upload: {
    eyebrow: string;
    title: string;
    note: string;
    dropTitle: string;
    checkinLabel: string;
    checkinTitle: string;
    submit: string;
    submitting: string;
  };
  photoGrid: {
    emptyTitle: string;
    emptyDefault: string;
    memoryBadge: string;
  };
  viewer: {
    sticker: string;
    noteKicker: string;
    chaptersLabel: string;
    favoriteOn: string;
    favoriteOff: string;
    editButton: string;
    editEyebrow: string;
    editTitle: string;
    themeLabel: string;
    locationPlaceholder: string;
    moodPlaceholder: string;
    tagsPlaceholder: string;
  };
}

const generated = (path: string) => `assets/themes/${path}`;

export const themes: Record<string, GalleryTheme> = {
  'numazu-seaside': {
    id: 'numazu-seaside',
    name: 'Numazu / Uchiura Seaside',
    shortName: 'Numazu Seaside',
    className: 'theme-numazu-seaside',
    description: '沼津、内浦、海边道路、放学后与学园偶像世界边缘的空气。',
    colors: {
      deep: '#103a58',
      accent: '#f49b3d',
      accentSoft: '#fff0d4',
      water: '#83d4ee',
      sky: '#dff7ff',
      violet: '#cbc7ff',
      cream: '#fff8ec',
    },
    assets: {
      heroBg: generated('numazu/hero-bg.webp'),
      roomBg: generated('numazu/hero-bg.webp'),
      motif: generated('numazu/motif.svg'),
      mapLine: generated('numazu/map-line.svg'),
      scenes: {
        home: generated('numazu/hero-scene.webp'),
        library: generated('numazu/wall-scene.webp'),
        albums: generated('numazu/route-scene.webp'),
        upload: generated('numazu/upload-scene.webp'),
        viewer: generated('numazu/viewer-scene.webp'),
      },
    },
    motifs: ['海边道路', '内浦湾', '远山', '巴士站', '部室照片墙', '路线本', '蜜柑橙'],
    navigation: {
      home: '主题馆',
      library: '照片墙',
      albums: '路线本',
      upload: '带回',
      settings: '设置',
    },
    site: {
      brand: 'SORA THEME GALLERY',
      tagline: 'takanashi.moe / numazu seaside theme',
      footer: '沼津海边、放学后的光、还有我带回来的普通一天。',
    },
    hero: {
      kicker: 'numazu-seaside default theme',
      title: '沼津海边，',
      emphasis: '今天也开馆。',
      intro:
        '当前主题是沼津 / 内浦：海边道路、站牌、远山、部室照片墙和路线本会包住你的照片。它有学园偶像世界的空气，但照片、记忆和入口都属于 takanashi.moe。',
      notes: ['内浦湾', '放課後', 'みかん色'],
      ctaConnected: '进入沼津照片馆',
      ctaDisconnected: '连接私人照片库',
      secondaryCta: '把今天带回主题馆',
      connectedStatus: (photos) => `${photos} 张照片 · 默认收入 Numazu Seaside 主题`,
      idleStatus: '照片只从你的私有仓库读取；主题包装在本地页面生效',
      boardLabel: 'numazu memory wall',
      boardSubLabel: 'after school / bay route',
      timetableLabel: 'BAY BUS',
      timetableItems: ['07:42', '16:18', '18:03'],
      noteLabel: 'theme note',
      noteText: '海边路的白线、远山和练习后的风，会先替这一页开场。',
      routeTitle: '坂道 → 海边路 → 小码头',
      routeText: '下一页从这条路线走进去。',
      emptyHero: '第一张照片会成为 Numazu Seaside 的入口',
    },
    home: {
      roomEyebrow: 'THEME MAP',
      roomTitle: '当前主题馆：Numazu Seaside',
      roomNote:
        '这不是固定成沼津的相册，而是一套主题化照片馆结构。现在默认进入沼津海边馆；未来可以切换成函馆雪夜、金泽城下町、吴港、钏路冬日。',
      rooms: [
        {
          key: 'photo',
          to: '/library',
          mark: '01',
          title: '照片墙',
          summary: ({ photos }) => (photos ? `${photos} 张照片贴在当前主题馆` : '等第一张照片亮起来'),
        },
        {
          key: 'route',
          to: '/albums',
          mark: '02',
          title: '路线本',
          summary: ({ albums }) => (albums ? `${albums} 条沼津路线 / 章节` : '把一次出行写成章节'),
        },
        {
          key: 'keepsake',
          to: '/library',
          mark: '★',
          title: '反复翻看的东西',
          summary: () => '在照片墙里点亮珍藏。',
        },
        {
          key: 'upload',
          to: '/upload',
          mark: '＋',
          title: '把今天带回主题馆',
          summary: () => '新照片会带着默认主题写入元数据。',
        },
      ],
      latestEyebrow: 'RECENT IN THIS THEME',
      latestTitle: '刚收入主题馆的片刻',
      latestNote: '最近照片先被放到当前主题馆里：让主题负责开场，照片负责记忆本身。',
      albumUnit: '条路线',
      photoUnit: '张照片',
    },
    library: {
      eyebrow: 'THEME PHOTO WALL',
      title: '照片墙',
      note: '这里展示当前私人照片库里的照片。没有单独指定主题时，会按 Numazu Seaside 的照片墙语言来包装；以后照片可带自己的 themeId。',
      searchPlaceholder: '找某一天、某段坡道、某张海边照片，或未来的其它主题',
      newestSort: '按最近的光',
      nameSort: '按名字翻',
      sizeSort: '按文件大小',
      favorite: '珍藏',
      editorialMode: '主题墙',
      archiveMode: '索引板',
      editorialNote: '像贴在主题馆墙上的照片，保留地点空气和私人收藏感。',
      archiveNote: '像把墙上的照片取下来排成索引板，方便查找主题、地点、章节和心情。',
      allTags: '全部标签',
    },
    albums: {
      eyebrow: 'ROUTE NOTEBOOK',
      title: '路线本',
      note: '把一次出行写成一条主题路线：坡道、海边道路、车站、码头和那天的心情，都可以收进同一章。',
      create: '写下新路线',
      emptyTitle: '路线本还空着',
      emptyNote: '先写下一条路线，再从照片注记里把喜欢的片刻放进去。',
      drawerLabel: 'ROUTE NOTEBOOK',
      untitledDescription: '还没有写下这段路线的说明。',
      createEyebrow: 'NEW ROUTE',
      createTitle: '写下一条新的路线',
      titleLabel: '路线名称',
      titlePlaceholder: '例如：夏日傍晚的海边路',
      descriptionLabel: '路线说明',
      descriptionPlaceholder: '那天经过了哪里，又把什么带回来了',
      submit: '写进路线本',
    },
    upload: {
      eyebrow: 'BRING TODAY BACK',
      title: '把今天，\n带回主题馆。',
      note: '像回到房间后把照片放到桌上：先在本机读取日期与尺寸，再安全写入私有仓库；GPS 信息不会被保存。',
      dropTitle: '把今天带回来的照片放到这里',
      checkinLabel: 'THEME CHECK-IN',
      checkinTitle: '放进\n主题馆前',
      submit: '放进照片墙',
      submitting: '收进主题馆',
    },
    photoGrid: {
      emptyTitle: '这面主题墙还没有照片',
      emptyDefault: '换个筛选条件，或把今天喜欢的一张贴上来。',
      memoryBadge: 'theme',
    },
    viewer: {
      sticker: 'numazu note',
      noteKicker: 'THEME NOTE',
      chaptersLabel: '路线本',
      favoriteOn: '已经放进小收藏',
      favoriteOff: '收入小收藏',
      editButton: '补一点注记',
      editEyebrow: 'EDIT PHOTO NOTE',
      editTitle: '编辑照片注记',
      themeLabel: '照片主题',
      locationPlaceholder: '例如：内浦长井崎',
      moodPlaceholder: '例如：海风很舒服',
      tagsPlaceholder: '海岸, 车站, 夏日',
    },
  },
};

const futureThemes: GalleryTheme[] = [
  {
    ...themes['numazu-seaside'],
    id: 'hakodate-snow',
    name: 'Hakodate Snow Night',
    shortName: 'Hakodate Snow',
    className: 'theme-hakodate-snow',
    description: '函馆、雪、夜景、港口、坡道与 Saint Snow 气味的预留主题。',
    colors: { ...themes['numazu-seaside'].colors, accent: '#9bbcff', water: '#c9e9ff', cream: '#f7fbff' },
    motifs: ['雪', '夜景', '港口', '坡道', '路灯'],
  },
  {
    ...themes['numazu-seaside'],
    id: 'kanazawa-town',
    name: 'Kanazawa Old Town',
    shortName: 'Kanazawa Town',
    className: 'theme-kanazawa-town',
    description: '金泽、城下町、雨、茶屋街与蓮の空气味的预留主题。',
    colors: { ...themes['numazu-seaside'].colors, accent: '#b88a54', water: '#b9d7cf', cream: '#fff7e8' },
    motifs: ['城下町', '雨', '茶屋街', '石板路', '纸伞'],
  },
  {
    ...themes['numazu-seaside'],
    id: 'kure-harbor',
    name: 'Kure Harbor',
    shortName: 'Kure Harbor',
    className: 'theme-kure-harbor',
    description: '吴、港口、舰船、海军与濑户内海的预留主题。',
    colors: { ...themes['numazu-seaside'].colors, accent: '#d08d5a', water: '#8eb8cc', cream: '#fff8ef' },
    motifs: ['港口', '舰船', '码头', '濑户内海', '工业灯'],
  },
  {
    ...themes['numazu-seaside'],
    id: 'kushiro-winter',
    name: 'Kushiro Winter',
    shortName: 'Kushiro Winter',
    className: 'theme-kushiro-winter',
    description: '钏路、北国、湿原、风雪、港口与夕阳的预留主题。',
    colors: { ...themes['numazu-seaside'].colors, accent: '#e2a064', water: '#b9d4df', cream: '#fbfbf8' },
    motifs: ['湿原', '风雪', '港口', '夕阳', '北国'],
  },
];

futureThemes.forEach((theme) => {
  themes[theme.id] = theme;
});

export const DEFAULT_THEME_ID: ThemeId = 'numazu-seaside';
export const DEFAULT_THEME = themes[DEFAULT_THEME_ID];
export const themeOptions = Object.values(themes);

export function resolveTheme(themeId?: ThemeId) {
  return themes[themeId ?? DEFAULT_THEME_ID] ?? DEFAULT_THEME;
}

export function themedAsset(path: string) {
  const base = import.meta.env.BASE_URL || '/';
  return `${base}${path}`.replace(/\/{2,}/g, '/');
}

export function themeStyle(theme: GalleryTheme) {
  return {
    '--theme-deep': theme.colors.deep,
    '--theme-accent': theme.colors.accent,
    '--theme-accent-soft': theme.colors.accentSoft,
    '--theme-water': theme.colors.water,
    '--theme-sky': theme.colors.sky,
    '--theme-violet': theme.colors.violet,
    '--theme-cream': theme.colors.cream,
    '--theme-hero-bg': `url("${themedAsset(theme.assets.heroBg)}")`,
    '--theme-room-bg': `url("${themedAsset(theme.assets.roomBg)}")`,
    '--theme-home-scene': `url("${themedAsset(theme.assets.scenes.home)}")`,
    '--theme-library-scene': `url("${themedAsset(theme.assets.scenes.library)}")`,
    '--theme-albums-scene': `url("${themedAsset(theme.assets.scenes.albums)}")`,
    '--theme-upload-scene': `url("${themedAsset(theme.assets.scenes.upload)}")`,
    '--theme-viewer-scene': `url("${themedAsset(theme.assets.scenes.viewer)}")`,
  } as CSSProperties;
}
