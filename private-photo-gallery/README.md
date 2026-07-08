# Sora's Private Photo Space

属于 takanashi.moe 体系的私人在线相册：以轻透的海边空气感、个人主页气质和克制的收藏感为核心。网页部署在公开的 GitHub Pages，原始照片与相册元数据只保存在私有 `photo-vault` 仓库中。

## 功能

- 海边晨光式首页与最近照片
- 写真浏览、整理模式两种照片布局
- 地点、日期、心情、标签、纪念册与旅程章节
- 轻量照片注记、地点、心情与拍摄日期
- 批量拖放上传、基础 EXIF 拍摄时间读取和删除
- 照片标题、说明、标签及相册关系写回私有 manifest
- Web Share 系统分享；不支持时回退为本机下载
- Token 默认仅保存在当前会话，可选择在可信设备记住
- 尊重 `prefers-reduced-motion`，移动设备自动降低动态效果

## 本地开发

需要 Node.js 22。

```bash
npm install
npm run dev
```

开发地址：

```text
http://127.0.0.1:5173/secure_crypto_web/private-photo-gallery/
```

常用检查：

```bash
npm run typecheck
npm test
npm run build
```

## 私有仓库

默认连接：

```text
takanashi-sora/photo-vault
└── photos/
    ├── *.jpg
    └── .photo-vault/
        └── manifest.json
```

`manifest.json` 会在第一次保存照片信息或创建相册时自动生成。现有照片不需要迁移；没有元数据的照片仍会正常显示。

GitHub Fine-grained Token 只需：

1. 仅授权 `photo-vault` 仓库。
2. Repository permissions 中开启 `Contents: Read and write`。
3. 其他权限保持 `No access`。

图片通过 GitHub API 读取，并在浏览器中转成临时 Blob URL。应用不会创建公开 raw 链接，也不会写入 GPS 信息。

## 部署

Vite 的基础路径固定为：

```text
/secure_crypto_web/private-photo-gallery/
```

根目录 GitHub Actions 会执行测试与构建，再把原有加密工具和相册产物合并成同一个 Pages artifact。因此根页面与相册路径会同时保留：

- `https://takanashi-sora.github.io/secure_crypto_web/`
- `https://takanashi-sora.github.io/secure_crypto_web/private-photo-gallery/`

仓库 Settings → Pages 的 Source 需要选择 **GitHub Actions**。
