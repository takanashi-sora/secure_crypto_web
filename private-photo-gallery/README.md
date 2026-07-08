# Sora Private Photo Vault

这是“公开 GitHub Pages 前端 + 私有 GitHub 仓库存照片”的版本。

## 访问地址

```text
https://takanashi-sora.github.io/secure_crypto_web/private-photo-gallery/
```

## 推荐仓库结构

公开仓库：

```text
secure_crypto_web/
└── private-photo-gallery/
    └── index.html
```

私有照片仓库：

```text
photo-vault/
└── photos/
    └── .gitkeep
```

## 首次设置

1. 在 GitHub 新建一个私有仓库，推荐命名为 `photo-vault`。
2. 在仓库内创建 `photos/.gitkeep`，用于初始化照片目录。
3. 创建 fine-grained personal access token。
4. Token 只授权 `photo-vault` 这个仓库。
5. Repository permissions 中只需要 `Contents: Read and write`。
6. 打开网页，填写 Token、Owner、Repository、Branch、Folder。
7. 点击“保存本机设置”，然后点击“读取私有相册”。

## 工作方式

- 网页本体是公开的 GitHub Pages。
- 照片不存放在公开 Pages 仓库里。
- 照片通过 GitHub API 从私有仓库读取。
- 图片预览会在浏览器中生成临时 Blob URL。
- 不生成公开 raw 图片直链。
- Token 只保存在当前浏览器 localStorage，不会提交到 GitHub 仓库。

## 注意事项

- 不要在公共电脑上输入 Token。
- 私有仓库里的照片仍然占用 GitHub 仓库体积，不适合作为大量原图网盘。
- 如果照片达到几百张以上，建议迁移到 Cloudflare R2 / B2 / Immich 等更适合相册的方案。
