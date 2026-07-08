# Sora Photo Vault

GitHub Pages 静态照片管理器。

功能：

- 在线浏览仓库图片
- 拖拽上传图片到 `photo-gallery/photos/`
- GitHub Contents API 直接提交图片
- 图片预览、复制直链、删除

访问路径：

```
https://takanashi-sora.github.io/secure_crypto_web/photo-gallery/
```

首次使用：

1. 在 GitHub 创建一个 fine-grained personal access token。
2. 只授权本仓库的 Contents Read and Write 权限。
3. 在网页中输入 Token。
4. Token 只保存于浏览器 localStorage，不会写入仓库。

注意：公开仓库中的图片也是公开的。该工具适合个人展示相册，不适合作为大量私密照片云盘。
