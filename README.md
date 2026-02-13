# 🔒 安全加密工具 Secure Crypto Tool

一个美观、安全的网页加密/解密工具，可部署在 GitHub Pages 上，完美支持 iPad 和移动设备。

A beautiful, secure web-based encryption/decryption tool that can be deployed on GitHub Pages, with perfect support for iPad and mobile devices.

## ✨ 特性 Features

- 🔐 **AES-256 加密** - 使用行业标准的 AES-256 加密算法
- 🎨 **优美界面** - 现代化、响应式的用户界面设计
- 📱 **移动友好** - 完美支持 iPad、iPhone 和其他移动设备
- 🌐 **离线运行** - 所有操作在浏览器本地完成，无需网络连接
- 🔒 **隐私保护** - 数据不会发送到任何服务器
- 💾 **便捷操作** - 支持复制、下载加密/解密结果
- 🌍 **双语支持** - 中英文双语界面

## 🚀 在线使用 Live Demo

访问 GitHub Pages 部署的版本：`https://takanashi-sora.github.io/secure_crypto_web/`

部署后即可直接使用，无需任何配置！

## 📖 使用说明 Usage Guide

### 加密内容 Encrypt Content

1. 点击「加密 Encrypt」标签
2. 在文本框中输入要加密的内容（代码、文本等）
3. 输入一个强密码（建议至少8位，包含字母、数字、符号）
4. 点击「加密内容 Encrypt Content」按钮
5. 复制或下载加密后的文本进行安全保存

### 解密内容 Decrypt Content

1. 点击「解密 Decrypt」标签
2. 粘贴之前加密的文本
3. 输入加密时使用的密码
4. 点击「解密内容 Decrypt Content」按钮
5. 查看、复制或下载解密后的原始内容

## 🔧 本地运行 Local Development

```bash
# 克隆仓库
git clone https://github.com/[your-username]/secure_crypto_web.git

# 进入目录
cd secure_crypto_web

# 使用任何 HTTP 服务器运行，例如：
python -m http.server 8000
# 或
npx serve
```

然后在浏览器中访问 `http://localhost:8000`

### Python 桌面版工具 (单文件) / Python Desktop Tool (Single File)

项目新增 `secure_crypto_tool.py`，提供与网页版相同的 AES-256-GCM + PBKDF2-SHA256(100000 次) 加密逻辑和双语图形界面。

```bash
pip install "cryptography>=46.0.5"
python secure_crypto_tool.py
```

## 📦 部署到 GitHub Pages Deploy to GitHub Pages

### 方法 1: 使用 GitHub 界面 (推荐)

1. 进入仓库的 **Settings** (设置)
2. 在左侧菜单找到 **Pages** 选项
3. 在 **Source** (源) 下选择：
   - Branch: `main` (或你的默认分支)
   - Folder: `/ (root)`
4. 点击 **Save** (保存)
5. 等待几分钟，GitHub 会自动构建和部署
6. 部署完成后，访问：`https://takanashi-sora.github.io/secure_crypto_web/`

### 方法 2: 使用 GitHub Actions (自动化)

GitHub Pages 会自动检测静态网站并部署，无需额外配置！

### 验证部署

部署成功后，你会在 Pages 设置页面看到：
> ✅ Your site is live at https://takanashi-sora.github.io/secure_crypto_web/

## ⚙️ 配置说明

本应用是纯静态网站，无需任何后端服务器或数据库：
- ✅ 直接部署到 GitHub Pages
- ✅ 可部署到任何静态网站托管服务 (Netlify, Vercel, Cloudflare Pages 等)
- ✅ 可在本地文件系统直接打开 `index.html` 使用
- ✅ 所有加密操作在浏览器本地完成

## 🔐 安全提示 Security Notes

- ⚠️ **妥善保管密码** - 丢失密码将无法解密数据
- 🔑 **使用强密码** - 建议至少8位，包含大小写字母、数字和特殊字符
- 💾 **备份重要数据** - 建议对重要的加密数据进行备份
- 🔒 **本地运行** - 所有加密/解密操作都在浏览器本地完成，数据不会被上传
- 🌐 **HTTPS访问** - GitHub Pages 提供 HTTPS，确保访问安全

## 🛠️ 技术栈 Tech Stack

- HTML5
- CSS3 (响应式设计)
- JavaScript (ES6+)
- Web Crypto API (Native browser AES-256 encryption)

## 📄 许可证 License

MIT License

## 🤝 贡献 Contributing

欢迎提交 Issue 和 Pull Request！

## 📱 浏览器兼容性 Browser Compatibility

- ✅ Chrome/Edge (推荐)
- ✅ Firefox
- ✅ Safari (包括 iOS)
- ✅ 移动浏览器

---

Made with ❤️ for secure and private encryption
