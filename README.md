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

访问 GitHub Pages 部署的版本：`https://[your-username].github.io/secure_crypto_web/`

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

## 📦 部署到 GitHub Pages Deploy to GitHub Pages

1. 进入仓库的 Settings
2. 找到 Pages 选项
3. 在 Source 下选择 `main` 分支和 `/ (root)` 目录
4. 点击 Save
5. 等待几分钟后，你的应用就会发布到 `https://[your-username].github.io/secure_crypto_web/`

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
- CryptoJS (AES-256 加密库)

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