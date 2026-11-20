# Kestrel iOS 全能签本地软件源自动同步工具 (`tools/ios-repo-sync`)

零外部依赖的纯 Go 标准库工具：自动从 GitHub Actions `Build Kestrel iOS Dual IPAs` 拉取最新成功的 `Kestrel-Duo-Unsigned.ipa` 与 `Kestrel-Air-Unsigned.ipa`，生成兼容全能签（OmniSign / ESign）与 AltStore 的 `source.json`，并在局域网开放 HTTP 服务供 iPhone 直接下拉刷新重签安装。

## 常用命令

1. **拉取最新 CI 构建产物 + 启动局域网软件源服务（默认 `0.0.0.0:18080`）**：
   ```powershell
   go run ./tools/ios-repo-sync
   ```
2. **仅拉取一次最新 CI `.ipa` 并更新 `.ios-dist/source.json`**：
   ```powershell
   go run ./tools/ios-repo-sync -once
   ```
3. **仅启动 HTTP 软件源服务（不触发拉包）**：
   ```powershell
   go run ./tools/ios-repo-sync -serve -listen 0.0.0.0:18080
   ```

## iPhone 全能签配置方式

1. 保持手机与电脑处于同一局域网（Wi-Fi），运行 `go run ./tools/ios-repo-sync`。
2. 手机浏览器访问工具打印的 `http://<局域网IP>:18080/`，点击 **「一键复制全能签软件源地址」**；或直接添加 `http://<局域网IP>:18080/source.json`。
3. 以后云端 iOS 构建完成并本地同步后，直接在全能签软件源界面 **下拉刷新** 即可识别新版本号 `4.0.0.<run_number>` 一键重签更新。
