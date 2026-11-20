import AVFoundation
import SwiftUI
import UIKit

struct QRScannerSheetView: View {
    let onScanned: (String) -> Void
    @Environment(\.dismiss) private var dismiss

    @State private var permissionStatus: AVAuthorizationStatus = AVCaptureDevice.authorizationStatus(for: .video)
    @State private var torchOn = false
    @State private var statusHint = "将节点二维码（gft3://）放入框内"

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()

            switch permissionStatus {
            case .authorized:
                QRScannerRepresentable(
                    torchOn: $torchOn,
                    onCodeScanned: { code in
                        let generator = UINotificationFeedbackGenerator()
                        generator.notificationOccurred(.success)
                        onScanned(code)
                    },
                    onCameraError: { errMsg in
                        statusHint = errMsg
                    }
                )
                .ignoresSafeArea()

                scannerOverlay

            case .notDetermined:
                VStack(spacing: 14) {
                    ProgressView()
                        .tint(.white)
                    Text("正在请求相机权限...")
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundColor(.white)
                }
                .onAppear {
                    AVCaptureDevice.requestAccess(for: .video) { granted in
                        DispatchQueue.main.async {
                            permissionStatus = granted ? .authorized : .denied
                        }
                    }
                }

            default:
                VStack(spacing: 16) {
                    Image(systemName: "camera.fill")
                        .font(.system(size: 40))
                        .foregroundColor(Color(red: 0.024, green: 0.714, blue: 0.831))
                    Text("需要相机权限以扫描节点二维码")
                        .font(.system(size: 16, weight: .bold))
                        .foregroundColor(.white)
                    Text("请在 iOS“设置 -> 隐私与安全性 -> 相机”中允许访问相机。")
                        .font(.system(size: 13))
                        .foregroundColor(.gray)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 24)

                    Button("打开系统设置") {
                        if let url = URL(string: UIApplication.openSettingsURLString) {
                            UIApplication.shared.open(url)
                        }
                    }
                    .font(.system(size: 14, weight: .bold))
                    .foregroundColor(.black)
                    .padding(.horizontal, 22)
                    .padding(.vertical, 11)
                    .background(Color(red: 0.024, green: 0.714, blue: 0.831))
                    .cornerRadius(10)

                    Button("关闭") { dismiss() }
                        .font(.system(size: 14))
                        .foregroundColor(.white.opacity(0.8))
                        .padding(.top, 6)
                }
            }
        }
    }

    private var scannerOverlay: some View {
        VStack {
            HStack {
                Button(action: { dismiss() }) {
                    Image(systemName: "xmark")
                        .font(.system(size: 16, weight: .bold))
                        .foregroundColor(.white)
                        .padding(11)
                        .background(Color.black.opacity(0.55))
                        .clipShape(Circle())
                }

                Spacer()

                Button(action: { torchOn.toggle() }) {
                    HStack(spacing: 6) {
                        Image(systemName: torchOn ? "flashlight.on.fill" : "flashlight.off.fill")
                        Text(torchOn ? "关闭照明" : "手电筒")
                    }
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundColor(torchOn ? .black : .white)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .background(torchOn ? Color(red: 0.961, green: 0.620, blue: 0.043) : Color.black.opacity(0.55))
                    .cornerRadius(18)
                }
            }
            .padding(.horizontal, 18)
            .padding(.top, 16)

            Spacer()

            RoundedRectangle(cornerRadius: 18)
                .stroke(Color(red: 0.024, green: 0.714, blue: 0.831), lineWidth: 2.5)
                .frame(width: 245, height: 245)
                .background(Color.white.opacity(0.03))
                .cornerRadius(18)

            Text(statusHint)
                .font(.system(size: 13, weight: .medium))
                .foregroundColor(.white)
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
                .background(Color.black.opacity(0.6))
                .cornerRadius(12)
                .padding(.top, 18)

            Spacer()
        }
    }
}

private struct QRScannerRepresentable: UIViewControllerRepresentable {
    @Binding var torchOn: Bool
    let onCodeScanned: (String) -> Void
    let onCameraError: (String) -> Void

    func makeUIViewController(context: Context) -> QRScannerViewController {
        let vc = QRScannerViewController()
        vc.onCodeScanned = onCodeScanned
        vc.onCameraError = onCameraError
        return vc
    }

    func updateUIViewController(_ uiViewController: QRScannerViewController, context: Context) {
        uiViewController.setTorch(torchOn)
    }
}

private final class QRScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onCodeScanned: ((String) -> Void)?
    var onCameraError: ((String) -> Void)?

    private let sessionQueue = DispatchQueue(label: "com.ghostframe.qrscanner.session")
    private let captureSession = AVCaptureSession()
    private var previewLayer: AVCaptureVideoPreviewLayer?
    private var isConfigured = false
    private var didEmitCode = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black

        let preview = AVCaptureVideoPreviewLayer(session: captureSession)
        preview.videoGravity = .resizeAspectFill
        preview.frame = view.bounds
        view.layer.addSublayer(preview)
        previewLayer = preview

        configureAndStartSession()
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.bounds
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        setTorch(false)
        sessionQueue.async { [captureSession] in
            if captureSession.isRunning {
                captureSession.stopRunning()
            }
        }
    }

    func setTorch(_ enabled: Bool) {
        sessionQueue.async {
            guard let device = AVCaptureDevice.default(for: .video), device.hasTorch else { return }
            do {
                try device.lockForConfiguration()
                if enabled && device.isTorchModeSupported(.on) {
                    try device.setTorchModeOn(level: AVCaptureDevice.maxAvailableTorchLevel)
                } else if device.isTorchModeSupported(.off) {
                    device.torchMode = .off
                }
                device.unlockForConfiguration()
            } catch {
                // Best effort torch toggle.
            }
        }
    }

    private func configureAndStartSession() {
        sessionQueue.async { [weak self] in
            guard let self = self else { return }
            if !self.isConfigured {
                guard let videoDevice = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: .back)
                        ?? AVCaptureDevice.default(for: .video) else {
                    DispatchQueue.main.async {
                        self.onCameraError?("未检测到可用后置摄像头")
                    }
                    return
                }
                do {
                    let input = try AVCaptureDeviceInput(device: videoDevice)
                    self.captureSession.beginConfiguration()
                    if self.captureSession.canAddInput(input) {
                        self.captureSession.addInput(input)
                    }
                    let metadataOutput = AVCaptureMetadataOutput()
                    if self.captureSession.canAddOutput(metadataOutput) {
                        self.captureSession.addOutput(metadataOutput)
                        metadataOutput.setMetadataObjectsDelegate(self, queue: DispatchQueue.main)
                        if metadataOutput.availableMetadataObjectTypes.contains(.qr) {
                            metadataOutput.metadataObjectTypes = [.qr]
                        }
                    }
                    self.captureSession.commitConfiguration()
                    self.isConfigured = true
                } catch {
                    self.captureSession.commitConfiguration()
                    DispatchQueue.main.async {
                        self.onCameraError?("相机初始化失败: \(error.localizedDescription)")
                    }
                    return
                }
            }
            if !self.captureSession.isRunning {
                self.captureSession.startRunning()
            }
        }
    }

    func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard !didEmitCode,
              let readable = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              readable.type == .qr,
              let raw = readable.stringValue?.trimmingCharacters(in: .whitespacesAndNewlines),
              !raw.isEmpty else {
            return
        }
        didEmitCode = true
        sessionQueue.async { [captureSession] in
            if captureSession.isRunning {
                captureSession.stopRunning()
            }
        }
        onCodeScanned?(raw)
    }
}
