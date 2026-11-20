import AVFoundation
import Foundation

final class SilentAudioKeepAlive {
    private let audioEngine = AVAudioEngine()
    private let playerNode = AVAudioPlayerNode()
    private var silenceBuffer: AVAudioPCMBuffer?
    private var pcmFormat: AVAudioFormat?
    private var isStarted = false
    private var interruptionObserver: NSObjectProtocol?
    private var configChangeObserver: NSObjectProtocol?

    init() {
        interruptionObserver = NotificationCenter.default.addObserver(
            forName: AVAudioSession.interruptionNotification,
            object: AVAudioSession.sharedInstance(),
            queue: .main
        ) { [weak self] notification in
            self?.handleInterruption(notification)
        }
        configChangeObserver = NotificationCenter.default.addObserver(
            forName: .AVAudioEngineConfigurationChange,
            object: audioEngine,
            queue: .main
        ) { [weak self] _ in
            guard let self = self, self.isStarted else { return }
            self.restartPipeline()
        }
    }

    deinit {
        stop()
        if let observer = interruptionObserver {
            NotificationCenter.default.removeObserver(observer)
        }
        if let observer = configChangeObserver {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    var isActive: Bool { isStarted }

    func start() {
        guard !isStarted else { return }
        isStarted = true
        restartPipeline()
    }

    func stop() {
        guard isStarted else { return }
        isStarted = false
        playerNode.stop()
        audioEngine.stop()
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
    }

    private func restartPipeline() {
        guard isStarted else { return }
        do {
            let session = AVAudioSession.sharedInstance()
            try session.setCategory(.playback, mode: .default, options: [.mixWithOthers])
            try session.setActive(true)

            if pcmFormat == nil {
                pcmFormat = AVAudioFormat(standardFormatWithSampleRate: 16000, channels: 1)
            }
            guard let format = pcmFormat else { return }

            if silenceBuffer == nil,
               let buf = AVAudioPCMBuffer(pcmFormat: format, frameCapacity: 16000) {
                buf.frameLength = 16000
                if let channelData = buf.floatChannelData {
                    memset(channelData[0], 0, Int(buf.frameCapacity) * MemoryLayout<Float>.size)
                }
                silenceBuffer = buf
            }
            guard let buffer = silenceBuffer else { return }

            if !audioEngine.attachedNodes.contains(playerNode) {
                audioEngine.attach(playerNode)
                audioEngine.connect(playerNode, to: audioEngine.mainMixerNode, format: format)
            }
            audioEngine.mainMixerNode.outputVolume = 0.0

            if !audioEngine.isRunning {
                try audioEngine.start()
            }
            playerNode.stop()
            playerNode.scheduleBuffer(buffer, at: nil, options: .loops, completionHandler: nil)
            playerNode.play()
        } catch {
            // Best-effort keepalive; foreground proxy operation remains unaffected.
        }
    }

    private func handleInterruption(_ notification: Notification) {
        guard isStarted,
              let info = notification.userInfo,
              let typeRaw = info[AVAudioSessionInterruptionTypeKey] as? UInt,
              let type = AVAudioSession.InterruptionType(rawValue: typeRaw) else {
            return
        }
        if type == .ended {
            restartPipeline()
        }
    }
}
