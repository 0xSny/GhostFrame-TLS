//go:build windows

package winui

import (
	"fmt"
	"math"
	"unsafe"

	"ghostframe/internal/client"
)

const (
	trayIconID = 1

	cmdOpen      = 1001
	cmdToggle    = 1002
	cmdSysProxy  = 1003
	cmdImport    = 1004
	cmdQuit      = 1005
	cmdRouteRule = 1101
	cmdRouteGlob = 1102
	cmdRouteDir  = 1103
	cmdTransAuto = 1201
	cmdTransQUIC = 1202
	cmdTransTCP  = 1203
	cmdNodeBase  = 2000
)

// CreateVectorIcon synthesizes a crisp 32x32 ARGB vector HICON in memory
// without relying on any external .ico file.
func CreateVectorIcon(state client.ConnState) uintptr {
	const size = 32
	bmi := bitmapInfo{
		BmiHeader: bitmapInfoHeader{
			BiSize:        uint32(unsafe.Sizeof(bitmapInfoHeader{})),
			BiWidth:       size,
			BiHeight:      -size,
			BiPlanes:      1,
			BiBitCount:    32,
			BiCompression: biRGB,
		},
	}
	var bits unsafe.Pointer
	hColor, _, _ := pCreateDIBSection.Call(0, uintptr(unsafe.Pointer(&bmi)), dibRGBColors, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if hColor == 0 || bits == nil {
		return 0
	}
	defer func() { _, _, _ = pDeleteObject.Call(hColor) }()

	var maskZero [size * size / 8]byte
	hMask, _, _ := pCreateBitmap.Call(size, size, 1, 1, uintptr(unsafe.Pointer(&maskZero[0])))
	if hMask == 0 {
		return 0
	}
	defer func() { _, _, _ = pDeleteObject.Call(hMask) }()

	px := unsafe.Slice((*uint32)(bits), size*size)

	var ringA, ringB uint32
	switch state {
	case client.StateConnected:
		ringA = 0xFF10B981 // emerald
		ringB = 0xFF06B6D4 // cyan
	case client.StateConnecting:
		ringA = 0xFFF59E0B // amber
		ringB = 0xFFFBBF24
	case client.StateError:
		ringA = 0xFFEF4444 // crimson
		ringB = 0xFFF97316
	default:
		ringA = 0xFF64748B // cool slate
		ringB = 0xFF94A3B8
	}

	const bgDark = uint32(0xFF0B1220)
	const center = 15.5
	const outerR = 14.2
	const innerR = 11.4

	for y := 0; y < size; y++ {
		fy := float32(y) + 0.5
		for x := 0; x < size; x++ {
			fx := float32(x) + 0.5
			dx := fx - center
			dy := fy - center
			dist := float32(math.Hypot(float64(dx), float64(dy)))

			// Rounded dark shield base
			baseAlpha := clamp01(0.6 - (dist - outerR))
			if baseAlpha <= 0 {
				px[y*size+x] = 0
				continue
			}

			// Gradient color along diagonal
			gradT := clamp01((dx + dy + 22.0) / 44.0)
			ringCol := lerpColor(ringA, ringB, gradT)

			// Outer colored ring band
			ringDist := float32(math.Abs(float64(dist - (outerR-1.3))))
			ringMix := clamp01(1.3 - ringDist)

			// Stylized inner spectral prism / chevron emblem
			// Upper diagonal + lower chevron forming a futuristic "G" shard
			ax := float32(math.Abs(float64(dx)))
			dTop := float32(math.Abs(float64((dy + 2.5) - (-ax*0.55))))
			dLeft := float32(math.Abs(float64(dx+3.2))) + maxF32(0, float32(math.Abs(float64(dy)))-4.6)*4
			dBar := float32(math.Abs(float64(dy-1.2))) + maxF32(0, -dx)*4 + maxF32(0, dx-5.2)*4
			dRightStem := float32(math.Abs(float64(dx-4.2))) + maxF32(0, -(dy-1.2))*4 + maxF32(0, dy-5.0)*4
			dBot := float32(math.Abs(float64((dy-4.6) - (-dx*0.18)))) + maxF32(0, float32(math.Abs(float64(dx)))-4.5)*4

			glyphD := minF32(dTop+maxF32(0, ax-5.2)*4, minF32(dLeft, minF32(dBar, minF32(dRightStem, dBot))))
			glyphMix := float32(0)
			if dist < innerR-1.0 {
				glyphMix = clamp01(1.35 - glyphD)
			}

			col := bgDark
			if ringMix > 0 {
				col = lerpColor(col, ringCol, ringMix)
			}
			if glyphMix > 0 {
				col = lerpColor(col, lerpColor(ringB, 0xFFF8FAFC, 0.55), glyphMix)
			}

			r := uint32(float32((col>>16)&0xFF) * baseAlpha)
			g := uint32(float32((col>>8)&0xFF) * baseAlpha)
			b := uint32(float32(col&0xFF) * baseAlpha)
			a := uint32(255.0 * baseAlpha)
			px[y*size+x] = (a << 24) | (r << 16) | (g << 8) | b
		}
	}

	ii := iconInfo{
		FIcon:    1,
		HbmMask:  hMask,
		HbmColor: hColor,
	}
	hIcon, _, _ := pCreateIconIndirect.Call(uintptr(unsafe.Pointer(&ii)))
	return hIcon
}

func clamp01(v float32) float32 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

type trayManager struct {
	hwnd      uintptr
	added     bool
	icons     map[client.ConnState]uintptr
	lastState client.ConnState
	lastTip   string
}

func newTrayManager(hwnd uintptr) *trayManager {
	tm := &trayManager{
		hwnd: hwnd,
		icons: map[client.ConnState]uintptr{
			client.StateDisconnected: CreateVectorIcon(client.StateDisconnected),
			client.StateConnecting:   CreateVectorIcon(client.StateConnecting),
			client.StateConnected:    CreateVectorIcon(client.StateConnected),
			client.StateError:        CreateVectorIcon(client.StateError),
		},
	}
	tm.addOrModify(client.StateDisconnected, "GhostFrame-Pro | 未连接")
	return tm
}

func (tm *trayManager) iconFor(st client.ConnState) uintptr {
	if ic := tm.icons[st]; ic != 0 {
		return ic
	}
	return tm.icons[client.StateDisconnected]
}

func (tm *trayManager) addOrModify(state client.ConnState, tip string) {
	if tm.hwnd == 0 {
		return
	}
	if tm.added && state == tm.lastState && tip == tm.lastTip {
		return
	}
	ic := tm.iconFor(state)
	nid := notifyIconDataW{
		CbSize:           uint32(unsafe.Sizeof(notifyIconDataW{})),
		HWnd:             tm.hwnd,
		UID:              trayIconID,
		UFlags:           nifMessage | nifIcon | nifTip,
		UCallbackMessage: wmAppTray,
		HIcon:            ic,
		UVersion:         notifyIconV4,
	}
	copyUTF16(nid.SzTip[:], tip)

	if !tm.added {
		ok, _, _ := pShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&nid)))
		if ok != 0 {
			tm.added = true
			_, _, _ = pShellNotifyIconW.Call(nimSetVersion, uintptr(unsafe.Pointer(&nid)))
		}
	} else {
		_, _, _ = pShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&nid)))
	}
	tm.lastState = state
	tm.lastTip = tip
}

func (tm *trayManager) update(st map[string]any) {
	state := client.ConnState(strVal(st["state"]))
	mode := strVal(st["active_transport"])
	if mode == "" {
		mode = strVal(st["transport_pref"])
	}
	ping := intVal(st["ping_ms"])
	node := strVal(st["node_name"])

	var tip string
	switch state {
	case client.StateConnected:
		if ping > 0 {
			tip = fmt.Sprintf("GhostFrame-Pro | 已连接 (%s %dms)\n节点: %s", mode, ping, node)
		} else {
			tip = fmt.Sprintf("GhostFrame-Pro | 已连接 (%s)\n节点: %s", mode, node)
		}
	case client.StateConnecting:
		tip = fmt.Sprintf("GhostFrame-Pro | 正在连接 %s...", node)
	case client.StateError:
		tip = "GhostFrame-Pro | 连接异常（点击查看日志）"
	default:
		tip = "GhostFrame-Pro | 未连接（待机中）"
	}
	tm.addOrModify(state, tip)
}

func (tm *trayManager) destroy() {
	if tm.added && tm.hwnd != 0 {
		nid := notifyIconDataW{
			CbSize: uint32(unsafe.Sizeof(notifyIconDataW{})),
			HWnd:   tm.hwnd,
			UID:    trayIconID,
		}
		_, _, _ = pShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))
		tm.added = false
	}
	for k, ic := range tm.icons {
		if ic != 0 {
			_, _, _ = pDestroyIcon.Call(ic)
		}
		delete(tm.icons, k)
	}
}

func (tm *trayManager) showContextMenu(eng *client.Engine, onOpen func(), onImport func(), onQuit func(), onToast func(string, bool)) {
	st := eng.Status()
	state := client.ConnState(strVal(st["state"]))
	routeMode := strVal(st["route_mode"])
	transPref := strVal(st["transport_pref"])
	sysProxy := boolVal(st["sys_proxy"])
	activeIdx := intVal(st["active_node"])
	nodes, _ := st["nodes"].([]client.NodeSummary)

	hMenu, _, _ := pCreatePopupMenu.Call()
	if hMenu == 0 {
		return
	}
	defer func() { _, _, _ = pDestroyMenu.Call(hMenu) }()

	appendItem := func(menu uintptr, flags uint32, id uintptr, text string) {
		var txtPtr uintptr
		if text != "" {
			txtPtr = uintptr(unsafe.Pointer(utf16Ptr(text)))
		}
		_, _, _ = pAppendMenuW.Call(menu, uintptr(flags), id, txtPtr)
	}

	appendItem(hMenu, mfString, cmdOpen, "打开 GhostFrame-Pro 控制台")
	if state == client.StateConnected || state == client.StateConnecting {
		appendItem(hMenu, mfString, cmdToggle, "断开安全隧道")
	} else {
		appendItem(hMenu, mfString, cmdToggle, "连接安全隧道")
	}
	spFlags := uint32(mfString)
	if sysProxy {
		spFlags |= mfChecked
	}
	appendItem(hMenu, spFlags, cmdSysProxy, "系统代理 (WinINET)")
	appendItem(hMenu, mfSeparator, 0, "")

	// Route Submenu
	hRoute, _, _ := pCreatePopupMenu.Call()
	routeItems := []struct {
		id   uintptr
		val  string
		name string
	}{
		{cmdRouteRule, "rule", "Rule (CN 绕过直连)"},
		{cmdRouteGlob, "global", "Global (全局代理)"},
		{cmdRouteDir, "direct", "Direct (全部直连)"},
	}
	for _, ri := range routeItems {
		f := uint32(mfString)
		if routeMode == ri.val {
			f |= mfChecked
		}
		appendItem(hRoute, f, ri.id, ri.name)
	}
	appendItem(hMenu, mfPopup, hRoute, "分流模式")

	// Transport Submenu
	hTrans, _, _ := pCreatePopupMenu.Call()
	transItems := []struct {
		id   uintptr
		val  string
		name string
	}{
		{cmdTransAuto, "auto", "Auto (QUIC+TCP 双栈竞速)"},
		{cmdTransQUIC, "quic", "QUIC (端口跳跃极速)"},
		{cmdTransTCP, "tcp", "TCP (uTLS 强稳健)"},
	}
	for _, ti := range transItems {
		f := uint32(mfString)
		if transPref == ti.val {
			f |= mfChecked
		}
		appendItem(hTrans, f, ti.id, ti.name)
	}
	appendItem(hMenu, mfPopup, hTrans, "传输模式")

	// Node Submenu
	hNodes, _, _ := pCreatePopupMenu.Call()
	if len(nodes) == 0 {
		appendItem(hNodes, mfString, 0, "(暂无节点，点击下方导入)")
	} else {
		for _, n := range nodes {
			f := uint32(mfString)
			if n.Index == activeIdx {
				f |= mfChecked
			}
			label := fmt.Sprintf("%s (%s:%d)", n.Name, n.Host, n.Port)
			appendItem(hNodes, f, uintptr(cmdNodeBase+n.Index), label)
		}
	}
	appendItem(hMenu, mfPopup, hNodes, "切换节点")
	appendItem(hMenu, mfString, cmdImport, "从剪贴板导入节点 (gft3://)")
	appendItem(hMenu, mfSeparator, 0, "")
	appendItem(hMenu, mfString, cmdQuit, "彻底退出 GhostFrame-Pro")

	var pt point
	_, _, _ = pGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	_, _, _ = pSetForegroundWindow.Call(tm.hwnd)
	cmd, _, _ := pTrackPopupMenuEx.Call(hMenu, tpmLeftAlign|tpmRightButton|tpmReturnCmd|tpmNonotify, uintptr(pt.X), uintptr(pt.Y), tm.hwnd, 0)
	_, _, _ = pPostMessageW.Call(tm.hwnd, 0, 0, 0)

	switch {
	case cmd == cmdOpen:
		onOpen()
	case cmd == cmdToggle:
		if state == client.StateConnected || state == client.StateConnecting {
			eng.Disconnect()
			onToast("已断开安全隧道", false)
		} else {
			go func() {
				if err := eng.Connect(); err != nil {
					onToast("连接失败: "+err.Error(), true)
				}
			}()
		}
	case cmd == cmdSysProxy:
		_ = eng.SetSysProxyToggle(!sysProxy)
	case cmd == cmdRouteRule:
		_ = eng.SetRouteMode(client.RouteRule)
		onToast("分流模式已切换: Rule", false)
	case cmd == cmdRouteGlob:
		_ = eng.SetRouteMode(client.RouteGlobal)
		onToast("分流模式已切换: Global", false)
	case cmd == cmdRouteDir:
		_ = eng.SetRouteMode(client.RouteDirect)
		onToast("分流模式已切换: Direct", false)
	case cmd == cmdTransAuto:
		_ = eng.SetTransport("auto")
		onToast("传输偏好已切换: Auto", false)
	case cmd == cmdTransQUIC:
		_ = eng.SetTransport("quic")
		onToast("传输偏好已切换: QUIC", false)
	case cmd == cmdTransTCP:
		_ = eng.SetTransport("tcp")
		onToast("传输偏好已切换: TCP", false)
	case cmd == cmdImport:
		onImport()
	case cmd == cmdQuit:
		onQuit()
	case cmd >= cmdNodeBase && int(cmd-cmdNodeBase) < len(nodes):
		idx := nodes[int(cmd-cmdNodeBase)].Index
		go func(i int) { _ = eng.SelectNode(i) }(idx)
	}
}
