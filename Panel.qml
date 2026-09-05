import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

// minimalist precision desktop control panel with seamless auto-apply and zero-dialog service control
Panel {
  id: root
  moduleName: "io.github.oqullcan.albus.dev"
  ipcTarget: "io.github.oqullcan.albus.dev"
  manageIpc: false

  property var anchorItem: null
  property var hostWidget: null
  readonly property var barIdentity: hostWidget || root

  // navigation tab indices: 0 = settings (dns, dpi & security), 1 = live logs telemetry
  property int activeTab: 0

  // reactive runtime state
  property bool isRunning: false
  property bool isBusy: false
  property string activeDnsLabel: "Quad9"
  property string activeDnsKey: "quad9"
  property string mullvadProfile: "standard"
  property string customDnsUrl: ""
  property string customBootstrapPrimary: ""
  property string customBootstrapSecondary: ""
  property string customMss: "88"
  property string customMinMss: "64"
  property string customFakeTtl: "0"
  property string customFakeSni: ""
  property bool fakeBadChecksum: false
  property bool autoTtlEnabled: true
  property bool dnssecEnabled: true
  property bool pqcEnabled: true
  property bool ramOnlyEnabled: false
  property bool blockQuicEnabled: true
  property bool blockStunEnabled: true
  property bool killSwitchEnabled: true
  property bool networkLockdownEnabled: false
  property bool blockIpv6Enabled: true
  property string toastMessage: ""
  property bool isConfigLoading: false

  // accordion section state: "upstream", "dpi", "security", "dns"
  property string activeSection: "dpi"

  function toggleSection(sec) {
    if (root.activeSection === sec) {
      root.activeSection = ""
    } else {
      root.activeSection = sec
    }
  }

  // hardened dns subsystem runtime state
  property bool tcpListenerEnabled: true
  property bool localDohEnabled: true
  property string localDohAddr: "127.0.0.1:8053"
  property bool queryLogEnabled: false
  property string queryLogPath: ""
  property string ipcryptKey: ""
  property bool blocklistEnabled: true
  property string customBlocklistPath: ""
  property bool antiRebindingEnabled: true
  property bool blockBogonsEnabled: true
  property bool uncloakCnamesEnabled: true
  property bool dns64Enabled: false
  property bool ednsPaddingEnabled: true
  property bool blockUndelegatedEnabled: true
  property bool netmonEnabled: true

  // preserved CLI configuration parameters not directly exposed in UI
  property var storedPorts: [443]
  property int storedRestoreAfterBytes: 600
  property int storedRestoreMss: 0
  property string storedCgroup: "/sys/fs/cgroup"

  onOpenedChanged: if (opened) {
    loadConfig()
    refreshStatus()
  }

  Component.onCompleted: {
    loadConfig()
    refreshStatus()
  }

  // event stream telemetry state
  property var rawStreamEvents: []
  property var displayEvents: []
  property string streamFilter: "ALL"
  property string streamSearchQuery: ""
  property bool isStreamPaused: false
  property int countInjected: 0
  property int countDns: 0
  property int countQuic: 0
  property int countShield: 0
  property bool isAtBottom: true
  property int copiedEventId: -1
  property int recentEventCount: 0
  property string eventRateText: "idle"

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color dim: Qt.darker(foreground, 1.6)
  readonly property color subtle: Qt.darker(foreground, 2.5)
  readonly property color borderMuted: Qt.rgba(foreground.r, foreground.g, foreground.b, 0.12)
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color accent: Color.accent
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  component CompactToggle: Rectangle {
    id: ctRoot
    property string label: ""
    property string description: ""
    property bool checked: false
    property color foreground: root.foreground
    property color accent: "#10B981"
    property bool showDivider: true
    signal clicked()

    width: parent.width
    implicitHeight: descText.visible ? Style.space(40) : Style.space(32)
    color: ctMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.04) : "transparent"

    Behavior on color { ColorAnimation { duration: 90 } }

    MouseArea {
      id: ctMouse
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onClicked: ctRoot.clicked()
    }

    RowLayout {
      anchors.fill: parent
      anchors.leftMargin: Style.space(12)
      anchors.rightMargin: Style.space(12)
      spacing: Style.space(8)

      ColumnLayout {
        Layout.fillWidth: true
        spacing: 1

        Text {
          text: ctRoot.label
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          font.bold: true
          color: ctRoot.checked ? ctRoot.foreground : root.dim
          textFormat: Text.PlainText
          elide: Text.ElideRight
          Layout.fillWidth: true
        }

        Text {
          id: descText
          visible: ctRoot.description !== ""
          text: ctRoot.description
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption - 1
          color: ctRoot.checked ? Qt.darker(root.foreground, 1.8) : root.subtle
          textFormat: Text.PlainText
          elide: Text.ElideRight
          Layout.fillWidth: true
        }
      }

      ToggleSwitch {
        checked: ctRoot.checked
        trackHeight: 18
        interactive: false
        foreground: ctRoot.foreground
        accent: ctRoot.accent
      }
    }

    Rectangle {
      visible: ctRoot.showDivider
      anchors.bottom: parent.bottom
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.leftMargin: Style.space(12)
      anchors.rightMargin: Style.space(12)
      height: 1
      color: Qt.rgba(1, 1, 1, 0.05)
    }
  }

  component AccordionSectionHeader: Rectangle {
    id: ashRoot
    property string title: ""
    property string subtitle: ""
    property string sectionKey: ""
    readonly property bool isOpen: root.activeSection === sectionKey
    property color foreground: root.foreground
    property color accent: "#10B981"
    signal clicked()

    width: parent.width
    height: Style.space(34)
    radius: Style.cornerRadius
    color: isOpen ? Qt.rgba(1, 1, 1, 0.07) : (ashMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.04) : Qt.rgba(1, 1, 1, 0.015))
    border.color: isOpen ? Qt.rgba(1, 1, 1, 0.18) : (ashMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.09) : root.borderMuted)
    border.width: 1

    Behavior on color { ColorAnimation { duration: 90 } }
    Behavior on border.color { ColorAnimation { duration: 90 } }

    MouseArea {
      id: ashMouse
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onClicked: root.toggleSection(ashRoot.sectionKey)
    }

    RowLayout {
      anchors.fill: parent
      anchors.leftMargin: Style.space(10)
      anchors.rightMargin: Style.space(10)
      spacing: Style.space(8)

      Rectangle {
        width: 3
        height: Style.space(14)
        radius: 1.5
        color: ashRoot.isOpen ? ashRoot.accent : Qt.rgba(1, 1, 1, 0.2)
        Layout.alignment: Qt.AlignVCenter
        Behavior on color { ColorAnimation { duration: 90 } }
      }

      Text {
        text: ashRoot.title
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        font.bold: true
        color: ashRoot.isOpen ? root.foreground : root.dim
        textFormat: Text.PlainText
        Layout.alignment: Qt.AlignVCenter
      }

      Text {
        text: ashRoot.subtitle
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption - 2
        color: ashRoot.isOpen ? Qt.darker(root.foreground, 1.6) : root.subtle
        textFormat: Text.PlainText
        elide: Text.ElideRight
        Layout.fillWidth: true
        Layout.alignment: Qt.AlignVCenter
      }

      Text {
        text: ashRoot.isOpen ? "▲" : "▼"
        font.family: "monospace"
        font.pixelSize: Style.font.caption - 1
        font.bold: true
        color: ashRoot.isOpen ? ashRoot.accent : root.subtle
        Layout.alignment: Qt.AlignVCenter
      }
    }
  }

  function showToast(msg) {
    root.toastMessage = msg
    toastTimer.restart()
  }

  Timer {
    id: toastTimer
    interval: 2200
    onTriggered: root.toastMessage = ""
  }

  Timer {
    id: autoApplyTimer
    interval: 600
    repeat: false
    onTriggered: root.applyAndSave()
  }

  Timer {
    id: rateTimer
    interval: 1000
    running: root.opened && root.activeTab === 1
    repeat: true
    onTriggered: {
      var r = root.recentEventCount
      root.recentEventCount = 0
      root.eventRateText = r > 0 ? (r + " flow/s") : "idle"
    }
  }

  Timer {
    id: copiedFeedbackTimer
    interval: 1200
    onTriggered: root.copiedEventId = -1
  }

  function scheduleAutoApply() {
    if (root.isConfigLoading) return
    autoApplyTimer.restart()
  }

  function copyToClipboard(text) {
    if (!text) return
    copyProc.command = ["wl-copy", text]
    copyProc.running = true
    showToast("Copied to clipboard")
  }

  function stripAnsi(str) {
    if (!str) return ""
    return str
      .replace(/\x1B\[[0-9;]*[a-zA-Z]/g, "")
      .replace(/\u001b\[[0-9;]*[a-zA-Z]/g, "")
      .replace(/\[\d+m/g, "")
      .replace(/[^\x20-\x7E\t\n\r]/g, "")
  }

  function parseStatusJson(raw) {
    try {
      if (!raw) return null
      var data = JSON.parse(raw.trim())
      return {
        active: (data.class === "active" || data.active === true),
        dohUpstream: data.doh_upstream || root.activeDnsKey
      }
    } catch (e) {
      return null
    }
  }

  function parseConfigJson(raw) {
    try {
      if (!raw) return null
      return JSON.parse(raw.trim())
    } catch (e) {
      return null
    }
  }

  function parseLogLine(raw) {
    var clean = stripAnsi(raw).trim()
    if (clean === "") return null

    var timeStr = ""
    var isoMatch = clean.match(/(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)/)
    if (isoMatch) {
      try {
        var d = new Date(isoMatch[1])
        if (!isNaN(d.getTime())) {
          var pad = function(n) { return n < 10 ? "0" + n : n }
          timeStr = pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds())
        }
      } catch (e) {}
    }
    if (timeStr === "") {
      var timeMatch = clean.match(/(\d{2}:\d{2}:\d{2})/)
      timeStr = timeMatch ? timeMatch[1] : ""
    }

    var category = "SYS"
    var badgeColor = "#94A3B8"
    var title = clean
    var detail = "System event"
    var tag = ""

    if (clean.indexOf("fake ClientHello injected") !== -1 || clean.indexOf("ClientHello") !== -1) {
      category = "INJECT"
      badgeColor = "#38BDF8"
      var dstMatch = clean.match(/dst=([^\s]+)/)
      var ttlMatch = clean.match(/ttl=([^\s]+)/)
      var badCsMatch = clean.match(/bad_csum=([^\s]+)/) || clean.match(/bad_cs=([^\s]+)/)
      title = dstMatch ? dstMatch[1] : "TLS ClientHello"
      var isBad = badCsMatch && (badCsMatch[1] === "true" || badCsMatch[1] === "1")
      detail = isBad ? "0xDEAD bad-checksum middlebox desync" : "Fake SNI desync injected"
      tag = (isBad ? "0xDEAD • " : "") + (ttlMatch ? "TTL " + ttlMatch[1] : "TTL")
    } else if (clean.indexOf("DNS cache hit") !== -1 || clean.indexOf("cache_0ms") !== -1) {
      category = "DNS"
      badgeColor = "#A855F7"
      var domMatch = clean.match(/domain=([^\s]+)/)
      title = domMatch ? domMatch[1].replace(/["',]/g, "") : "DNS Cache Hit"
      detail = "Resolved via in-memory 0ms cache"
      tag = "0ms Cache"
    } else if (clean.indexOf("DNS server started") !== -1 || clean.indexOf("DNS-over-HTTPS proxy listening") !== -1) {
      category = "SYS"
      badgeColor = "#A855F7"
      title = "DoH Resolver Online"
      detail = "127.0.0.1:53 proxy listener ready"
      tag = "127.0.0.1"
    } else if (clean.indexOf("DNS resolved") !== -1 || clean.indexOf("DNS") !== -1 || clean.indexOf("query") !== -1 || clean.indexOf("resolved") !== -1) {
      category = "DNS"
      badgeColor = "#A855F7"
      var domMatch = clean.match(/domain=([^\s]+)/) || clean.match(/upstream=([^\s]+)/)
      var dnssecMatch = clean.match(/dnssec_authenticated=true/) || clean.match(/is_ad=true/)
      title = domMatch ? domMatch[1].replace(/["',]/g, "") : "DoH Query"
      detail = "Encrypted upstream resolution"
      tag = dnssecMatch ? "DNSSEC" : "DoH"
    } else if (clean.indexOf("QUIC") !== -1 || clean.indexOf("blocked") !== -1) {
      category = "QUIC"
      badgeColor = "#F59E0B"
      title = "QUIC (UDP 443) Blocked"
      detail = "Forced browser fallback to TCP"
      tag = "UDP 443"
    } else if (clean.indexOf("STUN") !== -1 || clean.indexOf("WebRTC") !== -1 || clean.indexOf("canary") !== -1 || clean.indexOf("Kill-Switch") !== -1 || clean.indexOf("Lockdown") !== -1) {
      category = "SHIELD"
      badgeColor = "#10B981"
      var isLock = clean.indexOf("Lockdown") !== -1
      title = isLock ? "Network Lockdown Rule" : "Privacy Shield Block"
      detail = isLock ? "Fail-closed TCP 80/443 protection" : "WebRTC STUN / DNS leak drop"
      tag = isLock ? "Lockdown" : "Leak Block"
    } else if (clean.indexOf("Error") !== -1 || clean.indexOf("Failed") !== -1) {
      category = "ERROR"
      badgeColor = "#EF4444"
      title = clean.replace(/.*Error:\s*/, "")
      detail = "Service warning / alert"
      tag = "ERROR"
    } else if (clean.indexOf("SIGHUP") !== -1 || clean.indexOf("reloading") !== -1 || clean.indexOf("Reloading") !== -1) {
      category = "SYS"
      badgeColor = "#94A3B8"
      title = "Live Parameters Reloaded"
      detail = "eBPF maps updated via SIGHUP"
      tag = "Reload"
    } else {
      var stripped = clean.replace(/^[\d\-T:\.Z]+\s*(INFO|WARN|DEBUG|ERROR)?\s*/, "")
      title = stripped !== "" ? stripped : clean
      detail = "Kernel event"
      tag = "INFO"
    }

    return {
      time: timeStr,
      category: category,
      badgeColor: badgeColor,
      title: title,
      detail: detail,
      tag: tag,
      raw: clean
    }
  }

  function appendStreamEvent(rawLine) {
    var parsed = parseLogLine(rawLine)
    if (!parsed) return

    root.recentEventCount++

    if (parsed.category === "INJECT") root.countInjected++
    else if (parsed.category === "DNS") root.countDns++
    else if (parsed.category === "QUIC") root.countQuic++
    else if (parsed.category === "SHIELD") root.countShield++

    if (root.isStreamPaused) return

    var list = root.rawStreamEvents.slice()
    list.push(parsed)
    if (list.length > 120) list.shift()
    root.rawStreamEvents = list

    updateDisplayEvents()
    if (root.isAtBottom) {
      Qt.callLater(function() {
        if (streamListView) streamListView.positionViewAtEnd()
      })
    }
  }

  function updateDisplayEvents() {
    var list = root.rawStreamEvents
    var query = root.streamSearchQuery.trim().toLowerCase()
    var filtered = []

    for (var i = 0; i < list.length; i++) {
      var item = list[i]
      var categoryMatch = (root.streamFilter === "ALL" || item.category === root.streamFilter)
      if (!categoryMatch) continue

      var queryMatch = (query === "" || 
                        item.title.toLowerCase().indexOf(query) !== -1 || 
                        item.detail.toLowerCase().indexOf(query) !== -1 ||
                        (item.tag && item.tag.toLowerCase().indexOf(query) !== -1))
      if (!queryMatch) continue

      filtered.push(item)
    }
    root.displayEvents = filtered
  }

  function setFilter(filterKey) {
    root.streamFilter = filterKey
    updateDisplayEvents()
  }

  function togglePause() {
    root.isStreamPaused = !root.isStreamPaused
    if (!root.isStreamPaused) {
      updateDisplayEvents()
      if (root.isAtBottom) {
        Qt.callLater(function() {
          if (streamListView) streamListView.positionViewAtEnd()
        })
      }
    }
  }

  function clearStream() {
    root.rawStreamEvents = []
    root.displayEvents = []
    root.countInjected = 0
    root.countDns = 0
    root.countQuic = 0
    root.countShield = 0
    root.recentEventCount = 0
    root.eventRateText = "idle"
    root.copiedEventId = -1
    root.isAtBottom = true
  }

  function open() {
    loadConfig()
    refreshStatus()
    root.controller.show()
  }

  function close() {
    root.controller.hide()
  }

  function toggle() {
    if (root.opened) root.close()
    else root.open()
  }

  function switchPanel(direction) {
    if (root.bar && typeof root.bar.switchPanelFrom === "function") {
      return root.bar.switchPanelFrom(root.hostWidget || root, direction)
    }
    return false
  }

  // background process execution controllers
  function refreshStatus() {
    if (!statusProc.running) statusProc.running = true
  }

  function loadConfig() {
    if (!configGetProc.running) configGetProc.running = true
  }

  function applyAndSave() {
    if (root.isConfigLoading) return
    autoApplyTimer.stop()
    var args = ["config", "set"]

    var upstream = root.activeDnsKey
    if (upstream.indexOf("mullvad") !== -1) {
      upstream = root.mullvadProfile === "standard" ? "mullvad" : "mullvad-" + root.mullvadProfile
    } else if (upstream === "custom") {
      var trimmedUrl = root.customDnsUrl.trim()
      if (trimmedUrl === "" || (!trimmedUrl.startsWith("http://") && !trimmedUrl.startsWith("https://") && !trimmedUrl.startsWith("sdns://") && trimmedUrl.indexOf(".") === -1)) {
        return
      }
      upstream = trimmedUrl
    }
    args.push("--doh-upstream", upstream)

    var ipRegex = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/
    var p1 = root.customBootstrapPrimary.trim()
    var p2 = root.customBootstrapSecondary.trim()
    if ((p1 !== "" && !ipRegex.test(p1)) || (p2 !== "" && !ipRegex.test(p2))) {
      // User is mid-typing an IP address; don't execute incomplete CLI call
      return
    }

    var boots = []
    if (p1 !== "" && ipRegex.test(p1)) boots.push(p1)
    if (p2 !== "" && ipRegex.test(p2)) boots.push(p2)
    if (boots.length > 0) {
      args.push("--doh-bootstrap-ips", boots.join(","))
    }

    args.push("--mss", root.customMss.trim() !== "" ? root.customMss.trim() : "88")
    args.push("--min-mss", root.customMinMss.trim() !== "" ? root.customMinMss.trim() : "64")
    var ttlVal = parseInt(root.customFakeTtl.trim(), 10)
    if (isNaN(ttlVal) || ttlVal <= 0) {
      args.push("--auto-ttl", "true")
      args.push("--fake-ttl", "8")
      root.autoTtlEnabled = true
    } else {
      args.push("--auto-ttl", "false")
      var clampedTtl = Math.min(Math.max(ttlVal, 1), 255)
      args.push("--fake-ttl", String(clampedTtl))
      root.autoTtlEnabled = false
    }
    if (root.customFakeSni.trim() !== "") {
      args.push("--fake-sni", root.customFakeSni.trim())
    }
    args.push("--fake-bad-checksum", root.fakeBadChecksum ? "true" : "false")
    args.push("--block-quic", root.blockQuicEnabled ? "true" : "false")
    args.push("--block-stun", root.blockStunEnabled ? "true" : "false")
    args.push("--kill-switch", root.killSwitchEnabled ? "true" : "false")
    args.push("--network-lockdown", root.networkLockdownEnabled ? "true" : "false")
    args.push("--block-ipv6", root.blockIpv6Enabled ? "true" : "false")
    args.push("--dnssec", root.dnssecEnabled ? "true" : "false")
    args.push("--pqc", root.pqcEnabled ? "true" : "false")
    args.push("--ram-only", root.ramOnlyEnabled ? "true" : "false")

    // hardened dns subsystem parameters
    args.push("--tcp-listener", root.tcpListenerEnabled ? "true" : "false")
    args.push("--local-doh", root.localDohEnabled ? "true" : "false")
    if (root.localDohAddr.trim() !== "") {
      args.push("--local-doh-addr", root.localDohAddr.trim())
    }
    args.push("--query-log", root.queryLogEnabled ? "true" : "false")
    if (root.queryLogPath.trim() !== "") {
      args.push("--query-log-path", root.queryLogPath.trim())
    }
    if (root.ipcryptKey.trim() !== "") {
      args.push("--ipcrypt-key", root.ipcryptKey.trim())
    }
    args.push("--blocklist", root.blocklistEnabled ? "true" : "false")
    if (root.customBlocklistPath.trim() !== "") {
      args.push("--blocklist-path", root.customBlocklistPath.trim())
    }
    args.push("--anti-dns-rebinding", root.antiRebindingEnabled ? "true" : "false")
    args.push("--block-bogons", root.blockBogonsEnabled ? "true" : "false")
    args.push("--uncloak-cnames", root.uncloakCnamesEnabled ? "true" : "false")
    args.push("--dns64", root.dns64Enabled ? "true" : "false")
    args.push("--edns-padding", root.ednsPaddingEnabled ? "true" : "false")
    args.push("--block-undelegated", root.blockUndelegatedEnabled ? "true" : "false")
    args.push("--netmon", root.netmonEnabled ? "true" : "false")

    // preserve backend tuning parameters
    if (root.storedPorts && root.storedPorts.length > 0) {
      args.push("--ports", root.storedPorts.join(","))
    }
    args.push("--restore-after-bytes", String(root.storedRestoreAfterBytes))
    args.push("--restore-mss", String(root.storedRestoreMss))
    if (root.storedCgroup) {
      args.push("--cgroup", root.storedCgroup)
    }

    configSetProc.command = ["albus"].concat(args)
    configSetProc.running = true
  }

  function toggleDaemon() {
    root.isBusy = true
    if (root.isRunning) {
      daemonActionProc.command = ["systemctl", "stop", "albus.service"]
    } else {
      daemonActionProc.command = ["systemctl", "start", "albus.service"]
    }
    daemonActionProc.running = true
  }

  function restartDaemon() {
    root.isBusy = true
    daemonActionProc.command = ["systemctl", "restart", "albus.service"]
    daemonActionProc.running = true
  }

  function purgeDnsCache() {
    flushCacheProc.command = ["systemctl", "kill", "-s", "SIGUSR1", "albus.service"]
    flushCacheProc.running = true
  }

  function openMonitor() {
    terminalProc.running = true
  }

  Process {
    id: flushCacheProc
    command: []
    running: false
    onExited: function(code) {
      root.showToast("DNS cache flushed")
    }
  }

  // subprocess definitions
  Process {
    id: statusProc
    command: ["albus", "status", "--json"]
    running: false
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        var s = root.parseStatusJson(text)
        if (s) {
          root.isRunning = s.active
        }
      }
    }
  }

  Process {
    id: configGetProc
    command: ["albus", "config", "get"]
    running: false
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        var cfg = root.parseConfigJson(text)
        if (cfg) {
          root.isConfigLoading = true

          root.customMss = String(cfg.mss || 88)
          root.customMinMss = String(cfg.min_mss !== undefined ? cfg.min_mss : 64)
          root.customFakeTtl = cfg.auto_ttl === false ? String(cfg.fake_ttl || 8) : "0"
          root.customFakeSni = cfg.fake_sni || ""
          root.fakeBadChecksum = !!cfg.fake_bad_checksum
          root.autoTtlEnabled = cfg.auto_ttl !== false
          root.dnssecEnabled = cfg.dnssec !== false
          root.pqcEnabled = cfg.pqc !== false
          root.ramOnlyEnabled = !!cfg.ram_only
          root.blockQuicEnabled = cfg.block_quic !== false
          root.blockStunEnabled = cfg.block_stun !== false
          root.killSwitchEnabled = cfg.kill_switch !== false
          root.networkLockdownEnabled = !!cfg.network_lockdown
          root.blockIpv6Enabled = cfg.block_ipv6 !== false

          // load hardened dns subsystem settings
          root.tcpListenerEnabled = cfg.tcp_listener !== false
          root.localDohEnabled = cfg.local_doh !== false
          root.localDohAddr = cfg.local_doh_addr || "127.0.0.1:8053"
          root.queryLogEnabled = !!cfg.query_log
          root.queryLogPath = cfg.query_log_path || ""
          root.ipcryptKey = cfg.ipcrypt_key || ""
          root.blocklistEnabled = cfg.blocklist !== false
          root.customBlocklistPath = cfg.blocklist_path || ""
          root.antiRebindingEnabled = cfg.anti_dns_rebinding !== false
          root.blockBogonsEnabled = cfg.block_bogons !== false
          root.uncloakCnamesEnabled = cfg.uncloak_cnames !== false
          root.dns64Enabled = !!cfg.dns64
          root.ednsPaddingEnabled = cfg.edns_padding !== false
          root.blockUndelegatedEnabled = cfg.block_undelegated !== false
          root.netmonEnabled = cfg.netmon !== false

          if (cfg.ports && Array.isArray(cfg.ports)) root.storedPorts = cfg.ports
          if (cfg.restore_after_bytes !== undefined) root.storedRestoreAfterBytes = cfg.restore_after_bytes
          if (cfg.restore_mss !== undefined) root.storedRestoreMss = cfg.restore_mss
          if (cfg.cgroup_path) root.storedCgroup = cfg.cgroup_path

          var up = cfg.doh_upstream || "quad9"
          if (up === "cloudflare" || up === "quad9") {
            root.activeDnsKey = up
            root.activeDnsLabel = up === "quad9" ? "Quad9" : "Cloudflare"
          } else if (up.indexOf("mullvad") !== -1) {
            root.activeDnsKey = up
            root.activeDnsLabel = "Mullvad"
            if (up === "mullvad" || up === "mullvad-standard") root.mullvadProfile = "standard"
            else if (up === "mullvad-adblock") root.mullvadProfile = "adblock"
            else if (up === "mullvad-base") root.mullvadProfile = "base"
            else if (up === "mullvad-extended") root.mullvadProfile = "extended"
            else if (up === "mullvad-family") root.mullvadProfile = "family"
            else if (up === "mullvad-all") root.mullvadProfile = "all"
          } else {
            root.activeDnsKey = "custom"
            root.activeDnsLabel = "Custom"
            root.customDnsUrl = up
          }

          root.customBootstrapPrimary = (cfg.doh_bootstrap_ips && cfg.doh_bootstrap_ips.length > 0) ? (cfg.doh_bootstrap_ips[0] || "") : ""
          root.customBootstrapSecondary = (cfg.doh_bootstrap_ips && cfg.doh_bootstrap_ips.length > 1) ? (cfg.doh_bootstrap_ips[1] || "") : ""

          root.isConfigLoading = false
        }
      }
    }
  }

  Process {
    id: configSetProc
    command: []
    running: false
    onExited: function(code) {
      if (code === 0) {
        root.showToast("Settings applied")
        if (root.isRunning) {
          daemonActionProc.command = ["systemctl", "restart", "albus.service"]
          daemonActionProc.running = true
        } else {
          root.refreshStatus()
        }
      } else {
        root.showToast("Failed to save settings")
      }
    }
  }

  Process {
    id: daemonActionProc
    command: []
    running: false
    onExited: function(code) {
      root.isBusy = false
      root.refreshStatus()
      root.loadConfig()
    }
  }

  Process {
    id: terminalProc
    command: ["xdg-terminal-exec", "albus", "monitor"]
    running: false
  }

  Process {
    id: copyProc
    command: []
    running: false
  }

  // journalctl event stream collector
  Process {
    id: streamProc
    command: ["journalctl", "-u", "albus.service", "-n", "40", "-f", "--no-pager", "-o", "cat"]
    running: root.opened && root.activeTab === 1
    stdout: SplitParser {
      onRead: function(line) {
        root.appendStreamEvent(line)
      }
    }
  }

  Timer {
    id: statusPoller
    interval: 2000
    running: root.opened
    repeat: true
    triggeredOnStart: true
    onTriggered: {
      if (!root.isBusy) root.refreshStatus()
    }
  }

  // keyboard panel container
  KeyboardPanel {
    id: panel
    anchorItem: root.anchorItem
    owner: root.barIdentity
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(520))
    contentHeight: panel.fittedContentHeight(mainColumn.implicitHeight + Style.space(20))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }

      onTextKey: function(t) {
        if (t === "1") root.activeTab = 0
        else if (t === "2") root.activeTab = 1
        else if (t === " " || t === "t" || t === "T") root.toggleDaemon()
        else if (t === "r" || t === "R") root.restartDaemon()
        else if (t === "c" || t === "C") root.purgeDnsCache()
        else if (t === "p" || t === "P") root.togglePause()
        else if (t === "j" || t === "J") {
          if (root.activeTab === 1 && streamListView) streamListView.contentY = Math.min(streamListView.contentHeight - streamListView.height, streamListView.contentY + 50)
        }
        else if (t === "k" || t === "K") {
          if (root.activeTab === 1 && streamListView) streamListView.contentY = Math.max(0, streamListView.contentY - 50)
        }
      }

      Flickable {
        id: panelFlick
        anchors.fill: parent
        contentWidth: width
        contentHeight: mainColumn.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        flickableDirection: Flickable.VerticalFlick
        interactive: contentHeight > height

        Column {
          id: mainColumn
          width: panelFlick.width - Style.space(16)
          anchors.horizontalCenter: parent.horizontalCenter
          anchors.top: parent.top
          anchors.topMargin: Style.space(8)
          spacing: Style.space(10)

          // 1. clean header bar
          Item {
            width: parent.width
            implicitHeight: Math.max(headerCol.implicitHeight, mainSwitch.implicitHeight)

            Column {
              id: headerCol
              anchors.left: parent.left
              anchors.right: mainSwitch.left
              anchors.rightMargin: Style.space(8)
              anchors.verticalCenter: parent.verticalCenter
              spacing: 2

              Row {
                spacing: Style.space(6)
                height: Math.max(albusTitle.implicitHeight, statusText.implicitHeight)

                Text {
                  id: albusTitle
                  text: "ALBUS"
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                  font.bold: true
                  color: root.foreground
                  anchors.verticalCenter: parent.verticalCenter
                }

                Text {
                  id: statusText
                  text: root.isRunning ? "● ACTIVE" : "○ STANDBY"
                  font.family: "monospace"
                  font.pixelSize: Style.font.caption - 1
                  font.bold: true
                  color: root.isRunning ? "#10B981" : root.dim
                  anchors.verticalCenter: parent.verticalCenter
                }
              }

              Text {
                width: parent.width
                text: root.isBusy ? "Applying rules..." : (root.isRunning ? ("eBPF sock_ops • ML-KEM-768 • " + (root.ramOnlyEnabled ? "RAM-Only" : "Persistent")) : "Engine is offline")
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption - 1
                color: root.dim
                elide: Text.ElideRight
              }
            }

            ToggleSwitch {
              id: mainSwitch
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              checked: root.isRunning
              busy: root.isBusy
              foreground: root.foreground
              accent: "#10B981"
              onToggled: root.toggleDaemon()
            }
          }

          // 2. ultra-sleek segmented tab bar
          BorderSurface {
            width: parent.width
            height: Style.space(32)
            radius: Style.cornerRadius
            color: Qt.rgba(1, 1, 1, 0.02)
            borderSpec: Border.controlSpec("normal", root.foreground, root.borderMuted)

            Row {
              anchors.fill: parent
              anchors.margins: 2
              spacing: 2

              Repeater {
                model: [
                  { index: 0, label: "SETTINGS" },
                  { index: 1, label: "LOGS" }
                ]

                Rectangle {
                  id: mainTabPill
                  width: (parent.width - 2) / 2
                  height: parent.height
                  radius: Style.cornerRadius > 0 ? Style.cornerRadius - 1 : 0
                  readonly property bool isSelected: root.activeTab === modelData.index
                  color: isSelected ? Qt.rgba(1, 1, 1, 0.10) : (mainTabMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.04) : "transparent")
                  border.color: isSelected ? Qt.rgba(1, 1, 1, 0.22) : "transparent"
                  border.width: isSelected ? 1 : 0

                  Behavior on color { ColorAnimation { duration: 90 } }

                  MouseArea {
                    id: mainTabMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.activeTab = modelData.index
                  }

                  Text {
                    anchors.centerIn: parent
                    text: modelData.label
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption - 1
                    font.bold: mainTabPill.isSelected
                    color: mainTabPill.isSelected ? root.foreground : root.dim
                    textFormat: Text.PlainText
                  }
                }
              }
            }
          }

          // 3. animated tab viewport
          Item {
            id: tabContainer
            width: parent.width
            implicitHeight: currentTabItem ? currentTabItem.implicitHeight : 0

            readonly property Item currentTabItem: root.activeTab === 0 ? tab0 : tab1

            Behavior on implicitHeight {
              NumberAnimation { duration: 140; easing.type: Easing.OutQuad }
            }

            // tab 0: encrypted resolver & security policies
            Column {
              id: tab0
              width: parent.width
              visible: root.activeTab === 0
              opacity: root.activeTab === 0 ? 1.0 : 0.0
              spacing: Style.space(8)

              Behavior on opacity {
                NumberAnimation { duration: 160; easing.type: Easing.OutQuad }
              }

              AccordionSectionHeader {
                title: "UPSTREAM RESOLVER"
                subtitle: root.activeDnsLabel + (root.activeDnsKey.indexOf("mullvad") !== -1 ? " (" + root.mullvadProfile + ")" : "")
                sectionKey: "upstream"
              }

              Item {
                id: secUpstreamWrap
                width: parent.width
                implicitHeight: root.activeSection === "upstream" ? secUpstreamCol.implicitHeight : 0
                height: implicitHeight
                clip: true
                opacity: root.activeSection === "upstream" ? 1.0 : 0.0
                visible: height > 0

                Behavior on implicitHeight { NumberAnimation { duration: 140; easing.type: Easing.OutQuad } }
                Behavior on opacity { NumberAnimation { duration: 120; easing.type: Easing.OutQuad } }

                Column {
                  id: secUpstreamCol
                  width: parent.width
                  spacing: Style.space(6)

                  // horizontal segmented resolver selector
                  BorderSurface {
                    width: parent.width
                    height: Style.space(30)
                    radius: Style.cornerRadius
                    color: Qt.rgba(1, 1, 1, 0.02)
                    borderSpec: Border.controlSpec("normal", root.foreground, root.borderMuted)

                    Row {
                      anchors.fill: parent
                      anchors.margins: 2
                      spacing: 2

                      Repeater {
                        model: [
                          { key: "quad9", label: "Quad9" },
                          { key: "cloudflare", label: "Cloudflare" },
                          { key: "mullvad", label: "Mullvad" },
                          { key: "custom", label: "Custom" }
                        ]

                        Rectangle {
                          id: segPill
                          width: (parent.width - 6) / 4
                          height: parent.height
                          radius: Style.cornerRadius > 0 ? Style.cornerRadius - 1 : 0
                          readonly property bool isSelected: modelData.key === "mullvad" ? root.activeDnsKey.indexOf("mullvad") !== -1 : root.activeDnsKey === modelData.key
                          color: isSelected ? Qt.rgba(1, 1, 1, 0.10) : (pillMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.04) : "transparent")
                          border.color: isSelected ? Qt.rgba(1, 1, 1, 0.22) : "transparent"
                          border.width: isSelected ? 1 : 0

                          Behavior on color { ColorAnimation { duration: 90 } }

                          MouseArea {
                            id: pillMouse
                            anchors.fill: parent
                            hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor
                            onClicked: {
                              if (modelData.key === "mullvad") {
                                root.activeDnsKey = root.mullvadProfile === "standard" ? "mullvad" : "mullvad-" + root.mullvadProfile
                                root.activeDnsLabel = "Mullvad"
                                root.applyAndSave()
                              } else if (modelData.key === "custom") {
                                root.activeDnsKey = "custom"
                                root.activeDnsLabel = "Custom"
                                if (root.customDnsUrl.trim() !== "") {
                                  root.applyAndSave()
                                }
                              } else {
                                root.activeDnsKey = modelData.key
                                root.activeDnsLabel = modelData.label
                                root.applyAndSave()
                              }
                            }
                          }

                          Text {
                            anchors.centerIn: parent
                            text: modelData.label
                            font.family: root.fontFamily
                            font.pixelSize: Style.font.caption - 1
                            font.bold: segPill.isSelected
                            color: segPill.isSelected ? root.foreground : root.dim
                            textFormat: Text.PlainText
                          }
                        }
                      }
                    }
                  }

                  // mullvad category blocker selector
                  Column {
                    width: parent.width
                    visible: root.activeDnsKey.indexOf("mullvad") !== -1
                    spacing: Style.space(4)

                    PanelSectionHeader {
                      text: "MULLVAD BLOCKER PROFILE"
                      foreground: root.foreground
                      fontFamily: root.fontFamily
                    }

                    Grid {
                      columns: 3
                      spacing: Style.space(4)
                      width: parent.width

                      Button {
                        width: (mainColumn.width - Style.space(8)) / 3
                        text: "Standard"
                        selected: root.mullvadProfile === "standard"
                        bordered: true
                        fontSize: Style.font.caption - 1
                        onClicked: {
                          root.mullvadProfile = "standard"
                          root.activeDnsKey = "mullvad"
                          root.applyAndSave()
                        }
                      }

                      Button {
                        width: (mainColumn.width - Style.space(8)) / 3
                        text: "Adblock"
                        selected: root.mullvadProfile === "adblock"
                        bordered: true
                        fontSize: Style.font.caption - 1
                        onClicked: {
                          root.mullvadProfile = "adblock"
                          root.activeDnsKey = "mullvad-adblock"
                          root.applyAndSave()
                        }
                      }

                      Button {
                        width: (mainColumn.width - Style.space(8)) / 3
                        text: "Base"
                        selected: root.mullvadProfile === "base"
                        bordered: true
                        fontSize: Style.font.caption - 1
                        onClicked: {
                          root.mullvadProfile = "base"
                          root.activeDnsKey = "mullvad-base"
                          root.applyAndSave()
                        }
                      }

                      Button {
                        width: (mainColumn.width - Style.space(8)) / 3
                        text: "Extended"
                        selected: root.mullvadProfile === "extended"
                        bordered: true
                        fontSize: Style.font.caption - 1
                        onClicked: {
                          root.mullvadProfile = "extended"
                          root.activeDnsKey = "mullvad-extended"
                          root.applyAndSave()
                        }
                      }

                      Button {
                        width: (mainColumn.width - Style.space(8)) / 3
                        text: "Family"
                        selected: root.mullvadProfile === "family"
                        bordered: true
                        fontSize: Style.font.caption - 1
                        onClicked: {
                          root.mullvadProfile = "family"
                          root.activeDnsKey = "mullvad-family"
                          root.applyAndSave()
                        }
                      }

                      Button {
                        width: (mainColumn.width - Style.space(8)) / 3
                        text: "All Shield"
                        selected: root.mullvadProfile === "all"
                        bordered: true
                        fontSize: Style.font.caption - 1
                        onClicked: {
                          root.mullvadProfile = "all"
                          root.activeDnsKey = "mullvad-all"
                          root.applyAndSave()
                        }
                      }
                    }
                  }

                  // custom endpoint parameters
                  Column {
                    width: parent.width
                    visible: root.activeDnsKey === "custom"
                    spacing: Style.space(4)

                    Text { text: "Endpoint URL or DNS Stamp (sdns://...)"; color: root.dim; font.pixelSize: Style.font.caption - 1; font.family: root.fontFamily }
                    TextField {
                      width: parent.width
                      placeholderText: "https://doh.example.com/dns-query or sdns://..."
                      text: root.customDnsUrl
                      onTextEdited: {
                        root.customDnsUrl = text
                        root.scheduleAutoApply()
                      }
                    }

                    Row {
                      width: parent.width
                      spacing: Style.space(6)

                      Column {
                        width: (parent.width - Style.space(6)) / 2
                        spacing: 2
                        Text { text: "Bootstrap IP 1"; color: root.dim; font.pixelSize: Style.font.caption - 1; font.family: root.fontFamily }
                        TextField {
                          width: parent.width
                          placeholderText: "e.g. 45.90.28.0"
                          text: root.customBootstrapPrimary
                          font.family: "monospace"
                          font.pixelSize: Style.font.caption
                          accent: "#10B981"
                          onTextEdited: {
                            root.customBootstrapPrimary = text
                            root.scheduleAutoApply()
                          }
                        }
                      }

                      Column {
                        width: (parent.width - Style.space(6)) / 2
                        spacing: 2
                        Text { text: "Bootstrap IP 2"; color: root.dim; font.pixelSize: Style.font.caption - 1; font.family: root.fontFamily }
                        TextField {
                          width: parent.width
                          placeholderText: "e.g. 45.90.30.0"
                          text: root.customBootstrapSecondary
                          font.family: "monospace"
                          font.pixelSize: Style.font.caption
                          accent: "#10B981"
                          onTextEdited: {
                            root.customBootstrapSecondary = text
                            root.scheduleAutoApply()
                          }
                        }
                      }
                    }
                  }
                }
              }

              AccordionSectionHeader {
                title: "DPI EVASION"
                subtitle: "MSS " + root.customMss + " • " + (root.fakeBadChecksum ? "0xDEAD • " : "") + (root.blockQuicEnabled ? "No-QUIC" : "QUIC")
                sectionKey: "dpi"
              }

              Item {
                id: secDpiWrap
                width: parent.width
                implicitHeight: root.activeSection === "dpi" ? secDpiCol.implicitHeight : 0
                height: implicitHeight
                clip: true
                opacity: root.activeSection === "dpi" ? 1.0 : 0.0
                visible: height > 0

                Behavior on implicitHeight { NumberAnimation { duration: 140; easing.type: Easing.OutQuad } }
                Behavior on opacity { NumberAnimation { duration: 120; easing.type: Easing.OutQuad } }

                Column {
                  id: secDpiCol
                  width: parent.width
                  spacing: Style.space(6)

                  Row {
                    width: parent.width
                    spacing: Style.space(6)

                    Column {
                      width: (parent.width - Style.space(12)) / 3
                      spacing: 2
                      Text { text: "TCP MSS"; color: root.dim; font.pixelSize: Style.font.caption - 1; font.family: root.fontFamily }
                      TextField {
                        width: parent.width
                        text: root.customMss
                        font.family: "monospace"
                        font.pixelSize: Style.font.caption
                        accent: "#10B981"
                        onTextEdited: {
                          root.customMss = text
                          root.scheduleAutoApply()
                        }
                      }
                    }

                    Column {
                      width: (parent.width - Style.space(12)) / 3
                      spacing: 2
                      Text { text: "Min MSS (Jitter)"; color: root.dim; font.pixelSize: Style.font.caption - 1; font.family: root.fontFamily }
                      TextField {
                        width: parent.width
                        text: root.customMinMss
                        font.family: "monospace"
                        font.pixelSize: Style.font.caption
                        accent: "#10B981"
                        onTextEdited: {
                          root.customMinMss = text
                          root.scheduleAutoApply()
                        }
                      }
                    }

                    Column {
                      width: (parent.width - Style.space(12)) / 3
                      spacing: 2
                      Text { text: "TTL (0 = Auto)"; color: root.dim; font.pixelSize: Style.font.caption - 1; font.family: root.fontFamily }
                      TextField {
                        width: parent.width
                        text: root.customFakeTtl
                        placeholderText: "0"
                        font.family: "monospace"
                        font.pixelSize: Style.font.caption
                        accent: "#10B981"
                        onTextEdited: {
                          root.customFakeTtl = text
                          root.scheduleAutoApply()
                        }
                      }
                    }
                  }

                  Column {
                    width: parent.width
                    spacing: 2
                    Text { text: "Fake SNI (Pool / Custom)"; color: root.dim; font.pixelSize: Style.font.caption - 1; font.family: root.fontFamily }
                    TextField {
                      width: parent.width
                      text: root.customFakeSni
                      placeholderText: "Default pool (rotating)"
                      font.family: "monospace"
                      font.pixelSize: Style.font.caption
                      accent: "#10B981"
                      onTextEdited: {
                        root.customFakeSni = text
                        root.scheduleAutoApply()
                      }
                    }
                  }

                  // grouped DPI evasion card
                  Rectangle {
                    width: parent.width
                    implicitHeight: dpiCol.implicitHeight
                    radius: Style.cornerRadius
                    color: Qt.rgba(1, 1, 1, 0.02)
                    border.color: Qt.rgba(1, 1, 1, 0.07)
                    border.width: 1
                    clip: true

                    Column {
                      id: dpiCol
                      width: parent.width

                      CompactToggle {
                        label: "Bad checksum desync (0xDEAD)"
                        description: "Poison stateful DPI inspection tables"
                        checked: root.fakeBadChecksum
                        onClicked: {
                          root.fakeBadChecksum = !root.fakeBadChecksum
                          root.applyAndSave()
                        }
                      }

                      CompactToggle {
                        label: "Block QUIC (UDP 443)"
                        description: "Force browser HTTPS fallback to TCP"
                        checked: root.blockQuicEnabled
                        onClicked: {
                          root.blockQuicEnabled = !root.blockQuicEnabled
                          root.applyAndSave()
                        }
                      }

                      CompactToggle {
                        label: "Block WebRTC STUN"
                        description: "Drop UDP 3478/5349 to prevent browser IP leaks"
                        checked: root.blockStunEnabled
                        showDivider: false
                        onClicked: {
                          root.blockStunEnabled = !root.blockStunEnabled
                          root.applyAndSave()
                        }
                      }
                    }
                  }
                }
              }

              AccordionSectionHeader {
                title: "SECURITY POLICIES"
                subtitle: (root.dnssecEnabled ? "DNSSEC • " : "") + (root.pqcEnabled ? "PQC • " : "") + (root.killSwitchEnabled ? "Kill-Switch" : "")
                sectionKey: "security"
              }

              Item {
                id: secSecurityWrap
                width: parent.width
                implicitHeight: root.activeSection === "security" ? secSecurityCol.implicitHeight : 0
                height: implicitHeight
                clip: true
                opacity: root.activeSection === "security" ? 1.0 : 0.0
                visible: height > 0

                Behavior on implicitHeight { NumberAnimation { duration: 140; easing.type: Easing.OutQuad } }
                Behavior on opacity { NumberAnimation { duration: 120; easing.type: Easing.OutQuad } }

                Column {
                  id: secSecurityCol
                  width: parent.width
                  spacing: Style.space(6)

                  // grouped security & storage card
                  Rectangle {
                    width: parent.width
                    implicitHeight: secCol.implicitHeight
                    radius: Style.cornerRadius
                    color: Qt.rgba(1, 1, 1, 0.02)
                    border.color: Qt.rgba(1, 1, 1, 0.07)
                    border.width: 1
                    clip: true

                    Column {
                      id: secCol
                      width: parent.width

                      CompactToggle {
                        label: "DNSSEC cryptographic validation"
                        description: "Enforce DO-bit & Authenticated Data verification"
                        checked: root.dnssecEnabled
                        onClicked: {
                          root.dnssecEnabled = !root.dnssecEnabled
                          root.applyAndSave()
                        }
                      }

                      CompactToggle {
                        label: "Post-Quantum Kyber768 (PQC)"
                        description: "Hybrid ML-KEM-768 quantum-safe key exchange"
                        checked: root.pqcEnabled
                        onClicked: {
                          root.pqcEnabled = !root.pqcEnabled
                          root.applyAndSave()
                        }
                      }

                      CompactToggle {
                        label: "Strict DNS Kill-Switch"
                        description: "Block non-loopback plaintext port 53 DNS leaks"
                        checked: root.killSwitchEnabled
                        onClicked: {
                          root.killSwitchEnabled = !root.killSwitchEnabled
                          root.applyAndSave()
                        }
                      }

                      CompactToggle {
                        label: "Fail-Closed Network Lockdown"
                        description: "Block outbound web traffic (ports 80/443) if eBPF fails"
                        checked: root.networkLockdownEnabled
                        onClicked: {
                          root.networkLockdownEnabled = !root.networkLockdownEnabled
                          root.applyAndSave()
                        }
                      }

                      CompactToggle {
                        label: "Filter AAAA (IPv6 drop)"
                        description: "Prevent unfragmented IPv6 inspection bypass leaks"
                        checked: root.blockIpv6Enabled
                        onClicked: {
                          root.blockIpv6Enabled = !root.blockIpv6Enabled
                          root.applyAndSave()
                        }
                      }

                      CompactToggle {
                        label: "Only-RAM volatile storage"
                        description: "Isolate state in volatile memory /run (wipes settings on reboot)"
                        checked: root.ramOnlyEnabled
                        showDivider: false
                        onClicked: {
                          root.ramOnlyEnabled = !root.ramOnlyEnabled
                          root.applyAndSave()
                        }
                      }
                    }
                  }
                }
              }

              AccordionSectionHeader {
                title: "HARDENED DNS & FILTERS"
                subtitle: (root.blocklistEnabled ? "Blocklist • " : "") + (root.localDohEnabled ? "Local DoH • " : "") + (root.tcpListenerEnabled ? "TCP:53" : "")
                sectionKey: "dns"
              }

              Item {
                id: secDnsWrap
                width: parent.width
                implicitHeight: root.activeSection === "dns" ? secDnsCol.implicitHeight : 0
                height: implicitHeight
                clip: true
                opacity: root.activeSection === "dns" ? 1.0 : 0.0
                visible: height > 0

                Behavior on implicitHeight { NumberAnimation { duration: 140; easing.type: Easing.OutQuad } }
                Behavior on opacity { NumberAnimation { duration: 120; easing.type: Easing.OutQuad } }

                Column {
                  id: secDnsCol
                  width: parent.width
                  spacing: Style.space(6)

                  // Protocol Listeners Card
                  Rectangle {
                    width: parent.width
                    implicitHeight: protoCol.implicitHeight
                    radius: Style.cornerRadius
                    color: Qt.rgba(1, 1, 1, 0.02)
                    border.color: Qt.rgba(1, 1, 1, 0.07)
                    border.width: 1
                    clip: true

                    Column {
                      id: protoCol
                      width: parent.width

                      CompactToggle {
                        label: "Local TCP Port 53 Listener"
                        description: "RFC 7766 length-prefixed framing and pipelining"
                        checked: root.tcpListenerEnabled
                        onClicked: {
                          root.tcpListenerEnabled = !root.tcpListenerEnabled
                          root.applyAndSave()
                        }
                      }

                      CompactToggle {
                        label: "Local DoH Server (RFC 8484)"
                        description: "Local HTTP/1.1 endpoint for browsers and apps"
                        checked: root.localDohEnabled
                        onClicked: {
                          root.localDohEnabled = !root.localDohEnabled
                          root.applyAndSave()
                        }
                      }

                      CompactToggle {
                        label: "Dynamic Network Monitor (Netmon)"
                        description: "Live interface and routing transitions monitor"
                        checked: root.netmonEnabled
                        showDivider: false
                        onClicked: {
                          root.netmonEnabled = !root.netmonEnabled
                          root.applyAndSave()
                        }
                      }
                    }
                  }

                  // Local DoH address row
                  Column {
                    width: parent.width
                    visible: root.localDohEnabled
                    spacing: 2
                    Text { text: "Local DoH Listen Address"; color: root.dim; font.pixelSize: Style.font.caption - 1; font.family: root.fontFamily }
                    TextField {
                      width: parent.width
                      text: root.localDohAddr
                      placeholderText: "127.0.0.1:8053"
                      font.family: "monospace"
                      font.pixelSize: Style.font.caption
                      accent: "#10B981"
                      onTextEdited: {
                        root.localDohAddr = text
                        root.scheduleAutoApply()
                      }
                    }
                  }

                  // Logging & Privacy Card
                  Rectangle {
                    width: parent.width
                    implicitHeight: logCol.implicitHeight
                    radius: Style.cornerRadius
                    color: Qt.rgba(1, 1, 1, 0.02)
                    border.color: Qt.rgba(1, 1, 1, 0.07)
                    border.width: 1
                    clip: true

                    Column {
                      id: logCol
                      width: parent.width

                      CompactToggle {
                        label: "Structured Query Audit Log"
                        description: "Asynchronous rotating TSV query logger"
                        checked: root.queryLogEnabled
                        onClicked: {
                          root.queryLogEnabled = !root.queryLogEnabled
                          root.applyAndSave()
                        }
                      }

                      CompactToggle {
                        label: "EDNS0 Padding (RFC 8467)"
                        description: "Discretize encrypted query lengths against analysis"
                        checked: root.ednsPaddingEnabled
                        showDivider: false
                        onClicked: {
                          root.ednsPaddingEnabled = !root.ednsPaddingEnabled
                          root.applyAndSave()
                        }
                      }
                    }
                  }

                  // Query log path & IPcrypt key inputs
                  Column {
                    width: parent.width
                    visible: root.queryLogEnabled
                    spacing: Style.space(4)

                    Text { text: "Query Log Output Path (Optional)"; color: root.dim; font.pixelSize: Style.font.caption - 1; font.family: root.fontFamily }
                    TextField {
                      width: parent.width
                      text: root.queryLogPath
                      placeholderText: "Default: /var/log/albus/query.log"
                      font.family: "monospace"
                      font.pixelSize: Style.font.caption
                      accent: "#10B981"
                      onTextEdited: {
                        root.queryLogPath = text
                        root.scheduleAutoApply()
                      }
                    }

                    Text { text: "IPcrypt Client IP Key (Optional 32-hex / Passphrase)"; color: root.dim; font.pixelSize: Style.font.caption - 1; font.family: root.fontFamily }
                    TextField {
                      width: parent.width
                      text: root.ipcryptKey
                      placeholderText: "e.g. 1234567890abcdef1234567890abcdef"
                      font.family: "monospace"
                      font.pixelSize: Style.font.caption
                      accent: "#10B981"
                      onTextEdited: {
                        root.ipcryptKey = text
                        root.scheduleAutoApply()
                      }
                    }
                  }

                  // Threat Filtering & Defense Card
                  Rectangle {
                    width: parent.width
                    implicitHeight: filterCol.implicitHeight
                    radius: Style.cornerRadius
                    color: Qt.rgba(1, 1, 1, 0.02)
                    border.color: Qt.rgba(1, 1, 1, 0.07)
                    border.width: 1
                    clip: true

                    Column {
                      id: filterCol
                      width: parent.width

                      CompactToggle {
                        label: "Threat Blocklist"
                        description: "HaGeZi Multi PRO + TIF in-memory Bloom filter"
                        checked: root.blocklistEnabled
                        onClicked: {
                          root.blocklistEnabled = !root.blocklistEnabled
                          root.applyAndSave()
                        }
                      }

                      CompactToggle {
                        label: "Anti-DNS Rebinding Shield"
                        description: "Drop responses resolving to RFC 1918 private IPs"
                        checked: root.antiRebindingEnabled
                        onClicked: {
                          root.antiRebindingEnabled = !root.antiRebindingEnabled
                          root.applyAndSave()
                        }
                      }

                      CompactToggle {
                        label: "Bogon IP Subnet Filter"
                        description: "Drop martian and unroutable bogon IP ranges"
                        checked: root.blockBogonsEnabled
                        onClicked: {
                          root.blockBogonsEnabled = !root.blockBogonsEnabled
                          root.applyAndSave()
                        }
                      }

                      CompactToggle {
                        label: "CNAME / HTTPS Uncloaking"
                        description: "Inspect canonical name targets against blocklist"
                        checked: root.uncloakCnamesEnabled
                        onClicked: {
                          root.uncloakCnamesEnabled = !root.uncloakCnamesEnabled
                          root.applyAndSave()
                        }
                      }

                      CompactToggle {
                        label: "Block Undelegated & Dotless"
                        description: "Sinkhole .local, .lan, and single-label queries"
                        checked: root.blockUndelegatedEnabled
                        onClicked: {
                          root.blockUndelegatedEnabled = !root.blockUndelegatedEnabled
                          root.applyAndSave()
                        }
                      }

                      CompactToggle {
                        label: "DNS64 IPv6 Synthesis"
                        description: "Synthesize RFC 6052 AAAA records for IPv4 hosts"
                        checked: root.dns64Enabled
                        showDivider: false
                        onClicked: {
                          root.dns64Enabled = !root.dns64Enabled
                          root.applyAndSave()
                        }
                      }
                    }
                  }
                }
              }

              // operational triggers
              Row {
                width: parent.width
                spacing: Style.space(6)

                Button {
                  width: (mainColumn.width - Style.space(6)) / 2
                  text: "Restart Service"
                  bordered: true
                  fontSize: Style.font.caption
                  onClicked: root.restartDaemon()
                }

                Button {
                  width: (mainColumn.width - Style.space(6)) / 2
                  text: "Flush Cache"
                  bordered: true
                  fontSize: Style.font.caption
                  onClicked: root.purgeDnsCache()
                }
              }
            }

            // tab 1: realtime packet flow telemetry stream (LOGS)
            Column {
              id: tab1
              width: parent.width
              visible: root.activeTab === 1
              opacity: root.activeTab === 1 ? 1.0 : 0.0
              spacing: Style.space(6)

              Behavior on opacity {
                NumberAnimation { duration: 160; easing.type: Easing.OutQuad }
              }

              // telemetry counters header (4 interactive metric cards)
              Row {
                width: parent.width
                spacing: Style.space(4)

                Repeater {
                  model: [
                    { key: "INJECT", label: "Injected", count: root.countInjected, color: "#38BDF8" },
                    { key: "DNS",    label: "DoH Resolv", count: root.countDns,      color: "#A855F7" },
                    { key: "QUIC",   label: "QUIC Block", count: root.countQuic,     color: "#F59E0B" },
                    { key: "SHIELD", label: "Shield",     count: root.countShield,   color: "#10B981" }
                  ]

                  Rectangle {
                    id: metricCard
                    width: (mainColumn.width - Style.space(12)) / 4
                    height: Style.space(38)
                    radius: Style.cornerRadius
                    readonly property color cardCol: modelData.color
                    readonly property bool isSelected: root.streamFilter === modelData.key
                    color: isSelected 
                      ? Qt.rgba(cardCol.r, cardCol.g, cardCol.b, 0.16)
                      : (cardMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.05) : Qt.rgba(1, 1, 1, 0.02))
                    border.color: isSelected 
                      ? cardCol 
                      : (cardMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.15) : root.borderMuted)
                    border.width: isSelected ? 1.5 : 1

                    Behavior on color { ColorAnimation { duration: 90 } }
                    Behavior on border.color { ColorAnimation { duration: 90 } }

                    MouseArea {
                      id: cardMouse
                      anchors.fill: parent
                      hoverEnabled: true
                      cursorShape: Qt.PointingHandCursor
                      onClicked: {
                        if (root.streamFilter === modelData.key) {
                          root.setFilter("ALL")
                        } else {
                          root.setFilter(modelData.key)
                        }
                      }
                    }

                    ColumnLayout {
                      anchors.centerIn: parent
                      spacing: 0

                      Text {
                        text: String(modelData.count)
                        font.bold: true
                        font.family: "monospace"
                        font.pixelSize: Style.font.bodySmall
                        color: modelData.color
                        Layout.alignment: Qt.AlignHCenter
                      }

                      Text {
                        text: modelData.label
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption - 2
                        font.bold: metricCard.isSelected
                        color: metricCard.isSelected ? root.foreground : root.dim
                        Layout.alignment: Qt.AlignHCenter
                      }
                    }
                  }
                }
              }

              // search input
              TextField {
                width: parent.width
                placeholderText: "Search domain (e.g. discord, chatgpt)..."
                text: root.streamSearchQuery
                font.pixelSize: Style.font.caption
                onTextChanged: {
                  root.streamSearchQuery = text
                  root.updateDisplayEvents()
                }
              }

              // category filter pills, live packet flow rate, pause, clear & terminal actions
              Item {
                width: parent.width
                implicitHeight: Math.max(filterPillsRow.implicitHeight, rightStreamControls.implicitHeight)

                Row {
                  id: filterPillsRow
                  anchors.left: parent.left
                  anchors.verticalCenter: parent.verticalCenter
                  spacing: Style.space(4)

                  Button {
                    text: "All"
                    selected: root.streamFilter === "ALL"
                    bordered: true
                    fontSize: Style.font.caption - 1
                    horizontalPadding: Style.space(6)
                    verticalPadding: Style.space(2)
                    onClicked: root.setFilter("ALL")
                  }

                  Button {
                    text: "Inject"
                    selected: root.streamFilter === "INJECT"
                    bordered: true
                    fontSize: Style.font.caption - 1
                    horizontalPadding: Style.space(6)
                    verticalPadding: Style.space(2)
                    onClicked: root.setFilter("INJECT")
                  }

                  Button {
                    text: "DNS"
                    selected: root.streamFilter === "DNS"
                    bordered: true
                    fontSize: Style.font.caption - 1
                    horizontalPadding: Style.space(6)
                    verticalPadding: Style.space(2)
                    onClicked: root.setFilter("DNS")
                  }

                  Button {
                    text: "QUIC"
                    selected: root.streamFilter === "QUIC"
                    bordered: true
                    fontSize: Style.font.caption - 1
                    horizontalPadding: Style.space(6)
                    verticalPadding: Style.space(2)
                    onClicked: root.setFilter("QUIC")
                  }

                  Button {
                    text: "Shield"
                    selected: root.streamFilter === "SHIELD"
                    bordered: true
                    fontSize: Style.font.caption - 1
                    horizontalPadding: Style.space(6)
                    verticalPadding: Style.space(2)
                    onClicked: root.setFilter("SHIELD")
                  }
                }

                Row {
                  id: rightStreamControls
                  anchors.right: parent.right
                  anchors.verticalCenter: parent.verticalCenter
                  spacing: Style.space(4)

                  // live flow rate indicator badge
                  Rectangle {
                    height: pauseStreamBtn.height
                    width: rateContentRow.implicitWidth + Style.space(10)
                    radius: Style.cornerRadius
                    color: Qt.rgba(1, 1, 1, 0.03)
                    border.color: root.borderMuted
                    border.width: 1

                    Row {
                      id: rateContentRow
                      anchors.centerIn: parent
                      spacing: Style.space(4)

                      Rectangle {
                        width: 5
                        height: 5
                        radius: 0
                        anchors.verticalCenter: parent.verticalCenter
                        color: (root.isRunning && !root.isStreamPaused) ? "#10B981" : root.dim
                      }

                      Text {
                        text: root.eventRateText
                        font.family: "monospace"
                        font.pixelSize: Style.font.caption - 2
                        color: root.dim
                        anchors.verticalCenter: parent.verticalCenter
                      }
                    }
                  }

                  Button {
                    id: pauseStreamBtn
                    text: root.isStreamPaused ? "Resume" : "Pause"
                    selected: root.isStreamPaused
                    bordered: true
                    fontSize: Style.font.caption - 1
                    horizontalPadding: Style.space(6)
                    verticalPadding: Style.space(2)
                    onClicked: root.togglePause()
                  }

                  Button {
                    text: "Clear"
                    bordered: true
                    fontSize: Style.font.caption - 1
                    horizontalPadding: Style.space(6)
                    verticalPadding: Style.space(2)
                    onClicked: root.clearStream()
                  }

                  Button {
                    text: "TUI"
                    bordered: true
                    fontSize: Style.font.caption - 1
                    horizontalPadding: Style.space(6)
                    verticalPadding: Style.space(2)
                    onClicked: root.openMonitor()
                  }
                }
              }

              // borderless terminal stream list with smart pinning
              BorderSurface {
                width: parent.width
                height: Style.space(330)
                color: Style.normalFillFor(root.foreground, root.accent)
                borderSpec: Border.controlSpec("normal", root.foreground, root.accent)
                radius: Style.cornerRadius
                clip: true

                ListView {
                  id: streamListView
                  anchors.fill: parent
                  anchors.leftMargin: Style.space(6)
                  anchors.rightMargin: Style.space(6)
                  anchors.topMargin: Style.space(6)
                  anchors.bottomMargin: Style.space(6)
                  model: root.displayEvents
                  spacing: Style.space(3)
                  boundsBehavior: Flickable.StopAtBounds

                  onContentYChanged: {
                    var maxScroll = contentHeight - height
                    root.isAtBottom = (maxScroll <= 0 || (maxScroll - contentY) < 30)
                  }

                  delegate: Rectangle {
                    id: eventCard
                    width: streamListView.width
                    height: Style.space(30)
                    radius: Style.cornerRadius
                    readonly property color badgeCol: modelData.badgeColor
                    readonly property bool isCopied: root.copiedEventId === index
                    color: isCopied
                      ? Qt.rgba(0.06, 0.72, 0.5, 0.16)
                      : (eventMouse.containsMouse ? Style.hoverFillFor(root.foreground, modelData.badgeColor) : "transparent")

                    Behavior on color { ColorAnimation { duration: 90 } }

                    MouseArea {
                      id: eventMouse
                      anchors.fill: parent
                      hoverEnabled: true
                      cursorShape: Qt.PointingHandCursor
                      onClicked: {
                        root.copyToClipboard(modelData.title + (modelData.tag ? " " + modelData.tag : ""))
                        root.copiedEventId = index
                        copiedFeedbackTimer.restart()
                      }
                    }

                    RowLayout {
                      anchors.fill: parent
                      anchors.leftMargin: Style.space(6)
                      anchors.rightMargin: Style.space(6)
                      spacing: Style.space(8)

                      // 1. Sleek category micro badge pill
                      Rectangle {
                        implicitWidth: catText.implicitWidth + Style.space(8)
                        implicitHeight: Style.space(18)
                        radius: Style.cornerRadius
                        color: Qt.rgba(badgeCol.r, badgeCol.g, badgeCol.b, 0.14)
                        border.color: Qt.rgba(badgeCol.r, badgeCol.g, badgeCol.b, 0.35)
                        border.width: 1
                        Layout.alignment: Qt.AlignVCenter

                        Text {
                          id: catText
                          anchors.centerIn: parent
                          text: modelData.category
                          font.family: "monospace"
                          font.pixelSize: Style.font.caption - 2
                          font.bold: true
                          color: modelData.badgeColor
                        }
                      }

                      // 2. Title / target domain
                      Text {
                        Layout.fillWidth: true
                        text: modelData.title
                        textFormat: Text.PlainText
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                        font.bold: true
                        color: root.foreground
                        elide: Text.ElideRight
                      }

                      // 3. Detail text (hidden on narrow widths)
                      Text {
                        text: modelData.detail
                        textFormat: Text.PlainText
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption - 1
                        color: root.dim
                        visible: eventCard.width > Style.space(340)
                        elide: Text.ElideRight
                      }

                      // 4. Tag pill (TTL, DNSSEC, 0ms Cache, etc.)
                      Rectangle {
                        visible: modelData.tag !== undefined && modelData.tag !== ""
                        implicitWidth: tagText.implicitWidth + Style.space(8)
                        implicitHeight: Style.space(16)
                        radius: Style.cornerRadius
                        color: Qt.rgba(1, 1, 1, 0.05)
                        border.color: Qt.rgba(1, 1, 1, 0.10)
                        border.width: 1
                        Layout.alignment: Qt.AlignVCenter

                        Text {
                          id: tagText
                          anchors.centerIn: parent
                          text: modelData.tag || ""
                          font.family: "monospace"
                          font.pixelSize: Style.font.caption - 2
                          color: root.dim
                        }
                      }

                      // 5. Copied badge or Timestamp
                      Text {
                        text: eventCard.isCopied ? "COPIED" : modelData.time
                        textFormat: Text.PlainText
                        font.family: "monospace"
                        font.pixelSize: Style.font.caption - 1
                        font.bold: eventCard.isCopied
                        color: eventCard.isCopied ? "#10B981" : root.dim
                        Layout.alignment: Qt.AlignVCenter
                      }
                    }
                  }

                  Text {
                    anchors.centerIn: parent
                    visible: root.displayEvents.length === 0
                    text: root.streamSearchQuery !== ""
                      ? "No events matching \"" + root.streamSearchQuery + "\""
                      : (root.isRunning ? "Listening for real-time DPI flows..." : "Service is offline. Start Albus to stream flows.")
                    textFormat: Text.PlainText
                    color: root.dim
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                  }
                }

                // Floating Jump to latest button when user scrolls up
                Rectangle {
                  visible: !root.isAtBottom && root.displayEvents.length > 0
                  anchors.bottom: parent.bottom
                  anchors.horizontalCenter: parent.horizontalCenter
                  anchors.bottomMargin: Style.space(8)
                  width: jumpText.implicitWidth + Style.space(16)
                  height: Style.space(22)
                  radius: Style.cornerRadius
                  color: Qt.rgba(0.08, 0.08, 0.10, 0.95)
                  border.color: root.borderMuted
                  border.width: 1

                  MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: {
                      streamListView.positionViewAtEnd()
                      root.isAtBottom = true
                    }
                  }

                  Text {
                    id: jumpText
                    anchors.centerIn: parent
                    text: "Jump to latest"
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption - 1
                    font.bold: true
                    color: "#38BDF8"
                  }
                }
              }
            }
          }

          // ephemeral user toast feedback badge
          BorderSurface {
            visible: root.toastMessage !== ""
            width: parent.width
            implicitHeight: Style.space(26)
            radius: Style.cornerRadius
            color: Style.hoverFillFor(root.foreground, "#10B981")
            borderSpec: Border.controlSpec("selected", root.foreground, "#10B981")

            Text {
              anchors.centerIn: parent
              text: root.toastMessage
              textFormat: Text.PlainText
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              font.bold: true
              color: "#10B981"
            }
          }

          // keybindings footer
          Item {
            width: parent.width
            implicitHeight: Math.max(leftHint.implicitHeight, rightHint.implicitHeight)

            Text {
              id: leftHint
              anchors.left: parent.left
              anchors.verticalCenter: parent.verticalCenter
              text: "1-2 tabs • space toggle"
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption - 1
              color: root.dim
            }

            Text {
              id: rightHint
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              text: "p pause • j/k scroll • esc close"
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption - 1
              color: root.dim
            }
          }
        }
      }
    }
  }
}
