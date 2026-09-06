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
  property string serviceUptime: ""
  property double activeStartTime: 0

  onIsRunningChanged: {
    if (isRunning) {
      refreshUptime()
    } else {
      root.serviceUptime = ""
      root.activeStartTime = 0
    }
  }

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
  property bool odohEnabled: false
  property string odohRelay: ""
  property string odohTarget: ""
  property bool dnsRacingEnabled: true

  // upstream proxy, tor & mtls runtime state
  property bool torEnabled: false
  property string socks5Proxy: ""
  property string tlsClientCert: ""
  property string tlsClientKey: ""

  // security audit, ecs & telemetry runtime state
  property bool nxLogEnabled: false
  property string nxLogPath: ""
  property string ednsClientSubnet: ""
  property bool metricsEnabled: false
  property string metricsAddr: "127.0.0.1:9153"

  // split dns, cache tuning, web ui & dnscrypt relays
  property string forwardRulesPath: "/etc/albus/forwarding-rules.txt"
  property string tlsKeyLogFile: ""
  property bool loadAdaptiveTimeoutEnabled: true
  property string negMinTtl: "60"
  property string negMaxTtl: "600"
  property bool webUiEnabled: true
  property string webUiAddr: "127.0.0.1:0205"
  property string webUiUser: ""
  property string webUiPassword: ""
  property string dnscryptRelays: ""
  property string dnscryptServers: ""

  // preserved CLI configuration parameters not directly exposed in UI
  property var storedPorts: [443]
  property int storedRestoreAfterBytes: 600
  property int storedRestoreMss: 0
  property string storedCgroup: "/sys/fs/cgroup"
  property int storedFakeSeqOffset: 0
  property int storedMinTtl: 3
  property int storedMaxTtl: 12
  property var storedAllowDomains: []
  property string storedAllowlistPath: ""
  property string lastDaemonAction: ""

  onOpenedChanged: if (opened) {
    loadConfig()
    refreshStatus()
    refreshUptime()
  }

  Component.onCompleted: {
    loadConfig()
    refreshStatus()
    refreshUptime()
  }

  // event stream telemetry state
  property var rawStreamEvents: []
  property var displayEvents: []
  property var pendingStreamEvents: []
  property string streamFilter: "ALL"
  property string streamSearchQuery: ""
  property bool isStreamPaused: false
  property bool isAtBottom: true
  property int copiedEventId: -1
  property int selectedLogIndex: -1
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
    radius: Style.cornerRadius
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

  component StyledTextField: TextField {
    id: stfRoot
    verticalPadding: Style.space(4)
    horizontalPadding: Style.space(8)
    selectByMouse: true
    font.family: "monospace"
    font.pixelSize: Style.font.caption
    color: root.foreground
    placeholderTextColor: root.subtle
    selectionColor: Qt.rgba(0.06, 0.72, 0.51, 0.3)
    selectedTextColor: root.foreground
    accent: "#10B981"
    background: Rectangle {
      radius: Style.cornerRadius
      color: stfRoot.activeFocus ? Qt.rgba(0.06, 0.72, 0.51, 0.08) : (stfRoot.hovered ? Qt.rgba(1, 1, 1, 0.05) : Qt.rgba(1, 1, 1, 0.02))
      border.color: stfRoot.activeFocus ? "#10B981" : (stfRoot.hovered ? Qt.rgba(1, 1, 1, 0.18) : Qt.rgba(1, 1, 1, 0.08))
      border.width: 1
      Behavior on border.color { ColorAnimation { duration: 90 } }
      Behavior on color { ColorAnimation { duration: 90 } }
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
    color: isOpen ? Qt.rgba(1, 1, 1, 0.05) : (ashMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.03) : "transparent")
    border.color: isOpen ? Qt.rgba(1, 1, 1, 0.12) : (ashMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.06) : "transparent")
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
        height: ashRoot.isOpen ? Style.space(14) : Style.space(8)
        radius: 1.5
        color: ashRoot.isOpen ? ashRoot.accent : Qt.rgba(1, 1, 1, 0.15)
        Layout.alignment: Qt.AlignVCenter
        Behavior on height { NumberAnimation { duration: 120; easing.type: Easing.OutQuad } }
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
        color: ashRoot.isOpen ? Qt.darker(root.foreground, 1.5) : root.subtle
        textFormat: Text.PlainText
        elide: Text.ElideRight
        Layout.fillWidth: true
        Layout.alignment: Qt.AlignVCenter
      }

      Text {
        text: "›"
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        font.bold: true
        color: ashRoot.isOpen ? ashRoot.accent : root.subtle
        Layout.alignment: Qt.AlignVCenter
        transformOrigin: Item.Center
        rotation: ashRoot.isOpen ? 90 : 0
        Behavior on rotation { NumberAnimation { duration: 120; easing.type: Easing.OutQuad } }
        Behavior on color { ColorAnimation { duration: 90 } }
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
    id: uptimeTimer
    interval: 1000
    running: root.opened && root.isRunning
    repeat: true
    triggeredOnStart: true
    onTriggered: {
      if (root.activeStartTime > 0) {
        var diffSec = Math.max(0, Math.floor((Date.now() - root.activeStartTime) / 1000))
        root.serviceUptime = root.formatUptime(diffSec)
      } else if (root.isRunning && !uptimeProc.running) {
        uptimeProc.running = true
      }
    }
  }

  Timer {
    id: copiedFeedbackTimer
    interval: 1200
    onTriggered: root.copiedEventId = -1
  }

  Timer {
    id: streamBatchTimer
    interval: 35
    repeat: false
    onTriggered: root.flushStreamBatch()
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

    if (clean.indexOf("fake ClientHello injected") !== -1 || clean.indexOf("ClientHello") !== -1 || (clean.indexOf("HTTP") !== -1 && clean.indexOf("split") !== -1)) {
      category = "INJECT"
      badgeColor = "#38BDF8"
      var isHttp = clean.indexOf("HTTP") !== -1 && clean.indexOf("split") !== -1
      var dstMatch = clean.match(/dst=([^\s]+)/)
      var ttlMatch = clean.match(/ttl=([^\s]+)/)
      var badCsMatch = clean.match(/bad_csum=([^\s]+)/) || clean.match(/bad_cs=([^\s]+)/)
      title = isHttp ? "HTTP Request Split" : (dstMatch ? dstMatch[1] : "TLS ClientHello")
      var isBad = badCsMatch && (badCsMatch[1] === "true" || badCsMatch[1] === "1")
      detail = isHttp ? "HTTP verb fragmented" : (isBad ? "0xDEAD desync" : "Desync injected")
      tag = isHttp ? "HTTP/1.1" : ((isBad ? "0xDEAD · " : "") + (ttlMatch ? "TTL " + ttlMatch[1] : "TTL"))
    } else if (clean.indexOf("HaGeZi") !== -1 || clean.indexOf("blocked by HaGeZi") !== -1 || clean.indexOf("CNAME cloaking") !== -1 || clean.indexOf("uncloaked_target") !== -1 || clean.indexOf("Bogon") !== -1 || clean.indexOf("Anti-DNS") !== -1 || clean.indexOf("Rebinding") !== -1 || clean.indexOf("STUN") !== -1 || clean.indexOf("WebRTC") !== -1 || clean.indexOf("canary") !== -1 || clean.indexOf("Kill-Switch") !== -1 || clean.indexOf("Lockdown") !== -1 || clean.indexOf("undelegated") !== -1) {
      category = "SHIELD"
      badgeColor = "#10B981"
      var isHagezi = clean.indexOf("HaGeZi") !== -1 || clean.indexOf("blocked by HaGeZi") !== -1
      var isCname = clean.indexOf("CNAME cloaking") !== -1 || clean.indexOf("uncloaked_target") !== -1
      var isBogon = clean.indexOf("Bogon") !== -1 || clean.indexOf("bogon") !== -1
      var isRebind = clean.indexOf("Anti-DNS") !== -1 || clean.indexOf("Rebinding") !== -1
      var isLock = clean.indexOf("Lockdown") !== -1
      var isCanary = clean.indexOf("canary") !== -1
      var isStun = clean.indexOf("STUN") !== -1 || clean.indexOf("WebRTC") !== -1
      var domMatch = clean.match(/domain=([^\s]+)/) || clean.match(/uncloaked_target=([^\s]+)/)
      var cleanDom = ""
      if (domMatch) {
        cleanDom = domMatch[1].replace(/^Some\(/, "").replace(/\)$/, "").replace(/["',?]/g, "")
      }
      var targetMatch = clean.match(/uncloaked_target=([^\s]+)/)
      var cleanTarget = targetMatch ? targetMatch[1].replace(/["',?]/g, "") : ""

      if (isHagezi) {
        title = cleanDom !== "" ? cleanDom : "HaGeZi Block"
        detail = "Threat filtered"
        tag = "Threat Block"
      } else if (isCname) {
        title = cleanTarget !== "" ? cleanTarget : (cleanDom !== "" ? cleanDom : "CNAME Tracker Block")
        detail = "Uncloaked tracker"
        tag = "Uncloak"
      } else if (isBogon) {
        title = cleanDom !== "" ? cleanDom : "Bogon IP Dropped"
        detail = "Bogon IP dropped"
        tag = "Bogon Drop"
      } else if (isRebind) {
        title = cleanDom !== "" ? cleanDom : "DNS Rebinding Shield"
        detail = "Private IP blocked"
        tag = "Anti-Rebind"
      } else if (isLock) {
        title = "Network Lockdown Rule"
        detail = "TCP 80/443 lockdown"
        tag = "Lockdown"
      } else if (isCanary) {
        title = "DNS Leak Canary Probe"
        detail = "Leak probe intercepted"
        tag = "Canary"
      } else if (isStun) {
        title = "WebRTC STUN Block"
        detail = "STUN IP leak blocked"
        tag = "STUN Drop"
      } else {
        title = cleanDom !== "" ? cleanDom : "Privacy Shield Block"
        detail = "Undelegated query drop"
        tag = "Shield"
      }
    } else if (clean.indexOf("DNS cache hit") !== -1 || clean.indexOf("cache_0ms") !== -1 || clean.indexOf("cloaking table") !== -1) {
      category = "DNS"
      badgeColor = "#A855F7"
      var domMatch = clean.match(/domain=([^\s]+)/)
      title = domMatch ? domMatch[1].replace(/["',]/g, "") : "DNS Cache Hit"
      detail = "0ms memory cache"
      tag = "0ms Cache"
    } else if (clean.indexOf("DNS server started") !== -1 || clean.indexOf("DNS-over-HTTPS proxy listening") !== -1) {
      category = "SYS"
      badgeColor = "#A855F7"
      title = "DoH Resolver Online"
      detail = "127.0.0.1:53 ready"
      tag = "127.0.0.1"
    } else if (clean.indexOf("DNS resolved") !== -1 || clean.indexOf("DNS") !== -1 || clean.indexOf("query") !== -1 || clean.indexOf("resolved") !== -1) {
      category = "DNS"
      badgeColor = "#A855F7"
      var domMatch = clean.match(/domain=([^\s]+)/) || clean.match(/upstream=([^\s]+)/)
      var dnssecMatch = clean.match(/dnssec_authenticated=true/) || clean.match(/is_ad=true/)
      title = domMatch ? domMatch[1].replace(/["',]/g, "") : "DoH Query"
      detail = "Encrypted DoH"
      tag = dnssecMatch ? "DNSSEC" : "DoH"
    } else if (clean.indexOf("QUIC") !== -1) {
      category = "QUIC"
      badgeColor = "#F59E0B"
      title = "QUIC (UDP 443) Blocked"
      detail = "Forced TCP fallback"
      tag = "UDP 443"
    } else if (clean.indexOf("Error") !== -1 || clean.indexOf("Failed") !== -1 || clean.indexOf("ERROR") !== -1 || clean.indexOf("WARN") !== -1 || clean.indexOf("panicked") !== -1) {
      category = "ERROR"
      badgeColor = "#EF4444"
      var errTitle = clean.replace(/.*(?:Error|ERROR|WARN|panicked):\s*/, "")
      title = errTitle !== "" ? errTitle : clean
      detail = "Service warning / alert"
      tag = "ALERT"
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

    if (root.isStreamPaused) return

    root.pendingStreamEvents.push(parsed)
    if (!streamBatchTimer.running) {
      streamBatchTimer.start()
    }
  }

  function flushStreamBatch() {
    if (root.pendingStreamEvents.length === 0) return

    var batch = root.pendingStreamEvents
    root.pendingStreamEvents = []

    var list = root.rawStreamEvents.slice()
    for (var i = 0; i < batch.length; i++) {
      list.push(batch[i])
    }
    if (list.length > 500) {
      list = list.slice(list.length - 500)
    }
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
    root.pendingStreamEvents = []
    streamBatchTimer.stop()
    root.rawStreamEvents = []
    root.displayEvents = []
    root.recentEventCount = 0
    root.eventRateText = "idle"
    root.copiedEventId = -1
    root.selectedLogIndex = -1
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
    if (root.isRunning && root.activeStartTime === 0) refreshUptime()
  }

  function refreshUptime() {
    if (!uptimeProc.running) uptimeProc.running = true
  }

  function formatUptime(sec) {
    if (sec < 0) sec = 0
    var m = Math.floor(sec / 60)
    var s = sec % 60
    var h = Math.floor(m / 60)
    var d = Math.floor(h / 24)
    if (d > 0) return d + "d " + (h % 24) + "h"
    if (h > 0) return h + "h " + (m % 60) + "m"
    if (m > 0) return m + "m " + s + "s"
    return s + "s"
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
    args.push("--odoh", root.odohEnabled ? "true" : "false")
    if (root.odohRelay.trim() !== "") {
      args.push("--odoh-relay", root.odohRelay.trim())
    }
    if (root.odohTarget.trim() !== "") {
      args.push("--odoh-target", root.odohTarget.trim())
    }

    args.push("--dns-racing", root.dnsRacingEnabled ? "true" : "false")

    // upstream proxy, tor & mtls parameters
    args.push("--tor", root.torEnabled ? "true" : "false")
    args.push("--socks5-proxy", root.socks5Proxy.trim())
    args.push("--tls-client-cert", root.tlsClientCert.trim())
    args.push("--tls-client-key", root.tlsClientKey.trim())

    // security audit, ecs & telemetry parameters
    args.push("--nx-log", root.nxLogEnabled ? "true" : "false")
    args.push("--nx-log-path", root.nxLogPath.trim())
    args.push("--edns-client-subnet", root.ednsClientSubnet.trim())
    args.push("--metrics", root.metricsEnabled ? "true" : "false")
    args.push("--metrics-addr", root.metricsAddr.trim() !== "" ? root.metricsAddr.trim() : "127.0.0.1:9153")

    // split dns, cache tuning, web ui & dnscrypt relays
    if (root.forwardRulesPath.trim() !== "") {
      args.push("--forward-rules-path", root.forwardRulesPath.trim())
    }
    if (root.tlsKeyLogFile.trim() !== "") {
      args.push("--tls-key-log-file", root.tlsKeyLogFile.trim())
    }
    args.push("--timeout-load-reduction", root.loadAdaptiveTimeoutEnabled ? "0.75" : "0.0")
    if (root.negMinTtl.trim() !== "") {
      args.push("--neg-min-ttl", root.negMinTtl.trim())
    }
    if (root.negMaxTtl.trim() !== "") {
      args.push("--neg-max-ttl", root.negMaxTtl.trim())
    }
    args.push("--web-ui", root.webUiEnabled ? "true" : "false")
    if (root.webUiAddr.trim() !== "") {
      args.push("--web-ui-addr", root.webUiAddr.trim())
    }
    if (root.webUiUser.trim() !== "") {
      args.push("--web-ui-user", root.webUiUser.trim())
    }
    if (root.webUiPassword.trim() !== "") {
      args.push("--web-ui-password", root.webUiPassword.trim())
    }
    if (root.dnscryptRelays.trim() !== "") {
      args.push("--dnscrypt-relays", root.dnscryptRelays.trim())
    }
    if (root.dnscryptServers.trim() !== "") {
      args.push("--dnscrypt-servers", root.dnscryptServers.trim())
    }

    // preserve backend tuning parameters
    if (root.storedPorts && root.storedPorts.length > 0) {
      args.push("--ports", root.storedPorts.join(","))
    }
    args.push("--restore-after-bytes", String(root.storedRestoreAfterBytes))
    args.push("--restore-mss", String(root.storedRestoreMss))
    if (root.storedCgroup) {
      args.push("--cgroup", root.storedCgroup)
    }
    args.push("--fake-seq-offset", String(root.storedFakeSeqOffset))
    args.push("--min-ttl", String(root.storedMinTtl))
    args.push("--max-ttl", String(root.storedMaxTtl))
    if (root.storedAllowDomains && root.storedAllowDomains.length > 0) {
      args.push("--allow-domains", root.storedAllowDomains.join(","))
    }
    if (root.storedAllowlistPath && root.storedAllowlistPath.trim() !== "") {
      args.push("--allowlist-path", root.storedAllowlistPath.trim())
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
    root.lastDaemonAction = "restart"
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
    id: uptimeProc
    command: ["systemctl", "show", "albus.service", "--property=ActiveEnterTimestamp", "--value"]
    running: false
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        var clean = text ? text.trim() : ""
        var m = clean.match(/(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})/)
        if (m) {
          var d = new Date(m[1] + "T" + m[2])
          if (!isNaN(d.getTime())) {
            root.activeStartTime = d.getTime()
            var diffSec = Math.max(0, Math.floor((Date.now() - root.activeStartTime) / 1000))
            root.serviceUptime = root.formatUptime(diffSec)
          }
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
          root.odohEnabled = !!cfg.odoh_enabled
          root.odohRelay = cfg.odoh_relay || ""
          root.odohTarget = cfg.odoh_target || ""
          root.dnsRacingEnabled = cfg.dns_racing !== false

          // load upstream proxy, tor & mtls
          root.torEnabled = !!cfg.tor
          root.socks5Proxy = cfg.socks5_proxy || ""
          root.tlsClientCert = cfg.tls_client_cert || ""
          root.tlsClientKey = cfg.tls_client_key || ""

          // load security audit, ecs & telemetry
          root.nxLogEnabled = !!cfg.nx_log
          root.nxLogPath = cfg.nx_log_path || ""
          root.ednsClientSubnet = cfg.edns_client_subnet || ""
          root.metricsEnabled = !!cfg.metrics
          root.metricsAddr = cfg.metrics_addr || "127.0.0.1:9153"

          // load split dns, cache tuning, web ui & dnscrypt relays
          root.forwardRulesPath = cfg.forwarding_rules_path || cfg.forward_rules_path || ""
          root.tlsKeyLogFile = cfg.tls_key_log_file || ""
          root.loadAdaptiveTimeoutEnabled = (cfg.timeout_load_reduction !== undefined) ? (cfg.timeout_load_reduction > 0) : true
          root.negMinTtl = cfg.cache_neg_min_ttl !== undefined ? String(cfg.cache_neg_min_ttl) : "60"
          root.negMaxTtl = cfg.cache_neg_max_ttl !== undefined ? String(cfg.cache_neg_max_ttl) : "600"
          root.webUiEnabled = !!cfg.web_ui
          root.webUiAddr = cfg.web_ui_addr || "127.0.0.1:0205"
          root.webUiUser = cfg.web_ui_user || ""
          root.webUiPassword = cfg.web_ui_pass || cfg.web_ui_password || ""
          root.dnscryptRelays = (cfg.dnscrypt_relays && Array.isArray(cfg.dnscrypt_relays)) ? cfg.dnscrypt_relays.join(",") : ""
          root.dnscryptServers = (cfg.dnscrypt_servers && Array.isArray(cfg.dnscrypt_servers)) ? cfg.dnscrypt_servers.join(",") : ""

          if (cfg.ports && Array.isArray(cfg.ports)) root.storedPorts = cfg.ports
          if (cfg.restore_after_bytes !== undefined) root.storedRestoreAfterBytes = cfg.restore_after_bytes
          if (cfg.restore_mss !== undefined) root.storedRestoreMss = cfg.restore_mss
          if (cfg.cgroup_path) root.storedCgroup = cfg.cgroup_path
          if (cfg.fake_seq_offset !== undefined) root.storedFakeSeqOffset = cfg.fake_seq_offset
          if (cfg.min_ttl !== undefined) root.storedMinTtl = cfg.min_ttl
          if (cfg.max_ttl !== undefined) root.storedMaxTtl = cfg.max_ttl
          if (cfg.allow_domains && Array.isArray(cfg.allow_domains)) root.storedAllowDomains = cfg.allow_domains
          if (cfg.allowlist_path) root.storedAllowlistPath = cfg.allowlist_path

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
      root.activeStartTime = 0
      root.refreshStatus()
      root.refreshUptime()
      root.loadConfig()
      if (root.lastDaemonAction === "restart") {
        root.showToast("Service restarted")
      }
      root.lastDaemonAction = ""
    }
  }

  Process {
    id: terminalProc
    command: ["xdg-terminal-exec", "albus", "monitor"]
    running: false
  }

  Process {
    id: browserProc
    command: ["xdg-open", "http://" + (root.webUiAddr.trim() || "127.0.0.1:0205")]
    running: false
  }

  Process {
    id: updateResolversProc
    command: ["albus", "resolvers", "update"]
    running: false
    onExited: function(code) {
      if (code === 0) {
        root.showToast("Resolver lists updated and verified")
      } else {
        root.showToast("Failed to update resolver lists")
      }
    }
  }

  Process {
    id: copyProc
    command: []
    running: false
  }

  // journalctl event stream collector
  Process {
    id: streamProc
    command: ["journalctl", "-u", "albus.service", "-n", "200", "-f", "--no-pager", "-o", "cat"]
    running: root.opened
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
      onCloseRequested: {
        if (root.selectedLogIndex !== -1) {
          root.selectedLogIndex = -1
        } else {
          root.close()
        }
      }
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
                height: Math.max(albusTitle.implicitHeight, statusPill.height)

                Text {
                  id: albusTitle
                  text: "ALBUS"
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                  font.bold: true
                  color: root.foreground
                  anchors.verticalCenter: parent.verticalCenter
                }

                Rectangle {
                  id: statusPill
                  anchors.verticalCenter: parent.verticalCenter
                  height: Style.space(18)
                  width: statusRow.implicitWidth + Style.space(10)
                  radius: Style.cornerRadius
                  color: root.isRunning ? Qt.rgba(0.06, 0.72, 0.51, 0.12) : Qt.rgba(1, 1, 1, 0.04)
                  border.color: root.isRunning ? Qt.rgba(0.06, 0.72, 0.51, 0.28) : Qt.rgba(1, 1, 1, 0.08)
                  border.width: 1

                  Row {
                    id: statusRow
                    anchors.centerIn: parent
                    spacing: Style.space(4)

                    Rectangle {
                      width: 5
                      height: 5
                      radius: 2.5
                      color: root.isRunning ? "#10B981" : root.dim
                      anchors.verticalCenter: parent.verticalCenter
                    }

                    Text {
                      id: statusText
                      text: root.isRunning ? "ACTIVE" : "STANDBY"
                      font.family: "monospace"
                      font.pixelSize: Style.font.caption - 2
                      font.bold: true
                      color: root.isRunning ? "#10B981" : root.dim
                      anchors.verticalCenter: parent.verticalCenter
                    }
                  }
                }
              }

              Text {
                width: parent.width
                text: root.isBusy
                  ? "Applying rules..."
                  : (root.isRunning
                      ? ((root.serviceUptime !== "" ? ("Uptime " + root.serviceUptime + " · ") : "") + "eBPF sock_ops · ML-KEM-768 · " + (root.ramOnlyEnabled ? "RAM-Only" : "Persistent"))
                      : "Engine is offline")
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
                  color: isSelected ? Qt.rgba(1, 1, 1, 0.12) : (mainTabMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.05) : "transparent")
                  border.color: isSelected ? Qt.rgba(1, 1, 1, 0.20) : "transparent"
                  border.width: isSelected ? 1 : 0

                  Behavior on color { ColorAnimation { duration: 90 } }
                  Behavior on border.color { ColorAnimation { duration: 90 } }

                  MouseArea {
                    id: mainTabMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.activeTab = modelData.index
                  }

                  Row {
                    anchors.centerIn: parent
                    spacing: Style.space(5)

                    Text {
                      text: modelData.label
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption - 1
                      font.bold: mainTabPill.isSelected
                      color: mainTabPill.isSelected ? root.foreground : root.dim
                      textFormat: Text.PlainText
                      anchors.verticalCenter: parent.verticalCenter
                    }

                    Rectangle {
                      visible: modelData.index === 1 && root.isRunning
                      width: 5
                      height: 5
                      radius: 2.5
                      color: "#10B981"
                      anchors.verticalCenter: parent.verticalCenter
                    }
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
                subtitle: root.activeDnsLabel + (root.activeDnsKey.indexOf("mullvad") !== -1 ? " · " + root.mullvadProfile : "") + (root.dnsRacingEnabled ? " · Racing" : "")
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
                      text: "Mullvad Filter Profile"
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
                        verticalPadding: Style.space(3)
                        horizontalPadding: Style.space(4)
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
                        verticalPadding: Style.space(3)
                        horizontalPadding: Style.space(4)
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
                        verticalPadding: Style.space(3)
                        horizontalPadding: Style.space(4)
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
                        verticalPadding: Style.space(3)
                        horizontalPadding: Style.space(4)
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
                        verticalPadding: Style.space(3)
                        horizontalPadding: Style.space(4)
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
                        verticalPadding: Style.space(3)
                        horizontalPadding: Style.space(4)
                        onClicked: {
                          root.mullvadProfile = "all"
                          root.activeDnsKey = "mullvad-all"
                          root.applyAndSave()
                        }
                      }
                    }
                  }

                  // custom endpoint parameters form
                  Column {
                    width: parent.width
                    visible: root.activeDnsKey === "custom"
                    spacing: Style.space(6)

                    // DoH URL / Stamp full width
                    ColumnLayout {
                      width: parent.width
                      spacing: Style.space(3)

                      RowLayout {
                        Layout.fillWidth: true
                        spacing: Style.space(4)

                        Text {
                          text: "Custom DoH URL or DNS Stamp"
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.caption - 1
                          font.bold: true
                          color: root.foreground
                        }

                        Text {
                          text: "HTTPS endpoint or DNSCrypt sdns stamp"
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.caption - 2
                          color: root.subtle
                          elide: Text.ElideRight
                          Layout.fillWidth: true
                        }
                      }

                      StyledTextField {
                        Layout.fillWidth: true
                        text: root.customDnsUrl
                        placeholderText: "https://doh.example.com/dns-query or sdns://..."
                        onTextEdited: {
                          root.customDnsUrl = text
                          root.scheduleAutoApply()
                        }
                      }
                    }

                    // 2-column Bootstrap IP row
                    RowLayout {
                      width: parent.width
                      spacing: Style.space(8)

                      ColumnLayout {
                        Layout.fillWidth: true
                        Layout.preferredWidth: 1
                        spacing: Style.space(3)

                        Text {
                          text: "Primary Bootstrap IP"
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.caption - 1
                          font.bold: true
                          color: root.foreground
                        }

                        StyledTextField {
                          Layout.fillWidth: true
                          text: root.customBootstrapPrimary
                          placeholderText: "45.90.28.0"
                          onTextEdited: {
                            root.customBootstrapPrimary = text
                            root.scheduleAutoApply()
                          }
                        }
                      }

                      ColumnLayout {
                        Layout.fillWidth: true
                        Layout.preferredWidth: 1
                        spacing: Style.space(3)

                        Text {
                          text: "Secondary Bootstrap IP"
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.caption - 1
                          font.bold: true
                          color: root.foreground
                        }

                        StyledTextField {
                          Layout.fillWidth: true
                          text: root.customBootstrapSecondary
                          placeholderText: "45.90.30.0"
                          onTextEdited: {
                            root.customBootstrapSecondary = text
                            root.scheduleAutoApply()
                          }
                        }
                      }
                    }
                  }

                  // Happy Eyeballs DNS Racing toggle card
                  Rectangle {
                    width: parent.width
                    implicitHeight: racingCol.implicitHeight
                    radius: Style.cornerRadius
                    color: Qt.rgba(1, 1, 1, 0.02)
                    border.color: Qt.rgba(1, 1, 1, 0.07)
                    border.width: 1
                    clip: true

                    Column {
                      id: racingCol
                      width: parent.width

                      CompactToggle {
                        label: "DNS Racing (Happy Eyeballs)"
                        description: "Race queries across top resolvers concurrently for lowest latency"
                        checked: root.dnsRacingEnabled
                        showDivider: false
                        onClicked: {
                          root.dnsRacingEnabled = !root.dnsRacingEnabled
                          root.applyAndSave()
                        }
                      }
                    }
                  }

                  // SOCKS5 & Tor Proxy Routing Card
                  Rectangle {
                    width: parent.width
                    implicitHeight: proxyCardCol.implicitHeight
                    radius: Style.cornerRadius
                    color: Qt.rgba(1, 1, 1, 0.02)
                    border.color: root.torEnabled ? Qt.rgba(0.06, 0.72, 0.51, 0.3) : Qt.rgba(1, 1, 1, 0.07)
                    border.width: 1
                    clip: true

                    Column {
                      id: proxyCardCol
                      width: parent.width

                      CompactToggle {
                        label: "Tor Onion Network Routing"
                        description: "Tunnel upstream queries through local Tor socks5://127.0.0.1:9050"
                        checked: root.torEnabled
                        showDivider: !root.torEnabled || root.socks5Proxy.trim() !== ""
                        onClicked: {
                          root.torEnabled = !root.torEnabled
                          root.applyAndSave()
                        }
                      }

                      Column {
                        visible: !root.torEnabled
                        width: parent.width
                        spacing: Style.space(3)
                        topPadding: Style.space(4)
                        bottomPadding: Style.space(8)
                        leftPadding: Style.space(12)
                        rightPadding: Style.space(12)

                        RowLayout {
                          width: parent.width - Style.space(24)
                          spacing: Style.space(4)

                          Text {
                            text: "Custom SOCKS5 Proxy"
                            font.family: root.fontFamily
                            font.pixelSize: Style.font.caption - 1
                            font.bold: true
                            color: root.foreground
                          }

                          Text {
                            text: "socks5:// or socks5h:// URL"
                            font.family: root.fontFamily
                            font.pixelSize: Style.font.caption - 2
                            color: root.subtle
                            elide: Text.ElideRight
                            Layout.fillWidth: true
                          }
                        }

                        StyledTextField {
                          width: parent.width - Style.space(24)
                          text: root.socks5Proxy
                          placeholderText: "socks5://127.0.0.1:1080"
                          onTextEdited: {
                            root.socks5Proxy = text
                            root.scheduleAutoApply()
                          }
                        }

                        Rectangle {
                          width: parent.width - Style.space(24)
                          height: 1
                          color: Qt.rgba(1, 1, 1, 0.05)
                        }

                        RowLayout {
                          width: parent.width - Style.space(24)
                          spacing: Style.space(6)

                          Text {
                            text: "Anonymized DNSCrypt Relays"
                            font.family: root.fontFamily
                            font.pixelSize: Style.font.caption - 1
                            font.bold: true
                            color: root.foreground
                          }

                          Rectangle {
                            height: 16
                            radius: 3
                            color: Qt.rgba(0.95, 0.65, 0.15, 0.15)
                            border.color: Qt.rgba(0.95, 0.65, 0.15, 0.4)
                            border.width: 1
                            implicitWidth: experimentalRelayText.implicitWidth + 8

                            Text {
                              id: experimentalRelayText
                              anchors.centerIn: parent
                              text: "Experimental - Coming Soon"
                              font.family: root.fontFamily
                              font.pixelSize: Style.font.caption - 3
                              font.bold: true
                              color: Qt.rgba(0.95, 0.65, 0.15, 0.95)
                            }
                          }

                          Item {
                            Layout.fillWidth: true
                          }
                        }

                        Text {
                          width: parent.width - Style.space(24)
                          text: "Relay stamps or names (backend under development, not active in live traffic)"
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.caption - 2
                          color: root.subtle
                          wrapMode: Text.WordWrap
                        }

                        StyledTextField {
                          width: parent.width - Style.space(24)
                          text: root.dnscryptRelays
                          placeholderText: "sdns://... (comma separated)"
                          onTextEdited: {
                            root.dnscryptRelays = text
                            root.scheduleAutoApply()
                          }
                        }
                      }
                    }
                  }

                  // Client mTLS X.509 Authentication Card
                  Rectangle {
                    width: parent.width
                    implicitHeight: mtlsCardCol.implicitHeight
                    radius: Style.cornerRadius
                    color: Qt.rgba(1, 1, 1, 0.02)
                    border.color: (root.tlsClientCert.trim() !== "" && root.tlsClientKey.trim() !== "") ? Qt.rgba(0.06, 0.72, 0.51, 0.3) : Qt.rgba(1, 1, 1, 0.07)
                    border.width: 1
                    clip: true

                    Column {
                      id: mtlsCardCol
                      width: parent.width
                      spacing: Style.space(6)
                      topPadding: Style.space(8)
                      bottomPadding: Style.space(8)
                      leftPadding: Style.space(12)
                      rightPadding: Style.space(12)

                      RowLayout {
                        width: parent.width - Style.space(24)
                        spacing: Style.space(4)

                        Text {
                          text: "Client mTLS Authentication (X.509)"
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.caption
                          font.bold: true
                          color: root.foreground
                        }

                        Text {
                          text: "For private DoH upstream"
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.caption - 2
                          color: root.subtle
                          elide: Text.ElideRight
                          Layout.fillWidth: true
                        }
                      }

                      RowLayout {
                        width: parent.width - Style.space(24)
                        spacing: Style.space(8)

                        ColumnLayout {
                          Layout.fillWidth: true
                          Layout.preferredWidth: 1
                          spacing: Style.space(3)

                          Text {
                            text: "Client Certificate"
                            font.family: root.fontFamily
                            font.pixelSize: Style.font.caption - 1
                            font.bold: true
                            color: root.foreground
                          }

                          StyledTextField {
                            Layout.fillWidth: true
                            text: root.tlsClientCert
                            placeholderText: "/etc/ssl/client.crt"
                            onTextEdited: {
                              root.tlsClientCert = text
                              root.scheduleAutoApply()
                            }
                          }
                        }

                        ColumnLayout {
                          Layout.fillWidth: true
                          Layout.preferredWidth: 1
                          spacing: Style.space(3)

                          Text {
                            text: "Client Private Key"
                            font.family: root.fontFamily
                            font.pixelSize: Style.font.caption - 1
                            font.bold: true
                            color: root.foreground
                          }

                          StyledTextField {
                            Layout.fillWidth: true
                            text: root.tlsClientKey
                            placeholderText: "/etc/ssl/client.key"
                            onTextEdited: {
                              root.tlsClientKey = text
                              root.scheduleAutoApply()
                            }
                          }
                        }
                      }
                    }
                  }

                  // Remote Resolvers Minisign Action Card
                  Rectangle {
                    width: parent.width
                    height: Style.space(32)
                    radius: Style.cornerRadius
                    color: Qt.rgba(1, 1, 1, 0.02)
                    border.color: Qt.rgba(1, 1, 1, 0.07)
                    border.width: 1

                    RowLayout {
                      anchors.fill: parent
                      anchors.leftMargin: Style.space(12)
                      anchors.rightMargin: Style.space(8)
                      spacing: Style.space(8)

                      ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 0

                        Text {
                          text: "Public Resolver Lists"
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.caption
                          font.bold: true
                          color: root.foreground
                        }

                        Text {
                          text: "Cryptographically verified with Minisign Ed25519"
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.caption - 2
                          color: root.subtle
                        }
                      }

                      Rectangle {
                        height: Style.space(22)
                        width: updateBtnText.implicitWidth + Style.space(14)
                        radius: Style.cornerRadius - 2
                        color: updateBtnMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.08) : Qt.rgba(1, 1, 1, 0.04)
                        border.color: Qt.rgba(1, 1, 1, 0.1)
                        border.width: 1

                        Text {
                          id: updateBtnText
                          anchors.centerIn: parent
                          text: "Update Lists"
                          color: root.foreground
                          font.pixelSize: Style.font.caption - 1
                          font.family: root.fontFamily
                        }

                        MouseArea {
                          id: updateBtnMouse
                          anchors.fill: parent
                          hoverEnabled: true
                          cursorShape: Qt.PointingHandCursor
                          onClicked: {
                            updateResolversProc.running = true
                            root.showToast("Updating resolver lists...")
                          }
                        }
                      }
                    }
                  }
                }
              }

              AccordionSectionHeader {
                title: "DPI EVASION"
                subtitle: ["MSS " + root.customMss, root.fakeBadChecksum ? "Desync" : "", root.blockQuicEnabled ? "No-QUIC" : ""].filter(Boolean).join(" · ")
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

                  // DPI Evasion Parameters Form
                  Column {
                    width: parent.width
                    spacing: Style.space(8)

                    // 3-column MSS & TTL row
                    RowLayout {
                      width: parent.width
                      spacing: Style.space(8)

                      ColumnLayout {
                        Layout.fillWidth: true
                        Layout.preferredWidth: 1
                        spacing: Style.space(3)

                        Text {
                          text: "TCP MSS"
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.caption - 1
                          font.bold: true
                          color: root.foreground
                        }

                        StyledTextField {
                          Layout.fillWidth: true
                          horizontalAlignment: Text.AlignHCenter
                          text: root.customMss
                          placeholderText: "1200"
                          inputMethodHints: Qt.ImhDigitsOnly
                          onTextEdited: {
                            root.customMss = text
                            root.scheduleAutoApply()
                          }
                        }
                      }

                      ColumnLayout {
                        Layout.fillWidth: true
                        Layout.preferredWidth: 1
                        spacing: Style.space(3)

                        Text {
                          text: "Min MSS (Jitter)"
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.caption - 1
                          font.bold: true
                          color: root.foreground
                        }

                        StyledTextField {
                          Layout.fillWidth: true
                          horizontalAlignment: Text.AlignHCenter
                          text: root.customMinMss
                          placeholderText: "88"
                          inputMethodHints: Qt.ImhDigitsOnly
                          onTextEdited: {
                            root.customMinMss = text
                            root.scheduleAutoApply()
                          }
                        }
                      }

                      ColumnLayout {
                        Layout.fillWidth: true
                        Layout.preferredWidth: 1
                        spacing: Style.space(3)

                        Text {
                          text: "Fake TTL (0 = Auto)"
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.caption - 1
                          font.bold: true
                          color: root.foreground
                        }

                        StyledTextField {
                          Layout.fillWidth: true
                          horizontalAlignment: Text.AlignHCenter
                          text: root.customFakeTtl
                          placeholderText: "0"
                          inputMethodHints: Qt.ImhDigitsOnly
                          onTextEdited: {
                            root.customFakeTtl = text
                            root.scheduleAutoApply()
                          }
                        }
                      }
                    }

                    // Full-width Decoy SNI domain
                    ColumnLayout {
                      width: parent.width
                      spacing: Style.space(3)

                      RowLayout {
                        Layout.fillWidth: true
                        spacing: Style.space(4)

                        Text {
                          text: "Decoy SNI Domain"
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.caption - 1
                          font.bold: true
                          color: root.foreground
                        }

                        Text {
                          text: "Injected fake hostname for SNI splitting"
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.caption - 2
                          color: root.subtle
                          elide: Text.ElideRight
                          Layout.fillWidth: true
                        }
                      }

                      StyledTextField {
                        Layout.fillWidth: true
                        text: root.customFakeSni
                        placeholderText: "Default rotating pool (e.g. www.google.com)"
                        onTextEdited: {
                          root.customFakeSni = text
                          root.scheduleAutoApply()
                        }
                      }
                    }
                  }

                  // DPI Evasion Pure Toggles Card
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
                        label: "TCP Checksum Desync"
                        description: "Invalidate TCP checksums on decoy packets to evade DPI"
                        checked: root.fakeBadChecksum
                        onClicked: {
                          root.fakeBadChecksum = !root.fakeBadChecksum
                          root.applyAndSave()
                        }
                      }

                      CompactToggle {
                        label: "Block QUIC (UDP 443)"
                        description: "Force browser HTTPS fallback to inspectable TCP"
                        checked: root.blockQuicEnabled
                        onClicked: {
                          root.blockQuicEnabled = !root.blockQuicEnabled
                          root.applyAndSave()
                        }
                      }

                      CompactToggle {
                        label: "Block WebRTC STUN"
                        description: "Prevent real IP leaks via browser WebRTC (UDP 3478/5349)"
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
                subtitle: [root.dnssecEnabled ? "DNSSEC" : "", root.pqcEnabled ? "PQC" : "", root.killSwitchEnabled ? "Kill-Switch" : "", root.networkLockdownEnabled ? "Lockdown" : ""].filter(Boolean).join(" · ")
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
                        label: "DNSSEC Validation"
                        description: "Cryptographically verify DNS records against tampering"
                        checked: root.dnssecEnabled
                        onClicked: {
                          root.dnssecEnabled = !root.dnssecEnabled
                          root.applyAndSave()
                        }
                      }

                      CompactToggle {
                        label: "Quantum-Safe Encryption (PQC)"
                        description: "Hybrid ML-KEM-768 post-quantum key exchange for DoH"
                        checked: root.pqcEnabled
                        onClicked: {
                          root.pqcEnabled = !root.pqcEnabled
                          root.applyAndSave()
                        }
                      }

                      CompactToggle {
                        label: "DNS Leak Kill-Switch"
                        description: "Block unencrypted plaintext port 53 DNS leaks"
                        checked: root.killSwitchEnabled
                        onClicked: {
                          root.killSwitchEnabled = !root.killSwitchEnabled
                          root.applyAndSave()
                        }
                      }

                      CompactToggle {
                        label: "Fail-Closed Protection"
                        description: "Block outbound web traffic if bypass engine stops unexpectedly"
                        checked: root.networkLockdownEnabled
                        onClicked: {
                          root.networkLockdownEnabled = !root.networkLockdownEnabled
                          root.applyAndSave()
                        }
                      }

                      CompactToggle {
                        label: "IPv6 Leak Prevention"
                        description: "Filter AAAA queries to avoid unbypassed IPv6 traffic leaks"
                        checked: root.blockIpv6Enabled
                        onClicked: {
                          root.blockIpv6Enabled = !root.blockIpv6Enabled
                          root.applyAndSave()
                        }
                      }

                      CompactToggle {
                        label: "Ephemeral RAM-Only Storage"
                        description: "Store state in RAM; reset all configuration upon reboot"
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
                subtitle: [root.blocklistEnabled ? "Blocklist" : "", root.antiRebindingEnabled ? "Shield" : "", root.odohEnabled ? "ODoH" : "", root.localDohEnabled ? "Local DoH" : ""].filter(Boolean).join(" · ")
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
                        description: "Accept standard DNS queries locally over TCP"
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
                        showDivider: !root.localDohEnabled
                        onClicked: {
                          root.localDohEnabled = !root.localDohEnabled
                          root.applyAndSave()
                        }
                      }

                      Column {
                        visible: root.localDohEnabled
                        width: parent.width
                        spacing: Style.space(3)
                        topPadding: Style.space(4)
                        bottomPadding: Style.space(8)
                        leftPadding: Style.space(12)
                        rightPadding: Style.space(12)

                        RowLayout {
                          width: parent.width - Style.space(24)
                          spacing: Style.space(4)

                          Text {
                            text: "Local DoH Listen Address"
                            font.family: root.fontFamily
                            font.pixelSize: Style.font.caption - 1
                            font.bold: true
                            color: root.foreground
                          }

                          Text {
                            text: "Binding host and port"
                            font.family: root.fontFamily
                            font.pixelSize: Style.font.caption - 2
                            color: root.subtle
                            elide: Text.ElideRight
                            Layout.fillWidth: true
                          }
                        }

                        StyledTextField {
                          width: parent.width - Style.space(24)
                          text: root.localDohAddr
                          placeholderText: "127.0.0.1:8053"
                          onTextEdited: {
                            root.localDohAddr = text
                            root.scheduleAutoApply()
                          }
                        }
                      }

                      Rectangle {
                        visible: root.localDohEnabled
                        width: parent.width - Style.space(24)
                        x: Style.space(12)
                        height: 1
                        color: Qt.rgba(1, 1, 1, 0.05)
                      }

                      CompactToggle {
                        label: "Network Interface Monitor"
                        description: "Automatically adapt routing on network interface changes"
                        checked: root.netmonEnabled
                        showDivider: true
                        onClicked: {
                          root.netmonEnabled = !root.netmonEnabled
                          root.applyAndSave()
                        }
                      }

                      CompactToggle {
                        label: "Prometheus Metrics Endpoint (/metrics)"
                        description: "Expose OpenMetrics telemetries on local HTTP server"
                        checked: root.metricsEnabled
                        showDivider: !root.metricsEnabled
                        onClicked: {
                          root.metricsEnabled = !root.metricsEnabled
                          root.applyAndSave()
                        }
                      }

                      Column {
                        visible: root.metricsEnabled
                        width: parent.width
                        spacing: Style.space(3)
                        topPadding: Style.space(4)
                        bottomPadding: Style.space(8)
                        leftPadding: Style.space(12)
                        rightPadding: Style.space(12)

                        RowLayout {
                          width: parent.width - Style.space(24)
                          spacing: Style.space(4)

                          Text {
                            text: "Metrics Listen Address"
                            font.family: root.fontFamily
                            font.pixelSize: Style.font.caption - 1
                            font.bold: true
                            color: root.foreground
                          }

                          Text {
                            text: "Binding host and port"
                            font.family: root.fontFamily
                            font.pixelSize: Style.font.caption - 2
                            color: root.subtle
                            elide: Text.ElideRight
                            Layout.fillWidth: true
                          }
                        }

                        StyledTextField {
                          width: parent.width - Style.space(24)
                          text: root.metricsAddr
                          placeholderText: "127.0.0.1:9153"
                          onTextEdited: {
                            root.metricsAddr = text
                            root.scheduleAutoApply()
                          }
                        }
                      }

                      Rectangle {
                        width: parent.width - Style.space(24)
                        x: Style.space(12)
                        height: 1
                        color: Qt.rgba(1, 1, 1, 0.05)
                      }

                      CompactToggle {
                        label: "Web Monitoring Dashboard"
                        description: "Embedded zero-dependency HTTP dashboard and live telemetry"
                        checked: root.webUiEnabled
                        showDivider: !root.webUiEnabled
                        onClicked: {
                          root.webUiEnabled = !root.webUiEnabled
                          root.applyAndSave()
                        }
                      }

                      Column {
                        visible: root.webUiEnabled
                        width: parent.width
                        spacing: Style.space(4)
                        topPadding: Style.space(4)
                        bottomPadding: Style.space(8)
                        leftPadding: Style.space(12)
                        rightPadding: Style.space(12)

                        RowLayout {
                          width: parent.width - Style.space(24)
                          spacing: Style.space(4)

                          Text {
                            text: "Dashboard Listen Address"
                            font.family: root.fontFamily
                            font.pixelSize: Style.font.caption - 1
                            font.bold: true
                            color: root.foreground
                          }

                          Text {
                            text: "HTTP bind address"
                            font.family: root.fontFamily
                            font.pixelSize: Style.font.caption - 2
                            color: root.subtle
                            elide: Text.ElideRight
                            Layout.fillWidth: true
                          }
                        }

                        StyledTextField {
                          width: parent.width - Style.space(24)
                          text: root.webUiAddr
                          placeholderText: "127.0.0.1:0205"
                          onTextEdited: {
                            root.webUiAddr = text
                            root.scheduleAutoApply()
                          }
                        }

                        RowLayout {
                          width: parent.width - Style.space(24)
                          spacing: Style.space(8)

                          ColumnLayout {
                            Layout.fillWidth: true
                            Layout.preferredWidth: 1
                            spacing: Style.space(2)

                            Text {
                              text: "Auth Username"
                              font.family: root.fontFamily
                              font.pixelSize: Style.font.caption - 2
                              color: root.dim
                            }

                            StyledTextField {
                              Layout.fillWidth: true
                              text: root.webUiUser
                              placeholderText: "admin (optional)"
                              onTextEdited: {
                                root.webUiUser = text
                                root.scheduleAutoApply()
                              }
                            }
                          }

                          ColumnLayout {
                            Layout.fillWidth: true
                            Layout.preferredWidth: 1
                            spacing: Style.space(2)

                            Text {
                              text: "Auth Password"
                              font.family: root.fontFamily
                              font.pixelSize: Style.font.caption - 2
                              color: root.dim
                            }

                            StyledTextField {
                              Layout.fillWidth: true
                              text: root.webUiPassword
                              placeholderText: "password (optional)"
                              echoMode: TextInput.Password
                              onTextEdited: {
                                root.webUiPassword = text
                                root.scheduleAutoApply()
                              }
                            }
                          }
                        }

                        Rectangle {
                          height: Style.space(22)
                          width: openWebUiText.implicitWidth + Style.space(16)
                          radius: Style.cornerRadius - 2
                          color: openWebUiMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.10) : Qt.rgba(1, 1, 1, 0.04)
                          border.color: Qt.rgba(1, 1, 1, 0.15)
                          border.width: 1

                          Text {
                            id: openWebUiText
                            anchors.centerIn: parent
                            text: "Open Web Dashboard"
                            color: root.foreground
                            font.pixelSize: Style.font.caption - 1
                            font.family: root.fontFamily
                          }

                          MouseArea {
                            id: openWebUiMouse
                            anchors.fill: parent
                            hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor
                            onClicked: {
                              browserProc.command = ["xdg-open", "http://" + (root.webUiAddr.trim() || "127.0.0.1:0205")]
                              browserProc.running = true
                            }
                          }
                        }
                      }
                    }
                  }

                  // Oblivious DoH (RFC 9230) Relay Card
                  Rectangle {
                    width: parent.width
                    implicitHeight: odohCardCol.implicitHeight
                    radius: Style.cornerRadius
                    color: Qt.rgba(1, 1, 1, 0.02)
                    border.color: root.odohEnabled ? Qt.rgba(0.06, 0.72, 0.51, 0.3) : Qt.rgba(1, 1, 1, 0.07)
                    border.width: 1
                    clip: true

                    Column {
                      id: odohCardCol
                      width: parent.width

                      CompactToggle {
                        label: "Oblivious DoH (RFC 9230)"
                        description: "Hide client IP from DNS resolver via proxy relay"
                        checked: root.odohEnabled
                        showDivider: root.odohEnabled
                        onClicked: {
                          root.odohEnabled = !root.odohEnabled
                          root.applyAndSave()
                        }
                      }

                      Column {
                        visible: root.odohEnabled
                        width: parent.width
                        spacing: Style.space(6)
                        topPadding: Style.space(6)
                        bottomPadding: Style.space(4)
                        leftPadding: Style.space(12)
                        rightPadding: Style.space(12)

                        ColumnLayout {
                          width: parent.width - Style.space(24)
                          spacing: Style.space(3)

                          RowLayout {
                            Layout.fillWidth: true
                            spacing: Style.space(4)

                            Text {
                              text: "ODoH Relay Proxy URL"
                              font.family: root.fontFamily
                              font.pixelSize: Style.font.caption - 1
                              font.bold: true
                              color: root.foreground
                            }

                            Text {
                              text: "Intermediary relay proxy endpoint"
                              font.family: root.fontFamily
                              font.pixelSize: Style.font.caption - 2
                              color: root.subtle
                              elide: Text.ElideRight
                              Layout.fillWidth: true
                            }
                          }

                          StyledTextField {
                            Layout.fillWidth: true
                            text: root.odohRelay
                            placeholderText: "https://odoh.cloudflare-dns.com/dns-query"
                            onTextEdited: {
                              root.odohRelay = text
                              root.scheduleAutoApply()
                            }
                          }
                        }

                        ColumnLayout {
                          width: parent.width - Style.space(24)
                          spacing: Style.space(3)

                          RowLayout {
                            Layout.fillWidth: true
                            spacing: Style.space(4)

                            Text {
                              text: "ODoH Target Resolver URL"
                              font.family: root.fontFamily
                              font.pixelSize: Style.font.caption - 1
                              font.bold: true
                              color: root.foreground
                            }

                            Text {
                              text: "Final target resolver endpoint"
                              font.family: root.fontFamily
                              font.pixelSize: Style.font.caption - 2
                              color: root.subtle
                              elide: Text.ElideRight
                              Layout.fillWidth: true
                            }
                          }

                          StyledTextField {
                            Layout.fillWidth: true
                            text: root.odohTarget
                            placeholderText: "https://odoh.cloudflare-dns.com/dns-query"
                            onTextEdited: {
                              root.odohTarget = text
                              root.scheduleAutoApply()
                            }
                          }
                        }
                      }

                      Row {
                        visible: root.odohEnabled
                        spacing: Style.space(6)
                        topPadding: Style.space(4)
                        bottomPadding: Style.space(8)
                        leftPadding: Style.space(12)
                        rightPadding: Style.space(12)

                        Rectangle {
                          height: Style.space(22)
                          width: presetBtnText.implicitWidth + Style.space(12)
                          radius: Style.cornerRadius - 2
                          color: presetBtnMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.08) : Qt.rgba(1, 1, 1, 0.04)
                          border.color: Qt.rgba(1, 1, 1, 0.1)
                          border.width: 1

                          Text {
                            id: presetBtnText
                            anchors.centerIn: parent
                            text: "Fill Cloudflare Preset"
                            color: root.foreground
                            font.pixelSize: Style.font.caption - 1
                            font.family: root.fontFamily
                          }

                          MouseArea {
                            id: presetBtnMouse
                            anchors.fill: parent
                            hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor
                            onClicked: {
                              root.odohRelay = "https://odoh.cloudflare-dns.com/dns-query"
                              root.odohTarget = "https://odoh.cloudflare-dns.com/dns-query"
                              root.applyAndSave()
                            }
                          }
                        }

                        Rectangle {
                          height: Style.space(22)
                          width: clearBtnText.implicitWidth + Style.space(12)
                          radius: Style.cornerRadius - 2
                          color: clearBtnMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.08) : Qt.rgba(1, 1, 1, 0.04)
                          border.color: Qt.rgba(1, 1, 1, 0.1)
                          border.width: 1

                          Text {
                            id: clearBtnText
                            anchors.centerIn: parent
                            text: "Reset Defaults"
                            color: root.dim
                            font.pixelSize: Style.font.caption - 1
                            font.family: root.fontFamily
                          }

                          MouseArea {
                            id: clearBtnMouse
                            anchors.fill: parent
                            hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor
                            onClicked: {
                              root.odohRelay = ""
                              root.odohTarget = ""
                              root.applyAndSave()
                            }
                          }
                        }
                      }
                    }
                  }

                  // Split DNS Forwarding Card
                  Rectangle {
                    width: parent.width
                    implicitHeight: forwardCardCol.implicitHeight
                    radius: Style.cornerRadius
                    color: Qt.rgba(1, 1, 1, 0.02)
                    border.color: root.forwardRulesPath.trim() !== "" ? Qt.rgba(0.06, 0.72, 0.51, 0.3) : Qt.rgba(1, 1, 1, 0.07)
                    border.width: 1
                    clip: true

                    Column {
                      id: forwardCardCol
                      width: parent.width
                      spacing: Style.space(4)
                      topPadding: Style.space(8)
                      bottomPadding: Style.space(8)
                      leftPadding: Style.space(12)
                      rightPadding: Style.space(12)

                      RowLayout {
                        width: parent.width - Style.space(24)
                        spacing: Style.space(4)

                        Text {
                          text: "Split DNS Domain Forwarding"
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.caption - 1
                          font.bold: true
                          color: root.foreground
                        }

                        Text {
                          text: "Forward rules path"
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.caption - 2
                          color: root.subtle
                          elide: Text.ElideRight
                          Layout.fillWidth: true
                        }
                      }

                      Text {
                        width: parent.width - Style.space(24)
                        text: "Route internal domains to specific resolvers (example: company.lan 192.168.1.1:53)"
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption - 2
                        color: root.dim
                        wrapMode: Text.WordWrap
                      }

                      StyledTextField {
                        width: parent.width - Style.space(24)
                        text: root.forwardRulesPath
                        placeholderText: "/etc/albus/forwarding-rules.txt"
                        onTextEdited: {
                          root.forwardRulesPath = text
                          root.scheduleAutoApply()
                        }
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
                        label: "DNS Query Audit Log"
                        description: "Write DNS queries to a local rotating log file"
                        checked: root.queryLogEnabled
                        showDivider: !root.queryLogEnabled
                        onClicked: {
                          root.queryLogEnabled = !root.queryLogEnabled
                          root.applyAndSave()
                        }
                      }

                      Column {
                        visible: root.queryLogEnabled
                        width: parent.width
                        spacing: Style.space(6)
                        topPadding: Style.space(4)
                        bottomPadding: Style.space(8)
                        leftPadding: Style.space(12)
                        rightPadding: Style.space(12)

                        ColumnLayout {
                          width: parent.width - Style.space(24)
                          spacing: Style.space(3)

                          RowLayout {
                            Layout.fillWidth: true
                            spacing: Style.space(4)

                            Text {
                              text: "Query Log Output Path"
                              font.family: root.fontFamily
                              font.pixelSize: Style.font.caption - 1
                              font.bold: true
                              color: root.foreground
                            }

                            Text {
                              text: "Destination file path"
                              font.family: root.fontFamily
                              font.pixelSize: Style.font.caption - 2
                              color: root.subtle
                              elide: Text.ElideRight
                              Layout.fillWidth: true
                            }
                          }

                          StyledTextField {
                            Layout.fillWidth: true
                            text: root.queryLogPath
                            placeholderText: "/var/log/albus/query.log"
                            onTextEdited: {
                              root.queryLogPath = text
                              root.scheduleAutoApply()
                            }
                          }
                        }

                        ColumnLayout {
                          width: parent.width - Style.space(24)
                          spacing: Style.space(3)

                          RowLayout {
                            Layout.fillWidth: true
                            spacing: Style.space(4)

                            Text {
                              text: "IPcrypt Client IP Key"
                              font.family: root.fontFamily
                              font.pixelSize: Style.font.caption - 1
                              font.bold: true
                              color: root.foreground
                            }

                            Text {
                              text: "32-hex key or passphrase"
                              font.family: root.fontFamily
                              font.pixelSize: Style.font.caption - 2
                              color: root.subtle
                              elide: Text.ElideRight
                              Layout.fillWidth: true
                            }
                          }

                          StyledTextField {
                            Layout.fillWidth: true
                            text: root.ipcryptKey
                            placeholderText: "1234567890abcdef..."
                            onTextEdited: {
                              root.ipcryptKey = text
                              root.scheduleAutoApply()
                            }
                          }
                        }
                      }

                      Rectangle {
                        width: parent.width - Style.space(24)
                        x: Style.space(12)
                        height: 1
                        color: Qt.rgba(1, 1, 1, 0.05)
                      }

                      CompactToggle {
                        label: "NXDomain Security Audit Log"
                        description: "Track nonexistent domain queries to detect botnet and DGA malware"
                        checked: root.nxLogEnabled
                        showDivider: !root.nxLogEnabled
                        onClicked: {
                          root.nxLogEnabled = !root.nxLogEnabled
                          root.applyAndSave()
                        }
                      }

                      Column {
                        visible: root.nxLogEnabled
                        width: parent.width
                        spacing: Style.space(3)
                        topPadding: Style.space(4)
                        bottomPadding: Style.space(8)
                        leftPadding: Style.space(12)
                        rightPadding: Style.space(12)

                        RowLayout {
                          width: parent.width - Style.space(24)
                          spacing: Style.space(4)

                          Text {
                            text: "NXDomain Log Output Path"
                            font.family: root.fontFamily
                            font.pixelSize: Style.font.caption - 1
                            font.bold: true
                            color: root.foreground
                          }

                          Text {
                            text: "Destination file path"
                            font.family: root.fontFamily
                            font.pixelSize: Style.font.caption - 2
                            color: root.subtle
                            elide: Text.ElideRight
                            Layout.fillWidth: true
                          }
                        }

                        StyledTextField {
                          width: parent.width - Style.space(24)
                          text: root.nxLogPath
                          placeholderText: "/var/log/albus/nx.log"
                          onTextEdited: {
                            root.nxLogPath = text
                            root.scheduleAutoApply()
                          }
                        }
                      }

                      Rectangle {
                        width: parent.width - Style.space(24)
                        x: Style.space(12)
                        height: 1
                        color: Qt.rgba(1, 1, 1, 0.05)
                      }

                      CompactToggle {
                        label: "EDNS0 Request Padding"
                        description: "Pad query sizes to prevent traffic size analysis"
                        checked: root.ednsPaddingEnabled
                        showDivider: true
                        onClicked: {
                          root.ednsPaddingEnabled = !root.ednsPaddingEnabled
                          root.applyAndSave()
                        }
                      }

                      Column {
                        width: parent.width
                        spacing: Style.space(3)
                        topPadding: Style.space(4)
                        bottomPadding: Style.space(8)
                        leftPadding: Style.space(12)
                        rightPadding: Style.space(12)

                        RowLayout {
                          width: parent.width - Style.space(24)
                          spacing: Style.space(4)

                          Text {
                            text: "EDNS Client Subnet (RFC 7871)"
                            font.family: root.fontFamily
                            font.pixelSize: Style.font.caption - 1
                            font.bold: true
                            color: root.foreground
                          }

                          Text {
                            text: "Prefix CIDR or 0.0.0.0/0 for zero-scope"
                            font.family: root.fontFamily
                            font.pixelSize: Style.font.caption - 2
                            color: root.subtle
                            elide: Text.ElideRight
                            Layout.fillWidth: true
                          }
                        }

                        StyledTextField {
                          width: parent.width - Style.space(24)
                          text: root.ednsClientSubnet
                          placeholderText: "0.0.0.0/0 or 198.51.100.0/24"
                          onTextEdited: {
                            root.ednsClientSubnet = text
                            root.scheduleAutoApply()
                          }
                        }
                      }

                      Rectangle {
                        width: parent.width - Style.space(24)
                        x: Style.space(12)
                        height: 1
                        color: Qt.rgba(1, 1, 1, 0.05)
                      }

                      Column {
                        width: parent.width
                        spacing: Style.space(3)
                        topPadding: Style.space(4)
                        bottomPadding: Style.space(8)
                        leftPadding: Style.space(12)
                        rightPadding: Style.space(12)

                        RowLayout {
                          width: parent.width - Style.space(24)
                          spacing: Style.space(4)

                          Text {
                            text: "TLS Master Keylog (Wireshark/NSS)"
                            font.family: root.fontFamily
                            font.pixelSize: Style.font.caption - 1
                            font.bold: true
                            color: root.foreground
                          }

                          Text {
                            text: "Export secrets path"
                            font.family: root.fontFamily
                            font.pixelSize: Style.font.caption - 2
                            color: root.subtle
                            elide: Text.ElideRight
                            Layout.fillWidth: true
                          }
                        }

                        StyledTextField {
                          width: parent.width - Style.space(24)
                          text: root.tlsKeyLogFile
                          placeholderText: "/tmp/sslkeylog.log (or SSLKEYLOGFILE)"
                          onTextEdited: {
                            root.tlsKeyLogFile = text
                            root.scheduleAutoApply()
                          }
                        }
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
                        label: "Threat & Ad Blocklist"
                        description: "In-memory HaGeZi Multi PRO + TIF Bloom filter"
                        checked: root.blocklistEnabled
                        onClicked: {
                          root.blocklistEnabled = !root.blocklistEnabled
                          root.applyAndSave()
                        }
                      }

                      CompactToggle {
                        label: "Anti-DNS Rebinding Shield"
                        description: "Block responses resolving to private LAN IP addresses"
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
                        description: "Inspect canonical alias targets against blocklist"
                        checked: root.uncloakCnamesEnabled
                        onClicked: {
                          root.uncloakCnamesEnabled = !root.uncloakCnamesEnabled
                          root.applyAndSave()
                        }
                      }

                      CompactToggle {
                        label: "Block Undelegated Domains"
                        description: "Sinkhole .local, .lan, and dotless query names"
                        checked: root.blockUndelegatedEnabled
                        onClicked: {
                          root.blockUndelegatedEnabled = !root.blockUndelegatedEnabled
                          root.applyAndSave()
                        }
                      }

                      CompactToggle {
                        label: "DNS64 IPv6 Synthesis"
                        description: "Synthesize IPv6 addresses for IPv4-only hosts"
                        checked: root.dns64Enabled
                        showDivider: true
                        onClicked: {
                          root.dns64Enabled = !root.dns64Enabled
                          root.applyAndSave()
                        }
                      }

                      CompactToggle {
                        label: "Load-Adaptive Query Timeout"
                        description: "Dynamically scale resolver timeout curve under high query concurrency"
                        checked: root.loadAdaptiveTimeoutEnabled
                        showDivider: true
                        onClicked: {
                          root.loadAdaptiveTimeoutEnabled = !root.loadAdaptiveTimeoutEnabled
                          root.applyAndSave()
                        }
                      }

                      Column {
                        width: parent.width
                        spacing: Style.space(3)
                        topPadding: Style.space(4)
                        bottomPadding: Style.space(8)
                        leftPadding: Style.space(12)
                        rightPadding: Style.space(12)

                        RowLayout {
                          width: parent.width - Style.space(24)
                          spacing: Style.space(4)

                          Text {
                            text: "Negative Cache TTL Clamping (Seconds)"
                            font.family: root.fontFamily
                            font.pixelSize: Style.font.caption - 1
                            font.bold: true
                            color: root.foreground
                          }

                          Text {
                            text: "Min and Max SOA TTL"
                            font.family: root.fontFamily
                            font.pixelSize: Style.font.caption - 2
                            color: root.subtle
                            elide: Text.ElideRight
                            Layout.fillWidth: true
                          }
                        }

                        RowLayout {
                          width: parent.width - Style.space(24)
                          spacing: Style.space(8)

                          ColumnLayout {
                            Layout.fillWidth: true
                            Layout.preferredWidth: 1
                            spacing: Style.space(2)

                            Text {
                              text: "Min TTL (e.g. 60)"
                              font.family: root.fontFamily
                              font.pixelSize: Style.font.caption - 2
                              color: root.dim
                            }

                            StyledTextField {
                              Layout.fillWidth: true
                              text: root.negMinTtl
                              placeholderText: "60"
                              onTextEdited: {
                                root.negMinTtl = text
                                root.scheduleAutoApply()
                              }
                            }
                          }

                          ColumnLayout {
                            Layout.fillWidth: true
                            Layout.preferredWidth: 1
                            spacing: Style.space(2)

                            Text {
                              text: "Max TTL (e.g. 600)"
                              font.family: root.fontFamily
                              font.pixelSize: Style.font.caption - 2
                              color: root.dim
                            }

                            StyledTextField {
                              Layout.fillWidth: true
                              text: root.negMaxTtl
                              placeholderText: "600"
                              onTextEdited: {
                                root.negMaxTtl = text
                                root.scheduleAutoApply()
                              }
                            }
                          }
                        }
                      }
                    }
                  }
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

              // search input
              Item {
                width: parent.width
                implicitHeight: searchField.implicitHeight

                TextField {
                  id: searchField
                  width: parent.width
                  placeholderText: "Search domain (e.g. discord, chatgpt)..."
                  text: root.streamSearchQuery
                  font.pixelSize: Style.font.caption
                  onTextChanged: {
                    root.streamSearchQuery = text
                    root.updateDisplayEvents()
                  }
                }

                Rectangle {
                  id: clearSearchBtn
                  visible: root.streamSearchQuery.length > 0
                  anchors.right: parent.right
                  anchors.rightMargin: Style.space(8)
                  anchors.verticalCenter: parent.verticalCenter
                  width: Style.space(18)
                  height: Style.space(18)
                  radius: Style.cornerRadius
                  color: clearSearchMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.12) : Qt.rgba(1, 1, 1, 0.04)

                  MouseArea {
                    id: clearSearchMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: {
                      searchField.text = ""
                    }
                  }

                  Text {
                    anchors.centerIn: parent
                    text: "✕"
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption - 2
                    color: root.dim
                  }
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

                  Button {
                    text: "Error"
                    selected: root.streamFilter === "ERROR"
                    bordered: true
                    fontSize: Style.font.caption - 1
                    horizontalPadding: Style.space(6)
                    verticalPadding: Style.space(2)
                    onClicked: root.setFilter("ERROR")
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
                        radius: 2.5
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
                height: Style.space(370)
                color: Style.normalFillFor(root.foreground, root.accent)
                borderSpec: Border.controlSpec("normal", root.foreground, root.accent)
                radius: Style.cornerRadius
                clip: true

                ListView {
                  id: streamListView
                  reuseItems: true
                  anchors.fill: parent
                  anchors.leftMargin: Style.space(6)
                  anchors.rightMargin: Style.space(6)
                  anchors.topMargin: Style.space(6)
                  anchors.bottomMargin: logInspector.visible ? Style.space(38) : Style.space(6)
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
                    readonly property bool isSelected: root.selectedLogIndex === index
                    color: isCopied
                      ? Qt.rgba(0.06, 0.72, 0.5, 0.16)
                      : (isSelected
                          ? Qt.rgba(1, 1, 1, 0.08)
                          : (eventMouse.containsMouse ? Style.hoverFillFor(root.foreground, modelData.badgeColor) : "transparent"))
                    border.color: isSelected ? Qt.rgba(1, 1, 1, 0.25) : "transparent"
                    border.width: isSelected ? 1 : 0

                    Behavior on color { ColorAnimation { duration: 90 } }
                    Behavior on border.color { ColorAnimation { duration: 90 } }

                    MouseArea {
                      id: eventMouse
                      anchors.fill: parent
                      hoverEnabled: true
                      cursorShape: Qt.PointingHandCursor
                      onClicked: {
                        root.copyToClipboard(modelData.title + (modelData.tag ? " " + modelData.tag : ""))
                        root.copiedEventId = index
                        copiedFeedbackTimer.restart()
                        root.selectedLogIndex = (root.selectedLogIndex === index ? -1 : index)
                      }
                    }

                    RowLayout {
                      anchors.fill: parent
                      anchors.leftMargin: Style.space(6)
                      anchors.rightMargin: Style.space(6)
                      spacing: Style.space(8)

                      // 1. Sleek category micro badge pill
                      Rectangle {
                        Layout.preferredWidth: Style.space(48)
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
                        Layout.maximumWidth: Style.space(130)
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
                        Layout.preferredWidth: Style.space(52)
                        horizontalAlignment: Text.AlignRight
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
                      : (root.streamFilter !== "ALL"
                          ? ("No recent " + root.streamFilter + " events in buffer")
                          : (root.isRunning ? "Listening for real-time DPI flows..." : "Service is offline. Start Albus to stream flows."))
                    textFormat: Text.PlainText
                    color: root.dim
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                  }
                }

                // Raw event inspector strip (appears when a log item is selected)
                Rectangle {
                  id: logInspector
                  visible: root.selectedLogIndex >= 0 && root.selectedLogIndex < root.displayEvents.length
                  anchors.bottom: parent.bottom
                  anchors.left: parent.left
                  anchors.right: parent.right
                  anchors.margins: Style.space(6)
                  height: Style.space(28)
                  color: Qt.rgba(0.06, 0.06, 0.08, 0.96)
                  border.color: Qt.rgba(1, 1, 1, 0.18)
                  border.width: 1
                  radius: Style.cornerRadius
                  z: 15

                  RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: Style.space(8)
                    anchors.rightMargin: Style.space(8)
                    spacing: Style.space(6)

                    Rectangle {
                      Layout.preferredWidth: Style.space(34)
                      implicitHeight: Style.space(18)
                      radius: Style.cornerRadius
                      color: Qt.rgba(0.22, 0.74, 0.97, 0.15)
                      border.color: Qt.rgba(0.22, 0.74, 0.97, 0.35)
                      border.width: 1
                      Layout.alignment: Qt.AlignVCenter

                      Text {
                        anchors.centerIn: parent
                        text: "RAW"
                        font.family: "monospace"
                        font.pixelSize: Style.font.caption - 2
                        font.bold: true
                        color: "#38BDF8"
                      }
                    }

                    Text {
                      Layout.fillWidth: true
                      text: (root.selectedLogIndex >= 0 && root.selectedLogIndex < root.displayEvents.length)
                        ? root.displayEvents[root.selectedLogIndex].raw
                        : ""
                      font.family: "monospace"
                      font.pixelSize: Style.font.caption - 2
                      color: root.foreground
                      elide: Text.ElideMiddle
                      textFormat: Text.PlainText
                      Layout.alignment: Qt.AlignVCenter
                    }

                    Rectangle {
                      height: Style.space(18)
                      width: copyRawText.implicitWidth + Style.space(10)
                      radius: Style.cornerRadius - 2
                      color: copyRawMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.14) : Qt.rgba(1, 1, 1, 0.06)
                      border.color: Qt.rgba(1, 1, 1, 0.12)
                      border.width: 1
                      Layout.alignment: Qt.AlignVCenter

                      MouseArea {
                        id: copyRawMouse
                        anchors.fill: parent
                        hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor
                        onClicked: {
                          if (root.selectedLogIndex >= 0 && root.selectedLogIndex < root.displayEvents.length) {
                            root.copyToClipboard(root.displayEvents[root.selectedLogIndex].raw)
                          }
                        }
                      }

                      Text {
                        id: copyRawText
                        anchors.centerIn: parent
                        text: "Copy"
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption - 2
                        font.bold: true
                        color: root.foreground
                      }
                    }

                    Rectangle {
                      height: Style.space(18)
                      width: Style.space(18)
                      radius: Style.cornerRadius - 2
                      color: closeInspMouse.containsMouse ? Qt.rgba(1, 1, 1, 0.14) : "transparent"
                      Layout.alignment: Qt.AlignVCenter

                      MouseArea {
                        id: closeInspMouse
                        anchors.fill: parent
                        hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor
                        onClicked: {
                          root.selectedLogIndex = -1
                        }
                      }

                      Text {
                        anchors.centerIn: parent
                        text: "✕"
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption - 2
                        color: root.dim
                      }
                    }
                  }
                }

                // Floating Jump to latest button when user scrolls up
                Rectangle {
                  id: jumpBtn
                  visible: !root.isAtBottom && root.displayEvents.length > 0
                  anchors.bottom: parent.bottom
                  anchors.right: parent.right
                  anchors.bottomMargin: logInspector.visible ? Style.space(42) : Style.space(8)
                  anchors.rightMargin: Style.space(10)
                  width: jumpText.implicitWidth + Style.space(16)
                  height: Style.space(22)
                  radius: Style.cornerRadius
                  color: jumpMouse.containsMouse ? Qt.rgba(0.12, 0.12, 0.16, 0.96) : Qt.rgba(0.06, 0.06, 0.08, 0.90)
                  border.color: jumpMouse.containsMouse ? "#38BDF8" : Qt.rgba(1, 1, 1, 0.16)
                  border.width: 1
                  z: 10

                  Behavior on color { ColorAnimation { duration: 90 } }
                  Behavior on border.color { ColorAnimation { duration: 90 } }

                  MouseArea {
                    id: jumpMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: {
                      streamListView.positionViewAtEnd()
                      root.isAtBottom = true
                    }
                  }

                  Text {
                    id: jumpText
                    anchors.centerIn: parent
                    text: "↓ Latest"
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
              text: "1-2 tabs · space toggle"
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption - 1
              color: root.dim
            }

            Text {
              id: rightHint
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              text: "p pause · j/k scroll · esc close"
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
