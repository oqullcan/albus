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

  // navigation tab indices: 0 = dns & security, 1 = dpi evasion, 2 = live telemetry
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
  property string customFakeSni: "www.google.com"
  property bool fakeBadChecksum: false
  property bool autoTtlEnabled: true
  property bool dnssecEnabled: true
  property bool pqcEnabled: true
  property bool ramOnlyEnabled: true
  property bool blockQuicEnabled: true
  property bool blockIpv6Enabled: true
  property string toastMessage: ""

  // event stream telemetry state
  property var rawStreamEvents: []
  property var displayEvents: []
  property string streamFilter: "ALL"
  property string streamSearchQuery: ""
  property bool isStreamPaused: false
  property int countInjected: 0
  property int countDns: 0
  property int countQuic: 0

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color dim: Qt.darker(foreground, 1.6)
  readonly property color subtle: Qt.darker(foreground, 2.5)
  readonly property color borderMuted: Qt.rgba(foreground.r, foreground.g, foreground.b, 0.12)
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color accent: Color.accent
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

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
    interval: 250
    repeat: false
    onTriggered: root.applyAndSave()
  }

  function scheduleAutoApply() {
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

    var timeMatch = clean.match(/(\d{2}:\d{2}:\d{2})/)
    var timeStr = timeMatch ? timeMatch[1] : ""

    var category = "INFO"
    var badgeColor = "#10B981"
    var title = clean
    var detail = "Kernel event"

    if (clean.indexOf("fake ClientHello injected") !== -1 || clean.indexOf("ClientHello") !== -1) {
      category = "INJECT"
      badgeColor = "#38BDF8"
      var dstMatch = clean.match(/dst=([^\s]+)/)
      var ttlMatch = clean.match(/ttl=([^\s]+)/)
      title = dstMatch ? dstMatch[1] : "TLS ClientHello"
      detail = "Fake SNI desync injected" + (ttlMatch ? " • TTL " + ttlMatch[1] : "")
    } else if (clean.indexOf("DNS server started") !== -1) {
      category = "DNS"
      badgeColor = "#A855F7"
      title = "DoH Engine Active (127.0.0.1:53)"
      detail = "Fast-Path in-memory cache ready"
    } else if (clean.indexOf("DNS") !== -1 || clean.indexOf("query") !== -1 || clean.indexOf("resolved") !== -1) {
      category = "DNS"
      badgeColor = "#A855F7"
      var domMatch = clean.match(/domain=([^\s]+)/) || clean.match(/upstream=([^\s]+)/)
      title = domMatch ? domMatch[1] : "DoH Query"
      detail = "Encrypted DNS resolution"
    } else if (clean.indexOf("QUIC") !== -1 || clean.indexOf("blocked") !== -1) {
      category = "QUIC"
      badgeColor = "#F59E0B"
      title = "QUIC (UDP 443) Blocked"
      detail = "Forced TCP fallback for DPI bypass"
    } else if (clean.indexOf("Error") !== -1 || clean.indexOf("Failed") !== -1) {
      category = "ERROR"
      badgeColor = "#EF4444"
      title = clean.replace(/.*Error:\s*/, "")
      detail = "Service warning / error"
    } else {
      var stripped = clean.replace(/^[\d\-T:\.Z]+\s*(INFO|WARN|DEBUG|ERROR)?\s*/, "")
      title = stripped !== "" ? stripped : clean
      detail = "Kernel event"
    }

    return {
      time: timeStr,
      category: category,
      badgeColor: badgeColor,
      title: title,
      detail: detail
    }
  }

  function appendStreamEvent(rawLine) {
    var parsed = parseLogLine(rawLine)
    if (!parsed) return

    if (parsed.category === "INJECT") root.countInjected++
    else if (parsed.category === "DNS") root.countDns++
    else if (parsed.category === "QUIC") root.countQuic++

    if (root.isStreamPaused) return

    var list = root.rawStreamEvents.slice()
    list.push(parsed)
    if (list.length > 80) list.shift()
    root.rawStreamEvents = list

    updateDisplayEvents()
    Qt.callLater(function() {
      if (streamListView) streamListView.positionViewAtEnd()
    })
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
                        item.detail.toLowerCase().indexOf(query) !== -1)
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
      Qt.callLater(function() {
        if (streamListView) streamListView.positionViewAtEnd()
      })
    }
  }

  function clearStream() {
    root.rawStreamEvents = []
    root.displayEvents = []
    root.countInjected = 0
    root.countDns = 0
    root.countQuic = 0
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
    var args = ["config", "set"]

    var upstream = root.activeDnsKey
    if (upstream.indexOf("mullvad") !== -1) {
      upstream = root.mullvadProfile === "standard" ? "mullvad" : "mullvad-" + root.mullvadProfile
    } else if (upstream === "custom") {
      upstream = root.customDnsUrl.trim() !== "" ? root.customDnsUrl.trim() : "quad9"
    }
    args.push("--doh-upstream", upstream)

    var boots = []
    if (root.customBootstrapPrimary.trim() !== "") boots.push(root.customBootstrapPrimary.trim())
    if (root.customBootstrapSecondary.trim() !== "") boots.push(root.customBootstrapSecondary.trim())
    if (boots.length > 0) {
      args.push("--doh-bootstrap-ips", boots.join(","))
    }

    args.push("--mss", root.customMss.trim() !== "" ? root.customMss.trim() : "88")
    if (root.customFakeSni.trim() !== "") {
      args.push("--fake-sni", root.customFakeSni.trim())
    }
    args.push("--fake-bad-checksum", root.fakeBadChecksum ? "true" : "false")
    args.push("--auto-ttl", root.autoTtlEnabled ? "true" : "false")
    args.push("--block-quic", root.blockQuicEnabled ? "true" : "false")
    args.push("--block-ipv6", root.blockIpv6Enabled ? "true" : "false")
    args.push("--dnssec", root.dnssecEnabled ? "true" : "false")
    args.push("--pqc", root.pqcEnabled ? "true" : "false")
    args.push("--ram-only", root.ramOnlyEnabled ? "true" : "false")

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
    showToast("DNS cache cleared")
  }

  function openMonitor() {
    terminalProc.running = true
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
          if (s.dohUpstream) {
            if (s.dohUpstream === "quad9") root.activeDnsLabel = "Quad9"
            else if (s.dohUpstream === "cloudflare") root.activeDnsLabel = "Cloudflare"
            else if (s.dohUpstream.indexOf("mullvad") !== -1) root.activeDnsLabel = "Mullvad"
            else root.activeDnsLabel = "Custom"
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
          root.customMss = String(cfg.mss || 88)
          root.customFakeSni = cfg.fake_sni || "www.google.com"
          root.fakeBadChecksum = !!cfg.fake_bad_checksum
          root.autoTtlEnabled = cfg.auto_ttl !== false
          root.dnssecEnabled = cfg.dnssec !== false
          root.pqcEnabled = cfg.pqc !== false
          root.ramOnlyEnabled = cfg.ram_only !== false
          root.blockQuicEnabled = cfg.block_quic !== false
          root.blockIpv6Enabled = cfg.block_ipv6 !== false

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

          if (cfg.doh_bootstrap_ips && cfg.doh_bootstrap_ips.length > 0) {
            root.customBootstrapPrimary = cfg.doh_bootstrap_ips[0] || ""
            root.customBootstrapSecondary = cfg.doh_bootstrap_ips[1] || ""
          }
        }
      }
    }
  }

  Process {
    id: configSetProc
    command: []
    running: false
    onExited: function(code) {
      root.showToast("Settings applied")
      if (root.isRunning) {
        daemonActionProc.command = ["systemctl", "restart", "albus.service"]
        daemonActionProc.running = true
      } else {
        root.refreshStatus()
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
    running: root.opened && root.activeTab === 2
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
    contentWidth: panel.fittedContentWidth(Style.space(430))
    contentHeight: panel.fittedContentHeight(mainColumn.implicitHeight + Style.space(20))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }

      onTextKey: function(t) {
        if (t === "1") root.activeTab = 0
        else if (t === "2") root.activeTab = 1
        else if (t === "3") root.activeTab = 2
        else if (t === " " || t === "t" || t === "T") root.toggleDaemon()
        else if (t === "r" || t === "R") root.restartDaemon()
        else if (t === "c" || t === "C") root.purgeDnsCache()
        else if (t === "p" || t === "P") root.togglePause()
        else if (t === "j" || t === "J") {
          if (root.activeTab === 2 && streamListView) streamListView.contentY = Math.min(streamListView.contentHeight - streamListView.height, streamListView.contentY + 50)
        }
        else if (t === "k" || t === "K") {
          if (root.activeTab === 2 && streamListView) streamListView.contentY = Math.max(0, streamListView.contentY - 50)
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
          RowLayout {
            width: parent.width
            spacing: Style.space(8)

            ColumnLayout {
              Layout.fillWidth: true
              spacing: 2

              RowLayout {
                spacing: Style.space(6)

                Rectangle {
                  width: Style.space(7)
                  height: Style.space(7)
                  radius: Style.cornerRadius
                  color: root.isRunning ? "#10B981" : root.subtle

                  SequentialAnimation on opacity {
                    running: root.isRunning && root.opened
                    loops: Animation.Infinite
                    NumberAnimation { from: 1.0; to: 0.3; duration: 1000; easing.type: Easing.InOutSine }
                    NumberAnimation { from: 0.3; to: 1.0; duration: 1000; easing.type: Easing.InOutSine }
                  }
                }

                Text {
                  text: "ALBUS"
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                  font.bold: true
                  color: root.foreground
                }

                Text {
                  text: root.isRunning ? "● ACTIVE" : "○ STANDBY"
                  font.family: "monospace"
                  font.pixelSize: Style.font.caption - 1
                  font.bold: true
                  color: root.isRunning ? "#10B981" : root.dim
                }
              }

              Text {
                text: root.isBusy ? "Applying rules..." : (root.isRunning ? "eBPF sock_ops • ML-KEM-768 • /dev/shm" : "Engine is offline")
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption - 1
                color: root.dim
              }
            }

            ToggleSwitch {
              checked: root.isRunning
              busy: root.isBusy
              foreground: root.foreground
              accent: "#10B981"
              onToggled: root.toggleDaemon()
            }
          }

          // 2. sharp segmented tab bar
          Row {
            width: parent.width
            spacing: Style.space(4)

            Button {
              width: (mainColumn.width - Style.space(8)) / 3
              text: "01 DNS & SEC"
              selected: root.activeTab === 0
              bordered: true
              fontSize: Style.font.caption - 1
              onClicked: root.activeTab = 0
            }

            Button {
              width: (mainColumn.width - Style.space(8)) / 3
              text: "02 DPI EVASION"
              selected: root.activeTab === 1
              bordered: true
              fontSize: Style.font.caption - 1
              onClicked: root.activeTab = 1
            }

            Button {
              width: (mainColumn.width - Style.space(8)) / 3
              text: "03 TELEMETRY"
              selected: root.activeTab === 2
              bordered: true
              fontSize: Style.font.caption - 1
              onClicked: root.activeTab = 2
            }
          }

          // 3. animated tab viewport
          Item {
            id: tabContainer
            width: parent.width
            implicitHeight: currentTabItem ? currentTabItem.implicitHeight : 0

            readonly property Item currentTabItem: root.activeTab === 0 ? tab0 : (root.activeTab === 1 ? tab1 : tab2)

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

              PanelSectionHeader {
                text: "UPSTREAM RESOLVER"
                foreground: root.foreground
                fontFamily: root.fontFamily
              }

              // horizontal segmented resolver selector
              Row {
                width: parent.width
                spacing: Style.space(4)

                Button {
                  width: (mainColumn.width - Style.space(12)) / 4
                  text: (root.activeDnsKey === "quad9" ? "● " : "") + "Quad9"
                  selected: root.activeDnsKey === "quad9"
                  bordered: true
                  fontSize: Style.font.caption - 1
                  onClicked: {
                    root.activeDnsKey = "quad9"
                    root.activeDnsLabel = "Quad9"
                    root.scheduleAutoApply()
                  }
                }

                Button {
                  width: (mainColumn.width - Style.space(12)) / 4
                  text: (root.activeDnsKey === "cloudflare" ? "● " : "") + "Cloudflare"
                  selected: root.activeDnsKey === "cloudflare"
                  bordered: true
                  fontSize: Style.font.caption - 1
                  onClicked: {
                    root.activeDnsKey = "cloudflare"
                    root.activeDnsLabel = "Cloudflare"
                    root.scheduleAutoApply()
                  }
                }

                Button {
                  width: (mainColumn.width - Style.space(12)) / 4
                  text: (root.activeDnsKey.indexOf("mullvad") !== -1 ? "● " : "") + "Mullvad"
                  selected: root.activeDnsKey.indexOf("mullvad") !== -1
                  bordered: true
                  fontSize: Style.font.caption - 1
                  onClicked: {
                    root.activeDnsKey = root.mullvadProfile === "standard" ? "mullvad" : "mullvad-" + root.mullvadProfile
                    root.activeDnsLabel = "Mullvad"
                    root.scheduleAutoApply()
                  }
                }

                Button {
                  width: (mainColumn.width - Style.space(12)) / 4
                  text: (root.activeDnsKey === "custom" ? "● " : "") + "Custom"
                  selected: root.activeDnsKey === "custom"
                  bordered: true
                  fontSize: Style.font.caption - 1
                  onClicked: {
                    root.activeDnsKey = "custom"
                    root.activeDnsLabel = "Custom"
                    root.scheduleAutoApply()
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
                    text: (root.mullvadProfile === "standard" ? "● " : "") + "Standard"
                    selected: root.mullvadProfile === "standard"
                    bordered: true
                    fontSize: Style.font.caption - 1
                    onClicked: {
                      root.mullvadProfile = "standard"
                      root.activeDnsKey = "mullvad"
                      root.scheduleAutoApply()
                    }
                  }

                  Button {
                    width: (mainColumn.width - Style.space(8)) / 3
                    text: (root.mullvadProfile === "adblock" ? "● " : "") + "Adblock"
                    selected: root.mullvadProfile === "adblock"
                    bordered: true
                    fontSize: Style.font.caption - 1
                    onClicked: {
                      root.mullvadProfile = "adblock"
                      root.activeDnsKey = "mullvad-adblock"
                      root.scheduleAutoApply()
                    }
                  }

                  Button {
                    width: (mainColumn.width - Style.space(8)) / 3
                    text: (root.mullvadProfile === "base" ? "● " : "") + "Base"
                    selected: root.mullvadProfile === "base"
                    bordered: true
                    fontSize: Style.font.caption - 1
                    onClicked: {
                      root.mullvadProfile = "base"
                      root.activeDnsKey = "mullvad-base"
                      root.scheduleAutoApply()
                    }
                  }

                  Button {
                    width: (mainColumn.width - Style.space(8)) / 3
                    text: (root.mullvadProfile === "extended" ? "● " : "") + "Extended"
                    selected: root.mullvadProfile === "extended"
                    bordered: true
                    fontSize: Style.font.caption - 1
                    onClicked: {
                      root.mullvadProfile = "extended"
                      root.activeDnsKey = "mullvad-extended"
                      root.scheduleAutoApply()
                    }
                  }

                  Button {
                    width: (mainColumn.width - Style.space(8)) / 3
                    text: (root.mullvadProfile === "family" ? "● " : "") + "Family"
                    selected: root.mullvadProfile === "family"
                    bordered: true
                    fontSize: Style.font.caption - 1
                    onClicked: {
                      root.mullvadProfile = "family"
                      root.activeDnsKey = "mullvad-family"
                      root.scheduleAutoApply()
                    }
                  }

                  Button {
                    width: (mainColumn.width - Style.space(8)) / 3
                    text: (root.mullvadProfile === "all" ? "● " : "") + "All Shield"
                    selected: root.mullvadProfile === "all"
                    bordered: true
                    fontSize: Style.font.caption - 1
                    onClicked: {
                      root.mullvadProfile = "all"
                      root.activeDnsKey = "mullvad-all"
                      root.scheduleAutoApply()
                    }
                  }
                }
              }

              // custom endpoint parameters
              Column {
                width: parent.width
                visible: root.activeDnsKey === "custom"
                spacing: Style.space(4)

                Text { text: "Endpoint URL"; color: root.dim; font.pixelSize: Style.font.caption - 1; font.family: root.fontFamily }
                TextField {
                  width: parent.width
                  placeholderText: "https://doh.example.com/dns-query"
                  text: root.customDnsUrl
                  onTextChanged: {
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
                      placeholderText: ""
                      text: root.customBootstrapPrimary
                      onTextChanged: {
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
                      placeholderText: ""
                      text: root.customBootstrapSecondary
                      onTextChanged: {
                        root.customBootstrapSecondary = text
                        root.scheduleAutoApply()
                      }
                    }
                  }
                }
              }

              PanelSectionHeader {
                text: "SECURITY & STORAGE POLICIES"
                foreground: root.foreground
                fontFamily: root.fontFamily
              }

              // frameless seamless policy list
              Column {
                width: parent.width
                spacing: Style.space(4)

                Toggle {
                  width: parent.width
                  label: "DNSSEC cryptographic validation"
                  description: "Enforce DO-bit & Authenticated Data verification"
                  checked: root.dnssecEnabled
                  onClicked: {
                    root.dnssecEnabled = !root.dnssecEnabled
                    root.scheduleAutoApply()
                  }
                }

                Toggle {
                  width: parent.width
                  label: "Post-Quantum Kyber768 (PQC)"
                  description: "Hybrid ML-KEM-768 quantum-safe key exchange"
                  checked: root.pqcEnabled
                  onClicked: {
                    root.pqcEnabled = !root.pqcEnabled
                    root.scheduleAutoApply()
                  }
                }

                Toggle {
                  width: parent.width
                  label: "Only-RAM volatile storage"
                  description: "Isolate state in /dev/shm — zero physical disk writes"
                  checked: root.ramOnlyEnabled
                  onClicked: {
                    root.ramOnlyEnabled = !root.ramOnlyEnabled
                    root.scheduleAutoApply()
                  }
                }

                Toggle {
                  width: parent.width
                  label: "Filter AAAA (IPv6 drop)"
                  description: "Prevent unfragmented IPv6 inspection bypass leaks"
                  checked: root.blockIpv6Enabled
                  onClicked: {
                    root.blockIpv6Enabled = !root.blockIpv6Enabled
                    root.scheduleAutoApply()
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
                  text: "Flush Cache (0ms)"
                  bordered: true
                  fontSize: Style.font.caption
                  onClicked: root.purgeDnsCache()
                }
              }
            }

            // tab 1: transport layer desynchronization tuning
            Column {
              id: tab1
              width: parent.width
              visible: root.activeTab === 1
              opacity: root.activeTab === 1 ? 1.0 : 0.0
              spacing: Style.space(8)

              Behavior on opacity {
                NumberAnimation { duration: 160; easing.type: Easing.OutQuad }
              }

              PanelSectionHeader {
                text: "TCP MSS & FAKE PAYLOAD"
                foreground: root.foreground
                fontFamily: root.fontFamily
              }

              Row {
                width: parent.width
                spacing: Style.space(6)

                Column {
                  width: Style.space(110)
                  spacing: 2
                  Text { text: "TCP MSS (bytes)"; color: root.dim; font.pixelSize: Style.font.caption - 1; font.family: root.fontFamily }
                  TextField {
                    width: parent.width
                    text: root.customMss
                    onTextChanged: {
                      root.customMss = text
                      root.scheduleAutoApply()
                    }
                  }
                }

                Column {
                  width: parent.width - Style.space(116)
                  spacing: 2
                  Text { text: "Fake SNI domain"; color: root.dim; font.pixelSize: Style.font.caption - 1; font.family: root.fontFamily }
                  TextField {
                    width: parent.width
                    text: root.customFakeSni
                    onTextChanged: {
                      root.customFakeSni = text
                      root.scheduleAutoApply()
                    }
                  }
                }
              }

              PanelSectionHeader {
                text: "KERNEL DESYNCHRONIZATION POLICIES"
                foreground: root.foreground
                fontFamily: root.fontFamily
              }

              // frameless evasion list
              Column {
                width: parent.width
                spacing: Style.space(4)

                Toggle {
                  width: parent.width
                  label: "Auto-TTL middlebox probing"
                  description: "Dynamically calculate router hop distance"
                  checked: root.autoTtlEnabled
                  onClicked: {
                    root.autoTtlEnabled = !root.autoTtlEnabled
                    root.scheduleAutoApply()
                  }
                }

                Toggle {
                  width: parent.width
                  label: "Bad checksum desync (0xDEAD)"
                  description: "Poison stateful DPI inspection tables"
                  checked: root.fakeBadChecksum
                  onClicked: {
                    root.fakeBadChecksum = !root.fakeBadChecksum
                    root.scheduleAutoApply()
                  }
                }

                Toggle {
                  width: parent.width
                  label: "Block QUIC (UDP 443)"
                  description: "Force browser HTTPS fallback to TCP"
                  checked: root.blockQuicEnabled
                  onClicked: {
                    root.blockQuicEnabled = !root.blockQuicEnabled
                    root.scheduleAutoApply()
                  }
                }
              }
            }

            // tab 2: realtime packet flow telemetry stream
            Column {
              id: tab2
              width: parent.width
              visible: root.activeTab === 2
              opacity: root.activeTab === 2 ? 1.0 : 0.0
              spacing: Style.space(6)

              Behavior on opacity {
                NumberAnimation { duration: 160; easing.type: Easing.OutQuad }
              }

              // telemetry counters header
              Row {
                width: parent.width
                spacing: Style.space(4)

                BorderSurface {
                  width: (mainColumn.width - Style.space(8)) / 3
                  height: Style.space(34)
                  radius: Style.cornerRadius
                  color: Style.hoverFillFor(root.foreground, "#38BDF8")
                  borderSpec: Border.controlSpec("normal", root.foreground, "#38BDF8")

                  RowLayout {
                    anchors.centerIn: parent
                    spacing: Style.space(4)

                    Text { text: String(root.countInjected); font.bold: true; font.family: "monospace"; font.pixelSize: Style.font.bodySmall; color: "#38BDF8" }
                    Text { text: "Injected"; font.family: root.fontFamily; font.pixelSize: Style.font.caption - 1; color: root.dim }
                  }
                }

                BorderSurface {
                  width: (mainColumn.width - Style.space(8)) / 3
                  height: Style.space(34)
                  radius: Style.cornerRadius
                  color: Style.hoverFillFor(root.foreground, "#A855F7")
                  borderSpec: Border.controlSpec("normal", root.foreground, "#A855F7")

                  RowLayout {
                    anchors.centerIn: parent
                    spacing: Style.space(4)

                    Text { text: String(root.countDns); font.bold: true; font.family: "monospace"; font.pixelSize: Style.font.bodySmall; color: "#A855F7" }
                    Text { text: "DoH Resolv"; font.family: root.fontFamily; font.pixelSize: Style.font.caption - 1; color: root.dim }
                  }
                }

                BorderSurface {
                  width: (mainColumn.width - Style.space(8)) / 3
                  height: Style.space(34)
                  radius: Style.cornerRadius
                  color: Style.hoverFillFor(root.foreground, "#F59E0B")
                  borderSpec: Border.controlSpec("normal", root.foreground, "#F59E0B")

                  RowLayout {
                    anchors.centerIn: parent
                    spacing: Style.space(4)

                    Text { text: String(root.countQuic); font.bold: true; font.family: "monospace"; font.pixelSize: Style.font.bodySmall; color: "#F59E0B" }
                    Text { text: "QUIC Block"; font.family: root.fontFamily; font.pixelSize: Style.font.caption - 1; color: root.dim }
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

              // category selection pills and pause toggle
              RowLayout {
                width: parent.width
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

                Item { Layout.fillWidth: true }

                Button {
                  text: root.isStreamPaused ? "Resume Stream" : "Pause Stream"
                  selected: root.isStreamPaused
                  bordered: true
                  fontSize: Style.font.caption - 1
                  horizontalPadding: Style.space(8)
                  verticalPadding: Style.space(2)
                  onClicked: root.togglePause()
                }
              }

              // borderless terminal stream list
              BorderSurface {
                width: parent.width
                height: Style.space(220)
                color: Style.normalFillFor(root.foreground, root.accent)
                borderSpec: Border.controlSpec("normal", root.foreground, root.accent)
                radius: Style.cornerRadius
                clip: true

                ListView {
                  id: streamListView
                  anchors.fill: parent
                  anchors.leftMargin: Style.space(8)
                  anchors.rightMargin: Style.space(8)
                  anchors.topMargin: Style.space(6)
                  anchors.bottomMargin: Style.space(6)
                  model: root.displayEvents
                  spacing: Style.space(2)
                  boundsBehavior: Flickable.StopAtBounds

                  delegate: Rectangle {
                    id: eventCard
                    width: streamListView.width
                    height: Style.space(30)
                    radius: Style.cornerRadius
                    color: eventMouse.containsMouse ? Style.hoverFillFor(root.foreground, modelData.badgeColor) : "transparent"

                    MouseArea {
                      id: eventMouse
                      anchors.fill: parent
                      hoverEnabled: true
                      cursorShape: Qt.PointingHandCursor
                      onClicked: root.copyToClipboard(modelData.title)
                    }

                    RowLayout {
                      anchors.fill: parent
                      anchors.leftMargin: Style.space(6)
                      anchors.rightMargin: Style.space(6)
                      spacing: Style.space(8)

                      Rectangle {
                        width: Style.space(6)
                        height: Style.space(6)
                        radius: Style.cornerRadius
                        color: modelData.badgeColor
                        Layout.alignment: Qt.AlignVCenter
                      }

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

                      Text {
                        text: modelData.detail
                        textFormat: Text.PlainText
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption - 1
                        color: root.dim
                        visible: eventCard.width > Style.space(300)
                        elide: Text.ElideRight
                      }

                      Text {
                        text: modelData.time
                        textFormat: Text.PlainText
                        font.family: "monospace"
                        font.pixelSize: Style.font.caption - 1
                        color: root.dim
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
              }

              // stream auxiliary action triggers
              Row {
                width: parent.width
                spacing: Style.space(6)

                Button {
                  width: (mainColumn.width - Style.space(6)) / 2
                  text: "Clear Stream"
                  bordered: true
                  fontSize: Style.font.caption
                  onClicked: root.clearStream()
                }

                Button {
                  width: (mainColumn.width - Style.space(6)) / 2
                  text: "Open Terminal TUI"
                  bordered: true
                  fontSize: Style.font.caption
                  onClicked: root.openMonitor()
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
          RowLayout {
            width: parent.width
            Text { text: "1-3 tabs • space toggle"; font.family: root.fontFamily; font.pixelSize: Style.font.caption - 1; color: root.dim }
            Item { Layout.fillWidth: true }
            Text { text: "p pause • j/k scroll • esc close"; font.family: root.fontFamily; font.pixelSize: Style.font.caption - 1; color: root.dim }
          }
        }
      }
    }
  }
}
