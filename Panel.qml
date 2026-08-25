import QtQuick
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui
import "Model.js" as Model

// albus anti-dpi disciplined, authentic omarchy dashboard with hotkeys, clean telemetry and zero design departure
Panel {
  id: root
  moduleName: "io.github.oqullcan.albus.dev"
  manageIpc: false

  // injected bar and host references
  property var anchorItem: null
  property var hostWidget: null

  // navigation state with smooth tab transition
  property int activeTab: 0 // 0: Overview, 1: Routing & DNS, 2: Streams, 3: Settings

  // reactive runtime states
  property bool isRunning: false
  property bool isBusy: false
  property bool isDiagnosing: false
  property var diagnosticReport: null
  property string currentMode: "auto"
  property string currentDns: "quad9"
  property string activeDns: "Quad9"
  property int dnsLatency: 0
  property string customDnsUrl: ""
  property string customBootstrapPrimary: ""
  property string customBootstrapSecondary: ""
  property string customWhitelist: ""
  property bool autostartEnabled: false
  property bool notificationsEnabled: false
  property string profileStatus: ""
  property string purgeStatus: ""
  property string repairStatus: ""
  property string customDnsApplyStatus: ""
  property bool coreReady: true
  property string setupStatus: ""
  property string latestReleaseVersion: "v1.0.0"
  property int totalConns: 0
  property int tlsCount: 0
  property int httpCount: 0
  property string protectedDataStr: "0 B"
  property bool onBattery: false
  property var activityHistory: []
  property var streamEvents: []
  property var notifiedTargets: ({})

  readonly property color foregroundColor: root.bar && root.bar.barForeground !== undefined ? root.bar.barForeground : Color.foreground
  readonly property color dimColor: Qt.darker(root.foregroundColor, 1.4)
  readonly property color accentColor: root.bar && root.bar.urgent !== undefined ? root.bar.urgent : Color.accent
  readonly property string panelFont: root.bar ? root.bar.fontFamily : Style.font.family
  readonly property string daemonScriptPath: Quickshell.env("HOME") + "/.local/bin/albusdev"



  function alpha(c, a) {
    return Qt.rgba(c.r, c.g, c.b, a)
  }

  Component.onCompleted: {
    root.loadConfig()
    root.refreshStatus()
    checkCoreProcess.running = true
  }


  Timer {
    id: statusTimer
    interval: root.onBattery ? 2500 : 1000
    running: true
    repeat: true
    onTriggered: if (!root.isBusy && !root.isDiagnosing && !actionProcess.running) root.refreshStatus()

  }

  function open() {
    root.controller.show()
    root.loadConfig()
    root.refreshStatus()
  }

  function close() {
    root.controller.hide()
  }

  function toggle() {
    if (root.opened) {
      root.close()
    } else {
      root.open()
    }
  }

  function switchPanel(direction) {
    if (root.bar && typeof root.bar.switchPanelFrom === "function") {
      return root.bar.switchPanelFrom(root.hostWidget || root, direction)
    }
    return false
  }

  function loadConfig() {
    if (!configProcess.running) {
      configProcess.command = [root.daemonScriptPath, "get-config"]
      configProcess.running = true
    }
  }

  function saveConfig() {
    saveProcess.running = false
    saveProcess.command = [
      root.daemonScriptPath,
      "save-config",
      root.currentMode,
      root.currentDns,
      root.customDnsUrl,
      root.customBootstrapPrimary,
      root.customBootstrapSecondary,
      root.customWhitelist,
      root.autostartEnabled ? "true" : "false",
      root.notificationsEnabled ? "true" : "false"
    ]
    saveProcess.running = true
  }

  function toggleAutostart() {
    root.autostartEnabled = !root.autostartEnabled
    root.saveConfig()
    var p = Qt.createQmlObject('import Quickshell.Io; Process { running: false; command: [] }', root)
    p.command = [root.daemonScriptPath, "set-autostart", root.autostartEnabled ? "true" : "false"]
    p.running = true
  }

  function toggleNotifications() {
    root.notificationsEnabled = !root.notificationsEnabled
    root.saveConfig()
  }

  function purgeCache() {
    var p = Qt.createQmlObject('import Quickshell.Io; Process { running: false; command: [] }', root)
    p.command = [root.daemonScriptPath, "purge-cache"]
    p.running = true
    root.purgeStatus = "PURGED"
    purgeTimer.restart()
  }

  Timer {
    id: purgeTimer
    interval: 2200
    onTriggered: root.purgeStatus = ""
  }

  Process {
    id: repairProcess
    running: false
    command: []
    stdout: StdioCollector { id: repairCollector; waitForEnd: true }
    onExited: function(exitCode) {
      root.isBusy = false
      root.repairStatus = exitCode === 0 ? "REPAIRED" : "FAILED"
      root.isRunning = false
      root.refreshStatus()
      repairTimer.restart()
    }
  }

  function repairNetwork() {
    root.repairStatus = "REPAIRING..."
    root.isBusy = true
    repairProcess.command = [root.daemonScriptPath, "fix-network"]
    repairProcess.running = true
  }

  Timer {
    id: repairTimer
    interval: 3500
    repeat: false
    onTriggered: root.repairStatus = ""
  }


  function exportProfile() {
    exportProcess.command = [root.daemonScriptPath, "export-profile"]
    exportProcess.running = true
  }

  Process {
    id: exportProcess
    running: false
    command: []
    stdout: StdioCollector { id: expStdout; waitForEnd: true }
    onExited: function(exitCode) {
      if (exitCode === 0) {
        var raw = String(expStdout.text || "").trim()
        try {
          var res = JSON.parse(raw)
          if (res && res.exported) {
            root.profileStatus = "Exported: " + (res.file ? res.file.split("/").pop() : "profile.json")
            profileTimer.restart()
          }
        } catch (e) {}
      }
    }
  }

  function importProfile() {
    importProcess.command = [root.daemonScriptPath, "import-profile"]
    importProcess.running = true
  }

  Process {
    id: importProcess
    running: false
    command: []
    stdout: StdioCollector { id: impStdout; waitForEnd: true }
    onExited: function(exitCode) {
      if (exitCode === 0) {
        var raw = String(impStdout.text || "").trim()
        try {
          var res = JSON.parse(raw)
          if (res && res.imported) {
            root.profileStatus = "Imported: " + (res.file ? res.file.split("/").pop() : "profile.json")
            profileTimer.restart()
            root.loadConfig()
            if (root.isRunning) root.runDaemon("start")
          }
        } catch (e) {}
      }
    }
  }

  Timer {
    id: profileTimer
    interval: 3000
    onTriggered: root.profileStatus = ""
  }

  function applyCustomDns() {
    if (customDnsInput) root.customDnsUrl = customDnsInput.text.trim()
    if (customBoot1Input) root.customBootstrapPrimary = customBoot1Input.text.trim()
    if (customBoot2Input) root.customBootstrapSecondary = customBoot2Input.text.trim()
    root.currentDns = "custom"
    root.saveConfig()
    if (root.isRunning) {
      root.runDaemon("start")
    }
    root.customDnsApplyStatus = "APPLIED"
    customDnsApplyTimer.restart()
  }

  Timer {
    id: customDnsApplyTimer
    interval: 2200
    onTriggered: root.customDnsApplyStatus = ""
  }

  Process {
    id: checkCoreProcess
    command: [root.daemonScriptPath, "check-core"]
    stdout: StdioCollector {
      onDataChanged: {
        try {
          var res = JSON.parse(value.trim())
          if (res) {
            root.coreReady = res.installed !== false
            if (res.latest_version) root.latestReleaseVersion = res.latest_version
          }
        } catch (e) {}
      }
    }
  }

  Process {
    id: setupDownloadProcess
    running: false
    command: []
    stdout: StdioCollector { id: dlCollector; waitForEnd: true }
    onExited: function(exitCode) {
      root.isBusy = false
      var raw = String(dlCollector.text || "").trim()
      try {
        var res = JSON.parse(raw)
        if (res && res.success) {
          root.setupStatus = "Core Ready (" + (res.version || "latest") + ")"
          root.coreReady = true
          root.refreshStatus()
        } else {
          root.setupStatus = (res && res.error) ? res.error : "Fetch Failed"
        }
      } catch (e) {
        root.setupStatus = exitCode === 0 ? "Core Ready" : "Fetch Failed"
      }
      setupStatusTimer.restart()
    }
  }

  Process {
    id: setupCompileProcess
    running: false
    command: []
    stdout: StdioCollector { id: compCollector; waitForEnd: true }
    onExited: function(exitCode) {
      root.isBusy = false
      var raw = String(compCollector.text || "").trim()
      try {
        var res = JSON.parse(raw)
        if (res && res.success) {
          root.setupStatus = "Compiled Successfully"
          root.coreReady = true
          root.refreshStatus()
        } else {
          root.setupStatus = (res && res.error) ? res.error : "Compile Failed"
        }
      } catch (e) {
        root.setupStatus = exitCode === 0 ? "Compiled" : "Compile Failed"
      }
      setupStatusTimer.restart()
    }
  }

  Timer {
    id: setupStatusTimer
    interval: 3500
    repeat: false
    onTriggered: root.setupStatus = ""
  }

  function fetchLatestCore() {
    root.setupStatus = "Fetching..."
    root.isBusy = true
    setupDownloadProcess.command = [root.daemonScriptPath, "setup-download"]
    setupDownloadProcess.running = true
  }

  function compileSourceCore() {
    root.setupStatus = "Compiling..."
    root.isBusy = true
    setupCompileProcess.command = [root.daemonScriptPath, "setup-compile"]
    setupCompileProcess.running = true
  }


  function runDiagnostic() {

    root.isDiagnosing = true
    diagnosticProcess.command = [root.daemonScriptPath, "diagnose"]
    diagnosticProcess.running = true
  }

  Timer {
    id: busySafetyTimer
    interval: 45000
    repeat: false
    onTriggered: {
      root.isBusy = false
      root.refreshStatus()
    }
  }

  Timer {
    id: statusSafetyDelayTimer
    interval: 350
    repeat: false
    onTriggered: root.refreshStatus()
  }

  function refreshStatus() {
    if (!statusProcess.running && !actionProcess.running) {
      statusProcess.command = [root.daemonScriptPath, "status", "--json"]
      statusProcess.running = true
    }
  }


  function runDaemon(action) {
    root.isBusy = true
    busySafetyTimer.restart()
    root.saveConfig()

    var effectiveDns = (root.currentDns === "custom" && root.customDnsUrl !== "")
      ? root.customDnsUrl
      : root.currentDns

    var bootstraps = []
    if (root.currentDns === "custom") {
      if (root.customBootstrapPrimary !== "") bootstraps.push(root.customBootstrapPrimary)
      if (root.customBootstrapSecondary !== "") bootstraps.push(root.customBootstrapSecondary)
    }
    var bootstrapArg = bootstraps.join(",")

    actionProcess.running = false
    if (action === "stop") {
      actionProcess.command = [root.daemonScriptPath, "stop"]
    } else {
      actionProcess.command = [
        root.daemonScriptPath,
        "start",
        root.currentMode,
        effectiveDns,
        bootstrapArg,
        root.customWhitelist
      ]
    }
    actionProcess.running = true
  }

  function toggleDaemon() {
    var nextState = !root.isRunning
    root.isRunning = nextState
    runDaemon(nextState ? "start" : "stop")
  }

  function applyMode(newMode) {
    root.currentMode = newMode
    root.saveConfig()
    if (root.isRunning) {
      root.runDaemon("start")
    }
  }

  function applyDns(newDns) {
    root.currentDns = newDns
    root.saveConfig()
    if (root.isRunning) {
      root.runDaemon("start")
    }
  }

  Process {
    id: configProcess
    running: false
    command: []
    stdout: StdioCollector { id: configStdout; waitForEnd: true }
    onExited: function(exitCode) {
      if (exitCode === 0) {
        var raw = String(configStdout.text || "").trim()
        var cfg = Model.parseConfig(raw)
        if (cfg) {
          if (cfg.mode !== undefined) root.currentMode = cfg.mode
          if (cfg.dns !== undefined) root.currentDns = cfg.dns
          if (cfg.custom_url !== undefined && cfg.custom_url !== "") root.customDnsUrl = cfg.custom_url
          if (cfg.custom_primary !== undefined && cfg.custom_primary !== "") root.customBootstrapPrimary = cfg.custom_primary
          if (cfg.custom_secondary !== undefined && cfg.custom_secondary !== "") root.customBootstrapSecondary = cfg.custom_secondary
          if (cfg.whitelist !== undefined) root.customWhitelist = cfg.whitelist
          if (cfg.autostart !== undefined) root.autostartEnabled = (cfg.autostart === true || cfg.autostart === "true")
          if (cfg.notifications !== undefined) root.notificationsEnabled = (cfg.notifications === true || cfg.notifications === "true")
        }
      }
    }
  }

  Process {
    id: saveProcess
    running: false
    command: []
  }

  Process {
    id: statusProcess
    running: false
    command: []
    stdout: StdioCollector { id: statusStdout; waitForEnd: true }
    onExited: function(exitCode) {
      if (exitCode === 0) {
        var raw = String(statusStdout.text || "")
        if (Model.parseStatus(raw)) {
          var s = Model.getStatus()
          root.isRunning = s.active
          root.totalConns = s.totalConnections
          root.tlsCount = s.tlsBypassed
          root.httpCount = s.httpBypassed
          root.protectedDataStr = s.bytesProtectedStr || "0 B"
          root.dnsLatency = s.latency
          root.activeDns = s.activeDns
          root.onBattery = s.onBattery || false
          root.activityHistory = s.history || []
          root.streamEvents = s.events || []
          if (sparklineCanvas) sparklineCanvas.requestPaint()

          if (root.notificationsEnabled && root.streamEvents && root.streamEvents.length > 0) {
            var latest = root.streamEvents[root.streamEvents.length - 1]
            if (latest && latest.target && !root.notifiedTargets[latest.target]) {
              root.notifiedTargets[latest.target] = true
              var notifProc = Qt.createQmlObject('import Quickshell.Io; Process { running: false; command: [] }', root)
              notifProc.command = [root.daemonScriptPath, "notify-evasion", latest.target]
              notifProc.running = true
            }
          }
        }
      }
    }
  }

  Process {
    id: diagnosticProcess
    running: false
    command: []
    stdout: StdioCollector { id: diagStdout; waitForEnd: true }
    onExited: function(exitCode) {
      root.isDiagnosing = false
      if (exitCode === 0) {
        var raw = String(diagStdout.text || "").trim()
        root.diagnosticReport = Model.parseDiagnostic(raw)
      }
    }
  }

  Process {
    id: actionProcess
    running: false
    command: []
    stdout: StdioCollector { id: actionStdout; waitForEnd: true }
    stderr: StdioCollector { id: actionStderr; waitForEnd: true }
    onExited: function(exitCode) {
      root.isBusy = false
      busySafetyTimer.stop()
      statusSafetyDelayTimer.restart()
    }

  }

  KeyboardPanel {
    id: panel
    anchorItem: root.anchorItem
    owner: root.hostWidget || root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(480))
    contentHeight: panel.fittedContentHeight(mainColumn.implicitHeight + Style.space(24))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onTextKey: function(t) {
        if (t === "1") root.activeTab = 0
        else if (t === "2") root.activeTab = 1
        else if (t === "3") root.activeTab = 2
        else if (t === "4") root.activeTab = 3
        else if (t === " " || t === "t" || t === "T") root.toggleDaemon()
      }

      Column {
        id: mainColumn
        width: parent.width - Style.space(16)
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.top: parent.top
        anchors.topMargin: Style.space(8)
        spacing: Style.space(12)

        // 1. HERO HEADER (Exact Omarchy PanelHero with Live Symmetrical Radar Indicator)
        PanelHero {
          width: parent.width
          title: "Albus Anti-DPI (DEV)"
          meta: root.isBusy
            ? "CONFIGURING KERNEL RULES"
            : (root.isRunning ? "PROTECTION ACTIVE" : "STANDBY")
          foreground: root.foregroundColor
          fontFamily: root.panelFont
          iconOpacity: 1.0
          iconComponent: Component {
            Item {
              id: iconRoot
              implicitWidth: Style.space(28)
              implicitHeight: Style.space(28)
              width: Style.space(28)
              height: Style.space(28)

              readonly property color activeColor: root.isRunning ? "#10B981" : "#EF4444"

              // Outer expanding concentric radar pulse wave
              Rectangle {
                id: wave1
                anchors.centerIn: parent
                radius: width / 2
                color: "transparent"
                border.color: iconRoot.activeColor
                border.width: 1
                visible: root.isRunning

                ParallelAnimation {
                  running: root.isRunning
                  loops: Animation.Infinite
                  NumberAnimation { target: wave1; property: "width"; from: Style.space(10); to: Style.space(26); duration: 1800; easing.type: Easing.OutQuad }
                  NumberAnimation { target: wave1; property: "height"; from: Style.space(10); to: Style.space(26); duration: 1800; easing.type: Easing.OutQuad }
                  NumberAnimation { target: wave1; property: "opacity"; from: 0.8; to: 0.0; duration: 1800; easing.type: Easing.OutQuad }
                }
              }

              // Symmetrical glowing aura
              Rectangle {
                id: glowHalo
                anchors.centerIn: parent
                width: Style.space(16)
                height: Style.space(16)
                radius: width / 2
                color: root.alpha(iconRoot.activeColor, 0.22)
                border.color: root.alpha(iconRoot.activeColor, 0.4)
                border.width: 1

                SequentialAnimation on opacity {
                  running: true
                  loops: Animation.Infinite
                  NumberAnimation { to: 0.4; duration: 1000; easing.type: Easing.InOutSine }
                  NumberAnimation { to: 1.0; duration: 1000; easing.type: Easing.InOutSine }
                }
              }

              // Symmetrical central core dot
              Rectangle {
                id: coreDot
                anchors.centerIn: parent
                width: Style.space(10)
                height: Style.space(10)
                radius: width / 2
                color: iconRoot.activeColor
              }
            }
          }
          trailingControl: Component {
            ToggleSwitch {
              checked: root.isRunning
              busy: root.isBusy
              accent: "#10B981"
              foreground: root.foregroundColor
              onToggled: root.toggleDaemon()
            }
          }
        }

        // 2. TOP TAB BAR (Segmented with Keyboard Index Hints)
        RowLayout {
          width: parent.width
          spacing: Style.space(6)

          Repeater {
            model: [
              { id: 0, label: "Overview", hint: "1" },
              { id: 1, label: "Routing & DNS", hint: "2" },
              { id: 2, label: "Streams", hint: "3" },
              { id: 3, label: "Settings", hint: "4" }
            ]
            delegate: Rectangle {
              id: tabBtn
              Layout.fillWidth: true
              height: Style.space(32)
              radius: Style.cornerRadius || 2
              color: root.activeTab === modelData.id
                ? root.alpha(root.foregroundColor, 0.16)
                : (tabMouse.containsMouse ? root.alpha(root.foregroundColor, 0.08) : "transparent")
              border.color: root.activeTab === modelData.id
                ? root.alpha(root.foregroundColor, 0.6)
                : (tabMouse.containsMouse ? root.alpha(root.foregroundColor, 0.3) : root.alpha(root.dimColor, 0.25))
              border.width: 1
              scale: tabMouse.pressed ? 0.98 : 1.0

              Behavior on color { ColorAnimation { duration: 120 } }
              Behavior on border.color { ColorAnimation { duration: 120 } }
              Behavior on scale { NumberAnimation { duration: 80; easing.type: Easing.OutQuad } }

              Row {
                anchors.centerIn: parent
                spacing: Style.space(4)

                Text {
                  text: modelData.label
                  font.family: root.panelFont
                  font.pixelSize: Style.font.body
                  font.bold: root.activeTab === modelData.id
                  color: root.activeTab === modelData.id ? root.foregroundColor : root.dimColor
                }
              }

              MouseArea {
                id: tabMouse
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: root.activeTab = modelData.id
              }
            }
          }
        }

        PanelSeparator {
          width: parent.width
          foreground: root.foregroundColor
        }

        // 3. TAB CONTENT HOST
        Item {
          width: parent.width
          implicitHeight: currentContent.implicitHeight

          Item {
            id: currentContent
            width: parent.width
            implicitHeight: {
              if (root.activeTab === 0) return tabOverview.implicitHeight
              if (root.activeTab === 1) return tabRouting.implicitHeight
              if (root.activeTab === 2) return tabSessions.implicitHeight
              return tabSettings.implicitHeight
            }

            // ==========================================
            // TAB 0: OVERVIEW
            // ==========================================
            Column {
              id: tabOverview
              width: parent.width
              visible: opacity > 0
              opacity: root.activeTab === 0 ? 1.0 : 0.0
              spacing: Style.space(10)

              Behavior on opacity { NumberAnimation { duration: 160; easing.type: Easing.OutQuad } }

              PanelSectionHeader {
                text: "TELEMETRY METRICS"
                foreground: root.foregroundColor
                fontFamily: root.panelFont
              }

              // Structured 2x2 Omarchy Surface Metric Cards
              GridLayout {
                width: parent.width
                columns: 2
                rowSpacing: Style.space(6)
                columnSpacing: Style.space(6)

                // 1. Protected Data
                Rectangle {
                  Layout.fillWidth: true
                  height: Style.space(48)
                  color: root.alpha(root.foregroundColor, 0.03)
                  radius: Style.cornerRadius || 2
                  border.color: root.alpha(root.dimColor, 0.2)
                  border.width: 1

                  Column {
                    anchors.fill: parent
                    anchors.margins: Style.space(6)
                    spacing: Style.space(2)

                    Text {
                      text: "DATA SHIELD"
                      font.family: root.panelFont
                      font.pixelSize: Style.font.caption - 1
                      font.bold: true
                      color: root.dimColor
                    }
                    Text {
                      text: root.protectedDataStr
                      font.family: root.panelFont
                      font.pixelSize: Style.font.body
                      font.bold: true
                      color: root.foregroundColor
                    }
                  }
                }

                // 2. Bypass Sessions
                Rectangle {
                  Layout.fillWidth: true
                  height: Style.space(48)
                  color: root.alpha(root.foregroundColor, 0.03)
                  radius: Style.cornerRadius || 2
                  border.color: root.alpha(root.dimColor, 0.2)
                  border.width: 1

                  Column {
                    anchors.fill: parent
                    anchors.margins: Style.space(6)
                    spacing: Style.space(2)

                    Text {
                      text: "BYPASS SESSIONS"
                      font.family: root.panelFont
                      font.pixelSize: Style.font.caption - 1
                      font.bold: true
                      color: root.dimColor
                    }
                    Text {
                      text: String(root.tlsCount) + " / " + String(root.totalConns)
                      font.family: root.panelFont
                      font.pixelSize: Style.font.body
                      font.bold: true
                      color: root.foregroundColor
                    }
                  }
                }

                // 3. DNS Resolver
                Rectangle {
                  Layout.fillWidth: true
                  height: Style.space(48)
                  color: root.alpha(root.foregroundColor, 0.03)
                  radius: Style.cornerRadius || 2
                  border.color: root.alpha(root.dimColor, 0.2)
                  border.width: 1

                  Column {
                    anchors.fill: parent
                    anchors.margins: Style.space(6)
                    spacing: Style.space(2)

                    Text {
                      text: "DNS RELAY"
                      font.family: root.panelFont
                      font.pixelSize: Style.font.caption - 1
                      font.bold: true
                      color: root.dimColor
                    }
                    Text {
                      text: root.activeDns
                      font.family: root.panelFont
                      font.pixelSize: Style.font.body
                      font.bold: true
                      color: root.foregroundColor
                      elide: Text.ElideRight
                    }
                  }
                }

                // 4. DNS Latency
                Rectangle {
                  Layout.fillWidth: true
                  height: Style.space(48)
                  color: root.alpha(root.foregroundColor, 0.03)
                  radius: Style.cornerRadius || 2
                  border.color: root.alpha(root.dimColor, 0.2)
                  border.width: 1

                  Column {
                    anchors.fill: parent
                    anchors.margins: Style.space(6)
                    spacing: Style.space(2)

                    Text {
                      text: "DNS LATENCY"
                      font.family: root.panelFont
                      font.pixelSize: Style.font.caption - 1
                      font.bold: true
                      color: root.dimColor
                    }
                    Text {
                      text: root.dnsLatency > 0 ? (String(root.dnsLatency) + " ms") : "—"
                      font.family: root.panelFont
                      font.pixelSize: Style.font.body
                      font.bold: true
                      color: root.dnsLatency > 150 ? "#F59E0B" : (root.isRunning ? "#10B981" : root.dimColor)
                    }
                  }
                }
              }

              PanelSeparator {
                width: parent.width
                foreground: root.foregroundColor
              }

              PanelSectionHeader {
                text: "LIVE TRAFFIC OSCILLOSCOPE"
                foreground: root.foregroundColor
                fontFamily: root.panelFont
              }

              Rectangle {
                width: parent.width
                height: Style.space(78)
                color: root.alpha(root.foregroundColor, 0.02)
                radius: Style.cornerRadius || 2
                border.color: root.alpha(root.dimColor, 0.22)
                border.width: 1

                RowLayout {
                  anchors.top: parent.top
                  anchors.left: parent.left
                  anchors.right: parent.right
                  anchors.topMargin: Style.space(6)
                  anchors.leftMargin: Style.space(8)
                  anchors.rightMargin: Style.space(8)

                  Row {
                    spacing: Style.space(4)

                    Rectangle {
                      width: 5
                      height: 5
                      radius: 2.5
                      color: root.isRunning ? "#10B981" : root.dimColor
                      anchors.verticalCenter: parent.verticalCenter
                    }

                    Text {
                      text: root.isRunning ? "REALTIME TELEMETRY" : "IDLE"
                      font.family: root.panelFont
                      font.pixelSize: Style.font.caption - 1
                      font.bold: true
                      color: root.isRunning ? "#10B981" : root.dimColor
                    }
                  }

                  Item { Layout.fillWidth: true }

                  Text {
                    text: root.isRunning
                      ? (root.tlsCount > 0 ? (String(root.tlsCount) + " active bypass streams") : "Monitoring interface")
                      : "Daemon offline"
                    font.family: root.panelFont
                    font.pixelSize: Style.font.caption - 1
                    color: root.dimColor
                  }
                }

                Canvas {
                  id: sparklineCanvas
                  anchors.fill: parent
                  anchors.topMargin: Style.space(22)
                  anchors.bottomMargin: Style.space(6)
                  anchors.leftMargin: Style.space(8)
                  anchors.rightMargin: Style.space(8)

                  property real wavePhase: 0

                  Timer {
                    interval: 40
                    running: root.isRunning && root.opened
                    repeat: true
                    onTriggered: {
                      sparklineCanvas.wavePhase += 0.08
                      sparklineCanvas.requestPaint()
                    }
                  }

                  onPaint: {
                    var ctx = getContext("2d")
                    ctx.clearRect(0, 0, width, height)

                    // 1. Draw subtle background oscilloscope grid
                    ctx.strokeStyle = "rgba(255, 255, 255, 0.05)"
                    ctx.lineWidth = 1
                    ctx.beginPath()
                    ctx.moveTo(0, height * 0.35); ctx.lineTo(width, height * 0.35)
                    ctx.moveTo(0, height * 0.70); ctx.lineTo(width, height * 0.70)
                    ctx.stroke()

                    var rawData = root.activityHistory || []
                    var points = []
                    var len = Math.max(rawData.length, 24)

                    var maxVal = 1
                    for (var i = 0; i < rawData.length; i++) {
                      if (rawData[i] > maxVal) maxVal = rawData[i]
                    }

                    var hasRealTraffic = false
                    for (var a = 0; a < rawData.length; a++) {
                      if (rawData[a] > 0) { hasRealTraffic = true; break }
                    }

                    for (var j = 0; j < len; j++) {
                      var val = (j < rawData.length) ? rawData[j] : 0
                      var norm = val / maxVal
                      var py = height - 6

                      if (root.isRunning) {
                        if (hasRealTraffic && val > 0) {
                          py = height - (norm * (height - 12)) - 6
                        } else {
                          // Gentle breathing organic micro-wave when idle
                          var osc = Math.sin(j * 0.35 + wavePhase) * 2.8 + Math.sin(j * 0.7 - wavePhase * 1.4) * 1.4
                          py = height - 9 + osc
                        }
                      }
                      points.push({ x: (j / (len - 1)) * width, y: py })
                    }

                    if (points.length < 2) return

                    // 2. Draw smooth quadratic curve gradient area fill
                    var grad = ctx.createLinearGradient(0, 0, 0, height)
                    if (root.isRunning) {
                      grad.addColorStop(0, "rgba(16, 185, 129, 0.32)")
                      grad.addColorStop(0.6, "rgba(16, 185, 129, 0.08)")
                      grad.addColorStop(1, "rgba(16, 185, 129, 0.0)")
                    } else {
                      grad.addColorStop(0, "rgba(107, 114, 128, 0.15)")
                      grad.addColorStop(1, "rgba(107, 114, 128, 0.0)")
                    }

                    ctx.beginPath()
                    ctx.moveTo(points[0].x, height)
                    ctx.lineTo(points[0].x, points[0].y)

                    for (var k = 0; k < points.length - 1; k++) {
                      var xc = (points[k].x + points[k + 1].x) / 2
                      var yc = (points[k].y + points[k + 1].y) / 2
                      ctx.quadraticCurveTo(points[k].x, points[k].y, xc, yc)
                    }
                    ctx.lineTo(points[points.length - 1].x, points[points.length - 1].y)
                    ctx.lineTo(width, height)
                    ctx.closePath()
                    ctx.fillStyle = grad
                    ctx.fill()

                    // 3. Draw neon glowing smooth stroke
                    ctx.beginPath()
                    ctx.moveTo(points[0].x, points[0].y)
                    for (var m = 0; m < points.length - 1; m++) {
                      var xc2 = (points[m].x + points[m + 1].x) / 2
                      var yc2 = (points[m].y + points[m + 1].y) / 2
                      ctx.quadraticCurveTo(points[m].x, points[m].y, xc2, yc2)
                    }
                    ctx.lineTo(points[points.length - 1].x, points[points.length - 1].y)

                    ctx.strokeStyle = root.isRunning ? "#10B981" : "#6B7280"
                    ctx.lineWidth = 2.0
                    ctx.shadowColor = root.isRunning ? "#10B981" : "transparent"
                    ctx.shadowBlur = root.isRunning ? 6 : 0
                    ctx.stroke()
                    ctx.shadowBlur = 0

                    // 4. Draw glowing head tracer dot on current lead edge
                    if (root.isRunning) {
                      var lead = points[points.length - 1]
                      ctx.beginPath()
                      ctx.arc(lead.x, lead.y, 3, 0, Math.PI * 2)
                      ctx.fillStyle = "#FFFFFF"
                      ctx.fill()

                      ctx.beginPath()
                      ctx.arc(lead.x, lead.y, 5.5, 0, Math.PI * 2)
                      ctx.strokeStyle = "#10B981"
                      ctx.lineWidth = 1.5
                      ctx.stroke()
                    }
                  }
                }
              }
            }

            // ==========================================
            // TAB 1: ROUTING & DNS
            // ==========================================
            Column {
              id: tabRouting
              width: parent.width
              visible: opacity > 0
              opacity: root.activeTab === 1 ? 1.0 : 0.0
              spacing: Style.space(12)

              Behavior on opacity { NumberAnimation { duration: 160; easing.type: Easing.OutQuad } }

              PanelSectionHeader {
                text: "EVASION STRATEGY"
                foreground: root.foregroundColor
                fontFamily: root.panelFont
              }

              RowLayout {
                width: parent.width
                spacing: Style.space(6)

                Repeater {
                  model: [
                    { id: "auto", label: "Auto" },
                    { id: "split", label: "1-Byte Split" },
                    { id: "ghost", label: "Ghost SNI" },
                    { id: "disorder", label: "Disorder" }
                  ]
                  delegate: Rectangle {
                    Layout.fillWidth: true
                    height: Style.space(32)
                    radius: Style.cornerRadius || 2
                    color: root.currentMode === modelData.id
                      ? root.alpha(root.foregroundColor, 0.16)
                      : (btnMouse.containsMouse ? root.alpha(root.foregroundColor, 0.08) : "transparent")
                    border.color: root.currentMode === modelData.id
                      ? root.alpha(root.foregroundColor, 0.6)
                      : (btnMouse.containsMouse ? root.alpha(root.foregroundColor, 0.3) : root.alpha(root.dimColor, 0.25))
                    border.width: 1
                    scale: btnMouse.pressed ? 0.98 : 1.0

                    Behavior on color { ColorAnimation { duration: 120 } }
                    Behavior on border.color { ColorAnimation { duration: 120 } }
                    Behavior on scale { NumberAnimation { duration: 80 } }

                    Text {
                      anchors.centerIn: parent
                      text: modelData.label
                      font.family: root.panelFont
                      font.pixelSize: Style.font.body
                      font.bold: root.currentMode === modelData.id
                      color: root.currentMode === modelData.id ? root.foregroundColor : root.dimColor
                    }

                    MouseArea {
                      id: btnMouse
                      anchors.fill: parent
                      hoverEnabled: true
                      cursorShape: Qt.PointingHandCursor
                      onClicked: root.applyMode(modelData.id)
                    }
                  }
                }
              }

              // Subtle Strategy Caption
              Text {
                width: parent.width
                wrapMode: Text.WordWrap
                font.family: root.panelFont
                font.pixelSize: Style.font.caption
                color: root.dimColor
                text: {
                  if (root.currentMode === "auto") return "Adaptive 1-byte TCP split with automatic disorder recovery on RST"
                  if (root.currentMode === "split") return "Cuts TLS ClientHello at byte-1 to defeat middlebox regex parsers"
                  if (root.currentMode === "ghost") return "Injects decoy ClientHello with TTL=3 to desynchronize stateful DPI"
                  return "Sends TCP payload segments out-of-order to evade inline deep packet inspection"
                }
              }


              PanelSectionHeader {
                text: "DNS PROVIDER"
                foreground: root.foregroundColor
                fontFamily: root.panelFont
              }

              RowLayout {
                width: parent.width
                spacing: Style.space(6)

                Repeater {
                  model: [
                    { id: "quad9", label: "Quad9" },
                    { id: "cloudflare", label: "Cloudflare" },
                    { id: "adguard", label: "AdGuard" },
                    { id: "custom", label: "Custom" }
                  ]
                  delegate: Rectangle {
                    Layout.fillWidth: true
                    height: Style.space(32)
                    radius: Style.cornerRadius || 2
                    color: root.currentDns === modelData.id
                      ? root.alpha(root.foregroundColor, 0.16)
                      : (dnsMouse.containsMouse ? root.alpha(root.foregroundColor, 0.08) : "transparent")
                    border.color: root.currentDns === modelData.id
                      ? root.alpha(root.foregroundColor, 0.6)
                      : (dnsMouse.containsMouse ? root.alpha(root.foregroundColor, 0.3) : root.alpha(root.dimColor, 0.25))
                    border.width: 1
                    scale: dnsMouse.pressed ? 0.98 : 1.0

                    Behavior on color { ColorAnimation { duration: 120 } }
                    Behavior on border.color { ColorAnimation { duration: 120 } }
                    Behavior on scale { NumberAnimation { duration: 80 } }

                    Text {
                      anchors.centerIn: parent
                      text: (root.currentDns === modelData.id && root.dnsLatency > 0 && modelData.id !== "custom")
                        ? (modelData.label + " (" + root.dnsLatency + "ms)")
                        : modelData.label
                      font.family: root.panelFont
                      font.pixelSize: Style.font.body
                      font.bold: root.currentDns === modelData.id
                      color: root.currentDns === modelData.id ? root.foregroundColor : root.dimColor
                    }

                    MouseArea {
                      id: dnsMouse
                      anchors.fill: parent
                      hoverEnabled: true
                      cursorShape: Qt.PointingHandCursor
                      onClicked: root.applyDns(modelData.id)
                    }
                  }
                }
              }

              // Custom DoH inputs with centered text and clean inline Apply button
              Column {
                width: parent.width
                visible: root.currentDns === "custom"
                spacing: Style.space(6)

                PanelSectionHeader {
                  text: "CUSTOM DOH ENDPOINT URL"
                  foreground: root.foregroundColor
                  fontFamily: root.panelFont
                }

                RowLayout {
                  width: parent.width
                  spacing: Style.space(6)

                  Rectangle {
                    Layout.fillWidth: true
                    height: Style.space(34)
                    color: "transparent"
                    radius: Style.cornerRadius || 2
                    border.color: customDnsInput.activeFocus ? root.foregroundColor : root.alpha(root.dimColor, 0.35)
                    border.width: 1

                    Behavior on border.color { ColorAnimation { duration: 140 } }

                    TextInput {
                      id: customDnsInput
                      anchors.fill: parent
                      anchors.leftMargin: Style.space(10)
                      anchors.rightMargin: Style.space(10)
                      verticalAlignment: TextInput.AlignVCenter
                      text: root.customDnsUrl
                      font.family: root.panelFont
                      font.pixelSize: Style.font.body
                      color: root.foregroundColor
                      selectByMouse: true
                      clip: true
                      onEditingFinished: root.applyCustomDns()

                      Text {
                        anchors.fill: parent
                        verticalAlignment: Text.AlignVCenter
                        text: "https://dns.example.com/dns-query"
                        font.family: root.panelFont
                        font.pixelSize: Style.font.body
                        color: root.alpha(root.dimColor, 0.4)
                        visible: !customDnsInput.text
                      }
                    }
                  }

                  // Inline Clean Apply Button
                  Rectangle {
                    width: Style.space(80)
                    height: Style.space(34)
                    radius: Style.cornerRadius || 2
                    color: applyDnsMouse.pressed 
                      ? root.alpha(root.foregroundColor, 0.2) 
                      : (root.customDnsApplyStatus !== "" 
                        ? root.alpha("#10B981", 0.2) 
                        : (applyDnsMouse.containsMouse ? root.alpha(root.foregroundColor, 0.12) : "transparent"))
                    border.color: root.customDnsApplyStatus !== "" 
                      ? "#10B981" 
                      : (applyDnsMouse.containsMouse ? root.alpha(root.foregroundColor, 0.6) : root.alpha(root.dimColor, 0.35))
                    border.width: 1
                    scale: applyDnsMouse.pressed ? 0.97 : 1.0

                    Behavior on scale { NumberAnimation { duration: 80 } }
                    Behavior on color { ColorAnimation { duration: 120 } }
                    Behavior on border.color { ColorAnimation { duration: 120 } }

                    Text {
                      anchors.centerIn: parent
                      text: root.customDnsApplyStatus !== "" ? "Applied" : "Apply"
                      font.family: root.panelFont
                      font.pixelSize: Style.font.body
                      font.bold: true
                      color: root.customDnsApplyStatus !== "" ? "#10B981" : root.foregroundColor
                    }

                    MouseArea {
                      id: applyDnsMouse
                      anchors.fill: parent
                      hoverEnabled: true
                      cursorShape: Qt.PointingHandCursor
                      onClicked: root.applyCustomDns()
                    }
                  }
                }

                PanelSectionHeader {
                  text: "BOOTSTRAP RESOLVER IPS"
                  foreground: root.foregroundColor
                  fontFamily: root.panelFont
                }

                RowLayout {
                  width: parent.width
                  spacing: Style.space(6)

                  Rectangle {
                    Layout.fillWidth: true
                    height: Style.space(34)
                    color: "transparent"
                    radius: Style.cornerRadius || 2
                    border.color: customBoot1Input.activeFocus ? root.foregroundColor : root.alpha(root.dimColor, 0.35)
                    border.width: 1

                    Behavior on border.color { ColorAnimation { duration: 140 } }

                    TextInput {
                      id: customBoot1Input
                      anchors.fill: parent
                      anchors.leftMargin: Style.space(10)
                      anchors.rightMargin: Style.space(10)
                      verticalAlignment: TextInput.AlignVCenter
                      text: root.customBootstrapPrimary
                      font.family: root.panelFont
                      font.pixelSize: Style.font.body
                      color: root.foregroundColor
                      selectByMouse: true
                      clip: true
                      onEditingFinished: root.applyCustomDns()

                      Text {
                        anchors.fill: parent
                        verticalAlignment: Text.AlignVCenter
                        text: "Bootstrap 1 (e.g. 1.1.1.1)"
                        font.family: root.panelFont
                        font.pixelSize: Style.font.body
                        color: root.alpha(root.dimColor, 0.4)
                        visible: !customBoot1Input.text
                      }
                    }
                  }

                  Rectangle {
                    Layout.fillWidth: true
                    height: Style.space(34)
                    color: "transparent"
                    radius: Style.cornerRadius || 2
                    border.color: customBoot2Input.activeFocus ? root.foregroundColor : root.alpha(root.dimColor, 0.35)
                    border.width: 1

                    Behavior on border.color { ColorAnimation { duration: 140 } }

                    TextInput {
                      id: customBoot2Input
                      anchors.fill: parent
                      anchors.leftMargin: Style.space(10)
                      anchors.rightMargin: Style.space(10)
                      verticalAlignment: TextInput.AlignVCenter
                      text: root.customBootstrapSecondary
                      font.family: root.panelFont
                      font.pixelSize: Style.font.body
                      color: root.foregroundColor
                      selectByMouse: true
                      clip: true
                      onEditingFinished: root.applyCustomDns()

                      Text {
                        anchors.fill: parent
                        verticalAlignment: Text.AlignVCenter
                        text: "Bootstrap 2 (e.g. 1.0.0.1)"
                        font.family: root.panelFont
                        font.pixelSize: Style.font.body
                        color: root.alpha(root.dimColor, 0.4)
                        visible: !customBoot2Input.text
                      }
                    }
                  }
                }
              }
            }

            // ==========================================
            // TAB 2: STREAMS & WHITELIST
            // ==========================================
            Column {
              id: tabSessions
              width: parent.width
              visible: opacity > 0
              opacity: root.activeTab === 2 ? 1.0 : 0.0
              spacing: Style.space(12)

              Behavior on opacity { NumberAnimation { duration: 160; easing.type: Easing.OutQuad } }

              RowLayout {
                width: parent.width

                PanelSectionHeader {
                  text: "LIVE INTERCEPTED STREAMS"
                  foreground: root.foregroundColor
                  fontFamily: root.panelFont
                  Layout.fillWidth: true
                }

                Rectangle {
                  visible: root.streamEvents && root.streamEvents.length > 0
                  height: Style.space(22)
                  width: clearTxt.implicitWidth + Style.space(14)
                  radius: Style.cornerRadius || 2
                  color: "transparent"
                  border.color: root.alpha(root.dimColor, 0.35)
                  border.width: 1

                  Text {
                    id: clearTxt
                    anchors.centerIn: parent
                    text: "Flush"
                    font.family: root.panelFont
                    font.pixelSize: Style.font.caption - 1
                    font.bold: true
                    color: root.dimColor
                  }

                  MouseArea {
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.streamEvents = []
                  }
                }
              }

              Rectangle {
                width: parent.width
                height: Style.space(145)
                color: "transparent"
                radius: Style.cornerRadius || 2
                border.color: root.alpha(root.dimColor, 0.25)
                border.width: 1

                ListView {
                  anchors.fill: parent
                  anchors.margins: Style.space(8)
                  clip: true
                  spacing: Style.space(6)
                  model: root.streamEvents.slice(0, 5)

                  delegate: RowLayout {
                    width: parent.width
                    spacing: Style.space(8)

                    Rectangle {
                      width: Style.space(7)
                      height: Style.space(7)
                      radius: 3.5
                      color: modelData.status === "OK" ? "#10B981" : "#EF4444"
                    }

                    Text {
                      Layout.fillWidth: true
                      text: modelData.target || "stream"
                      font.family: root.panelFont
                      font.pixelSize: Style.font.body
                      color: root.foregroundColor
                      elide: Text.ElideRight
                    }

                    Rectangle {
                      height: Style.space(20)
                      width: stratText.implicitWidth + Style.space(10)
                      radius: Style.cornerRadius || 2
                      color: root.alpha(root.foregroundColor, 0.1)

                      Text {
                        id: stratText
                        anchors.centerIn: parent
                        text: modelData.mode || "Split"
                        font.family: root.panelFont
                        font.pixelSize: Style.font.caption
                        color: root.dimColor
                      }
                    }
                  }
                }

                Text {
                  anchors.centerIn: parent
                  visible: !root.streamEvents || root.streamEvents.length === 0
                  text: root.isRunning ? "Listening for connections..." : "Daemon inactive"
                  font.family: root.panelFont
                  font.pixelSize: Style.font.body
                  color: root.dimColor
                }
              }

              PanelSeparator {
                width: parent.width
                foreground: root.foregroundColor
              }

              PanelSectionHeader {
                text: "PASSTHROUGH WHITELIST (BYPASS ALBUS)"
                foreground: root.foregroundColor
                fontFamily: root.panelFont
              }

              Rectangle {
                width: parent.width
                height: Style.space(34)
                color: "transparent"
                radius: Style.cornerRadius || 2
                border.color: whitelistInput.activeFocus ? root.foregroundColor : root.alpha(root.dimColor, 0.35)
                border.width: 1

                Behavior on border.color { ColorAnimation { duration: 140 } }

                TextInput {
                  id: whitelistInput
                  anchors.fill: parent
                  anchors.leftMargin: Style.space(10)
                  anchors.rightMargin: Style.space(10)
                  verticalAlignment: TextInput.AlignVCenter
                  text: root.customWhitelist
                  font.family: root.panelFont
                  font.pixelSize: Style.font.body
                  color: root.foregroundColor
                  selectByMouse: true
                  clip: true
                  onEditingFinished: {
                    root.customWhitelist = text
                    root.saveConfig()
                    if (root.isRunning) root.runDaemon("start")
                  }

                  Text {
                    anchors.fill: parent
                    verticalAlignment: Text.AlignVCenter
                    text: "bank.com, internal.local (comma-separated)"
                    font.family: root.panelFont
                    font.pixelSize: Style.font.body
                    color: root.alpha(root.dimColor, 0.4)
                    visible: !whitelistInput.text
                  }
                }
              }

              // Interactive Whitelist Tag Chips
              Flow {
                width: parent.width
                spacing: Style.space(6)
                visible: root.customWhitelist.trim() !== ""

                Repeater {
                  model: root.customWhitelist.split(",").map(function(s) { return s.trim() }).filter(function(s) { return s.length > 0 })
                  delegate: Rectangle {
                    height: Style.space(22)
                    width: tagRow.implicitWidth + Style.space(12)
                    radius: Style.cornerRadius || 2
                    color: root.alpha(root.foregroundColor, 0.08)
                    border.color: root.alpha(root.dimColor, 0.3)
                    border.width: 1

                    Row {
                      id: tagRow
                      anchors.centerIn: parent
                      spacing: Style.space(6)

                      Text {
                        text: modelData
                        font.family: root.panelFont
                        font.pixelSize: Style.font.caption
                        color: root.foregroundColor
                      }

                      Text {
                        text: "×"
                        font.family: root.panelFont
                        font.pixelSize: Style.font.caption
                        font.bold: true
                        color: root.dimColor
                      }
                    }

                    MouseArea {
                      anchors.fill: parent
                      cursorShape: Qt.PointingHandCursor
                      onClicked: {
                        var list = root.customWhitelist.split(",").map(function(s) { return s.trim() }).filter(function(s) { return s.length > 0 && s !== modelData })
                        root.customWhitelist = list.join(", ")
                        root.saveConfig()
                        if (root.isRunning) root.runDaemon("start")
                      }
                    }
                  }
                }
              }
            }

            // ==========================================
            // TAB 3: SETTINGS & RECOVERY
            // ==========================================
            Column {
              id: tabSettings
              width: parent.width
              visible: opacity > 0
              opacity: root.activeTab === 3 ? 1.0 : 0.0
              spacing: Style.space(12)

              Behavior on opacity { NumberAnimation { duration: 160; easing.type: Easing.OutQuad } }

              PanelSectionHeader {
                text: "CORE ENGINE & PROVISIONING"
                foreground: root.foregroundColor
                fontFamily: root.panelFont
              }

              RowLayout {
                width: parent.width
                spacing: Style.space(6)

                Rectangle {
                  Layout.fillWidth: true
                  height: Style.space(34)
                  radius: Style.cornerRadius || 2
                  color: root.alpha(root.foregroundColor, 0.05)
                  border.color: root.alpha(root.dimColor, 0.3)
                  border.width: 1

                  Text {
                    anchors.centerIn: parent
                    text: (root.setupStatus !== "" && root.setupStatus.indexOf("Compil") === -1)
                      ? root.setupStatus
                      : "Fetch Core (" + root.latestReleaseVersion + ")"
                    font.family: root.panelFont
                    font.pixelSize: Style.font.body
                    font.bold: true
                    color: root.foregroundColor
                  }

                  MouseArea {
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.fetchLatestCore()
                  }
                }

                Rectangle {
                  Layout.fillWidth: true
                  height: Style.space(34)
                  radius: Style.cornerRadius || 2
                  color: root.alpha(root.foregroundColor, 0.05)
                  border.color: root.alpha(root.dimColor, 0.3)
                  border.width: 1

                  Text {
                    anchors.centerIn: parent
                    text: (root.setupStatus !== "" && root.setupStatus.indexOf("Compil") !== -1)
                      ? root.setupStatus
                      : "Compile Source"
                    font.family: root.panelFont
                    font.pixelSize: Style.font.body
                    font.bold: true
                    color: root.foregroundColor
                  }

                  MouseArea {
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.compileSourceCore()
                  }
                }

              }

              PanelSectionHeader {
                text: "SYSTEM & RECOVERY"
                foreground: root.foregroundColor
                fontFamily: root.panelFont
              }


              RowLayout {
                width: parent.width
                spacing: Style.space(6)

                Rectangle {
                  Layout.fillWidth: true
                  height: Style.space(34)
                  radius: Style.cornerRadius || 2
                  color: "transparent"
                  border.color: root.alpha(root.accentColor, 0.5)
                  border.width: 1
                  scale: repMouse.pressed ? 0.98 : 1.0

                  Behavior on scale { NumberAnimation { duration: 80 } }

                  Text {
                    anchors.centerIn: parent
                    text: root.repairStatus !== "" ? root.repairStatus : "Repair Network"
                    font.family: root.panelFont
                    font.pixelSize: Style.font.body
                    font.bold: true
                    color: root.accentColor
                  }

                  MouseArea {
                    id: repMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.repairNetwork()
                  }
                }

                Rectangle {
                  Layout.fillWidth: true
                  height: Style.space(34)
                  radius: Style.cornerRadius || 2
                  color: "transparent"
                  border.color: root.alpha(root.dimColor, 0.25)
                  border.width: 1
                  scale: purMouse.pressed ? 0.98 : 1.0

                  Behavior on scale { NumberAnimation { duration: 80 } }

                  Text {
                    anchors.centerIn: parent
                    text: root.purgeStatus !== "" ? root.purgeStatus : "Purge Cache"
                    font.family: root.panelFont
                    font.pixelSize: Style.font.body
                    font.bold: true
                    color: root.foregroundColor
                  }

                  MouseArea {
                    id: purMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.purgeCache()
                  }
                }

                Rectangle {
                  Layout.fillWidth: true
                  height: Style.space(34)
                  radius: Style.cornerRadius || 2
                  color: "transparent"
                  border.color: root.alpha(root.dimColor, 0.25)
                  border.width: 1
                  scale: diagMouse.pressed ? 0.98 : 1.0

                  Behavior on scale { NumberAnimation { duration: 80 } }

                  Text {
                    anchors.centerIn: parent
                    text: root.isDiagnosing ? "Testing..." : "Diagnostics"
                    font.family: root.panelFont
                    font.pixelSize: Style.font.body
                    font.bold: true
                    color: root.foregroundColor
                  }

                  MouseArea {
                    id: diagMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.runDiagnostic()
                  }
                }
              }

              // Diagnostic benchmark result surface card
              Rectangle {
                width: parent.width
                visible: root.diagnosticReport !== null
                implicitHeight: diagCol.implicitHeight + Style.space(16)
                color: root.alpha(root.foregroundColor, 0.03)
                radius: Style.cornerRadius || 2
                border.color: root.alpha(root.dimColor, 0.2)
                border.width: 1

                Column {
                  id: diagCol
                  anchors.fill: parent
                  anchors.margins: Style.space(8)
                  spacing: Style.space(8)

                  RowLayout {
                    width: parent.width

                    Text {
                      text: "CDN LATENCY BENCHMARK"
                      font.family: root.panelFont
                      font.pixelSize: Style.font.caption - 1
                      font.bold: true
                      color: root.dimColor
                    }

                    Item { Layout.fillWidth: true }

                    Text {
                      text: "IMMUNITY SCORE: " + (root.diagnosticReport ? (root.diagnosticReport.overall_score || 100) : 100) + "/100"
                      font.family: root.panelFont
                      font.pixelSize: Style.font.caption - 1
                      font.bold: true
                      color: "#10B981"
                    }
                  }

                  Repeater {
                    model: (root.diagnosticReport && Array.isArray(root.diagnosticReport.targets)) ? root.diagnosticReport.targets : []
                    delegate: RowLayout {
                      width: parent.width
                      spacing: Style.space(8)

                      Text {
                        text: modelData.target
                        font.family: root.panelFont
                        font.pixelSize: Style.font.body
                        color: root.foregroundColor
                        Layout.preferredWidth: Style.space(130)
                        elide: Text.ElideRight
                      }

                      Text {
                        text: modelData.latency_ms + " ms"
                        font.family: root.panelFont
                        font.pixelSize: Style.font.body
                        font.bold: true
                        color: modelData.latency_ms > 120 ? "#F59E0B" : "#10B981"
                        Layout.preferredWidth: Style.space(60)
                        horizontalAlignment: Text.AlignRight
                      }

                      Rectangle {
                        Layout.fillWidth: true
                        height: Style.space(4)
                        radius: 2
                        color: root.alpha(root.dimColor, 0.25)

                        Rectangle {
                          width: Math.min(parent.width, Math.max(8, (modelData.latency_ms / 200) * parent.width))
                          height: parent.height
                          radius: 2
                          color: modelData.latency_ms > 120 ? "#F59E0B" : "#10B981"
                        }
                      }

                      Rectangle {
                        height: Style.space(18)
                        width: Style.space(34)
                        radius: Style.cornerRadius || 2
                        color: modelData.success ? root.alpha("#10B981", 0.15) : root.alpha("#EF4444", 0.15)
                        border.color: modelData.success ? "#10B981" : "#EF4444"
                        border.width: 1

                        Text {
                          anchors.centerIn: parent
                          text: modelData.success ? "OK" : "FAIL"
                          font.family: root.panelFont
                          font.pixelSize: Style.font.caption - 1
                          font.bold: true
                          color: modelData.success ? "#10B981" : "#EF4444"
                        }
                      }
                    }
                  }
                }
              }

              PanelSeparator {
                width: parent.width
                foreground: root.foregroundColor
              }

              // Profile & Config Backup Section
              PanelSectionHeader {
                text: "PROFILE & CONFIG BACKUP"
                foreground: root.foregroundColor
                fontFamily: root.panelFont
              }

              RowLayout {
                width: parent.width
                spacing: Style.space(6)

                Rectangle {
                  Layout.fillWidth: true
                  height: Style.space(34)
                  radius: Style.cornerRadius || 2
                  color: "transparent"
                  border.color: root.alpha(root.dimColor, 0.25)
                  border.width: 1
                  scale: expMouse.pressed ? 0.98 : 1.0

                  Behavior on scale { NumberAnimation { duration: 80 } }

                  Text {
                    anchors.centerIn: parent
                    text: "Export Profile"
                    font.family: root.panelFont
                    font.pixelSize: Style.font.body
                    font.bold: true
                    color: root.foregroundColor
                  }

                  MouseArea {
                    id: expMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.exportProfile()
                  }
                }

                Rectangle {
                  Layout.fillWidth: true
                  height: Style.space(34)
                  radius: Style.cornerRadius || 2
                  color: "transparent"
                  border.color: root.alpha(root.dimColor, 0.25)
                  border.width: 1
                  scale: impMouse.pressed ? 0.98 : 1.0

                  Behavior on scale { NumberAnimation { duration: 80 } }

                  Text {
                    anchors.centerIn: parent
                    text: "Import Profile"
                    font.family: root.panelFont
                    font.pixelSize: Style.font.body
                    font.bold: true
                    color: root.foregroundColor
                  }

                  MouseArea {
                    id: impMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.importProfile()
                  }
                }
              }

              Text {
                visible: root.profileStatus !== ""
                text: root.profileStatus
                font.family: root.panelFont
                font.pixelSize: Style.font.caption
                color: "#10B981"
              }

              PanelSeparator {
                width: parent.width
                foreground: root.foregroundColor
              }

              PanelSectionHeader {
                text: "PREFERENCES"
                foreground: root.foregroundColor
                fontFamily: root.panelFont
              }

              RowLayout {
                width: parent.width

                Text {
                  Layout.fillWidth: true
                  text: "Autostart on Boot"
                  font.family: root.panelFont
                  font.pixelSize: Style.font.body
                  color: root.foregroundColor
                }

                ToggleSwitch {
                  checked: root.autostartEnabled
                  foreground: root.foregroundColor
                  onToggled: root.toggleAutostart()
                }
              }

              RowLayout {
                width: parent.width

                Text {
                  Layout.fillWidth: true
                  text: "Session Notifications"
                  font.family: root.panelFont
                  font.pixelSize: Style.font.body
                  color: root.foregroundColor
                }

                ToggleSwitch {
                  checked: root.notificationsEnabled
                  foreground: root.foregroundColor
                  onToggled: root.toggleNotifications()
                }
              }
            }
          }
        }

        // 4. POWER-USER KEYBOARD LEGEND FOOTER
        PanelSeparator {
          width: parent.width
          foreground: root.foregroundColor
        }

        RowLayout {
          width: parent.width

          Text {
            text: "[1-4] Tabs"
            font.family: root.panelFont
            font.pixelSize: Style.font.caption - 1
            color: root.alpha(root.dimColor, 0.55)
          }

          Item { Layout.fillWidth: true }

          Text {
            text: "[Space] Toggle Protection"
            font.family: root.panelFont
            font.pixelSize: Style.font.caption - 1
            color: root.alpha(root.dimColor, 0.55)
          }

          Item { Layout.fillWidth: true }

          Text {
            text: "[Esc] Close"
            font.family: root.panelFont
            font.pixelSize: Style.font.caption - 1
            color: root.alpha(root.dimColor, 0.55)
          }
        }
      }
    }
  }
}
