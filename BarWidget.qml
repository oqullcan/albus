import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui
import "Model.js" as Model

// albus bar widget component with clean typography, zero emojis, and middle-click toggle
BarWidget {
  id: root
  moduleName: "io.github.oqullcan.albus"

  // panel lifecycle state

  readonly property bool opened: panelLoader.item
    ? panelLoader.item.opened === true
    : false
  readonly property bool popoutSwitchClosing: panelLoader.item
    ? panelLoader.item.popoutSwitchClosing === true
    : false

  // live protection state directly bound to panel state
  readonly property bool protectionActive: panelLoader.item
    ? panelLoader.item.isRunning === true
    : false

  function open() {
    if (panelLoader.item) panelLoader.item.open()
  }

  function close() {
    if (panelLoader.item) panelLoader.item.close()
  }

  function toggle() {
    if (panelLoader.item) panelLoader.item.toggle()
  }

  function closeForPopoutSwitch() {
    if (panelLoader.item) panelLoader.item.closeForPopoutSwitch()
  }

  function injectPanel() {
    if (!panelLoader.item) return
    panelLoader.item.bar = root.bar
    panelLoader.item.anchorItem = button
    panelLoader.item.hostWidget = root
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onBarChanged: injectPanel()

  // status polling timer for live bar indicator
  Timer {
    id: pollTimer
    interval: 1200
    running: true
    repeat: true
    onTriggered: {
      if (panelLoader.item && typeof panelLoader.item.refreshStatus === "function") {
        panelLoader.item.refreshStatus()
      }
    }
  }

  // deferred panel loader
  Loader {
    id: panelLoader
    active: true
    source: Qt.resolvedUrl("Panel.qml")
    visible: false
    onLoaded: {
      root.injectPanel()
      Qt.callLater(root.injectPanel)
    }
  }

  IpcHandler {
    target: "io.github.oqullcan.albus"

    function open(): void { root.open() }

    function close(): void { root.close() }
    function show(): void { root.open() }
    function hide(): void { root.close() }
    function toggle(): void { root.toggle() }
  }

  // bar icon button surface matching other omarchy bar icons
  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: root.protectionActive ? "󰒃" : "󰒄"
    active: root.protectionActive
    useActiveColor: true
    activeColor: root.bar && root.bar.urgent !== undefined ? root.bar.urgent : Color.accent
    tooltipText: root.protectionActive
      ? ("Albus Anti-DPI: Protected • " + (panelLoader.item ? panelLoader.item.activeDns : "Quad9") + (panelLoader.item && panelLoader.item.dnsLatency > 0 ? " (" + panelLoader.item.dnsLatency + "ms)" : "") + " • Middle-click to disable")
      : "Albus Anti-DPI: Standby • Click or Middle-click to protect"
    onPressed: function(buttonCode) {
      if (buttonCode === Qt.LeftButton) {
        root.toggle()
      } else if (buttonCode === Qt.MiddleButton || buttonCode === Qt.RightButton) {
        if (panelLoader.item) {
          panelLoader.item.toggleDaemon()
        }
      }
    }
  }

}
