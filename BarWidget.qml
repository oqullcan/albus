import QtQuick
import Quickshell
import qs.Commons
import qs.Ui

BarWidget {
  id: root
  moduleName: "io.github.oqullcan.albus.dev"

  readonly property bool opened: panelLoader.item ? panelLoader.item.opened === true : false
  readonly property bool popoutSwitchClosing: panelLoader.item ? panelLoader.item.popoutSwitchClosing === true : false

  function open() {
    if (panelLoader.item) panelLoader.item.open()
  }

  function close() {
    if (panelLoader.item) panelLoader.item.close()
  }

  function togglePanel() {
    if (panelLoader.item) panelLoader.item.toggle()
  }

  function closeForPopoutSwitch() {
    if (panelLoader.item && typeof panelLoader.item.closeForPopoutSwitch === "function")
      panelLoader.item.closeForPopoutSwitch()
    else close()
  }

  function injectPanel() {
    var target = panelLoader.item
    if (!target) return
    if ("bar" in target) target.bar = root.bar
    if ("anchorItem" in target) target.anchorItem = button
    if ("hostWidget" in target) target.hostWidget = root
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onBarChanged: injectPanel()

  Timer {
    id: statusTimer
    interval: 2000
    running: true
    repeat: true
    triggeredOnStart: true
    onTriggered: {
      if (panelLoader.item && typeof panelLoader.item.refreshStatus === "function") {
        panelLoader.item.refreshStatus()
      }
    }
  }

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

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: panelLoader.item && panelLoader.item.isRunning ? "󰞌" : "󰞏"
    active: panelLoader.item && panelLoader.item.isRunning
    tooltipText: panelLoader.item && panelLoader.item.isRunning
      ? "Albus DPI: Active (eBPF + DoH)"
      : "Albus DPI: Standby (Click to manage)"
    // Every button opens the panel. A right-click used to run an unconfirmed
    // `systemctl stop`, which is not a gesture this widget advertises and
    // whose consequence is fail-open: ExecStopPost reverts /etc/resolv.conf
    // to the saved plaintext nameservers and deletes the DNS kill-switch and
    // lockdown DROP rules, and systemd does not apply Restart=always to a unit
    // stopped by an explicit job, so the host stays unprotected indefinitely.
    // Lifecycle control lives in the panel, behind a visible switch and a
    // polkit prompt that names the action.
    onPressed: function(b) {
      root.togglePanel()
    }
  }
}
