# Desktop Integration (QML)

Albus includes native desktop panel and widget integration for the **Omarchy Quattro** shell on Linux. This allows desktop users to monitor packet telemetry, toggle evasion features, and inspect threat drops directly from the system bar without opening a web browser or terminal.

---

## Component Architecture

Desktop integration is implemented in pure QtQuick / QML without external binary wrappers:

| File | Role | Description |
| :--- | :--- | :--- |
| `manifest.json` | Plugin Metadata | Declares plugin identifier `io.github.oqullcan.albus.dev`, version, icons, and shell entry points. |
| `BarWidget.qml` | Status Bar Widget | Minimalist taskbar item displaying live status dot, active upstream icon, and query rate ticker. |
| `Panel.qml` | Control Center Flyout | Comprehensive flyout drawer mirroring the Web UI: real-time telemetry, provider switcher, MSS slider, and live log stream. |

```
+-----------------------------------------------------------+
| Omarchy Status Bar                                        |
| [Apps] [Workspaces]               [ALBUS * Quad9 18 q/s]  |  <-- BarWidget.qml
+-----------------------------------------------------|-----+
                                                      | Click
                                                      v
                                        +-------------------+
                                        | Panel.qml Flyout  |
                                        | - Metrics Grid    |
                                        | - Evasion Toggles |
                                        | - Upstream Cards  |
                                        | - Live Log Stream |
                                        +-------------------+
                                                      |
                                        REST API / CLI IPC
                                                      |
                                                      v
                                        +-------------------+
                                        | Albus Core Daemon |
                                        | (127.0.0.1:0205)  |
                                        +-------------------+
```

---

## Installation & Setup

### 1. Deploy Plugin Files

Copy the manifest and QML components to the user's Omarchy plugin repository:

```bash
PLUGIN_DIR="$HOME/.config/omarchy/plugins/io.github.oqullcan.albus.dev"
mkdir -p "$PLUGIN_DIR"
cp manifest.json BarWidget.qml Panel.qml "$PLUGIN_DIR/"
```

### 2. Register Plugin with Shell

Notify the Omarchy shell daemon to rescan and activate installed plugins:

```bash
omarchy-shell shell rescanPlugins
```

### 3. Add Widget to Panel Layout

In your Omarchy Quattro bar layout configuration (`~/.config/omarchy/quattro.json`):

```json
{
  "panel": {
    "right": [
      "systray",
      "io.github.oqullcan.albus.dev",
      "clock"
    ]
  }
}
```

---

## Features & Controls in `Panel.qml`

### Real-Time Metric Tiles
* **Active Status Pill**: Green glowing indicator when eBPF shaper is active; red when paused.
* **Telemetry Tickers**: Dynamic queries processed, DNS cache hit ratio, and cumulative threat drops.

### Interactive Control Matrix
* **One-Click Upstream Selection**: Switch between Quad9, Cloudflare, Mullvad profiles, and Custom endpoints. Changes apply instantly without restarting desktop applications.
* **MSS Clamping Slider**: Live slider to adjust initial TCP MSS between 64 and 1400 bytes.
* **Feature Toggles**:
  * PQC (ML-KEM-768 hybrid key exchange)
  * DNSSEC signature validation
  * HaGeZi Threat Filter
  * Anti-DNS Rebinding Shield
  * QUIC UDP 443 Drop
  * WebRTC STUN Leak Drop
  * DNS Leak Kill-Switch

### Live Log Streaming Cockpit
The panel embeds a real-time event monitor parsing systemd journal logs. Log items are categorized with distinct color badges (`INJECT`, `SHIELD`, `DNS`, `QUIC`, `SYS`) to provide immediate visual confirmation of DPI evasion in progress.
