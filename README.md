# Secure Trust On First Use (TOFU) for Enterprise Wi-Fi — NetworkManager

This repository contains a modified version of **NetworkManager** that implements a **Trust On First Use (TOFU)** framework for WPA2/3-Enterprise Wi-Fi authentication. It is the prototype accompanying the paper:

> **Secure Trust On First Use for Enterprise Wi-Fi: Design Guidelines and Linux Implementation**  
> Presented at ACM WiSec 2026  
> Anonymous review copy: https://anonymous.4open.science/r/Trust_on_First_Use-NetworkManager-938B

The changes extend NetworkManager with TOFU core logic, a new **CertificateAgent D-Bus interface**, and certificate persistence, enabling interactive, user-driven trust decisions during the EAP TLS handshake without sacrificing strong validation guarantees.

---

## Table of Contents

1. [Background and Motivation](#1-background-and-motivation)
2. [Security Findings](#2-security-findings)
3. [System Architecture](#3-system-architecture)
4. [Design Principles](#4-design-principles)
5. [Scope of This Repository](#5-scope-of-this-repository)
6. [Installation](#6-installation)
  6.1 [Prerequisites](#61-prerequisites)
  6.2 [Build and Install (Standalone)](#62-build-and-install-standalone)
  6.3 [wpa_supplicant](#63-wpa_supplicant)
  6.4 [GUI Agent (nm-applet / GNOME Shell)](#64-gui-agent-nm-applet--gnome-shell)
7. [Simulated Testbed Setup](#7-simulated-testbed-setup)
  7.1 [Load Virtual Radios](#71-load-virtual-radios)
  7.2 [Start the AP with hostapd](#72-start-the-ap-with-hostapd)
  7.3 [Set Up DHCP](#73-set-up-dhcp)
  7.4 [Connect the Client via NetworkManager](#74-connect-the-client-via-networkmanager)
  7.5 [Connecting via GNOME Settings](#75-connecting-via-gnome-settings)
8. [Evaluation Scenarios](#8-evaluation-scenarios)
9. [Debugging Tips](#9-debugging-tips)
10. [Related Repositories](#10-related-repositories)
11. [Security Considerations](#11-security-considerations)
12. [Disclaimer](#12-disclaimer)

---

## 1. Background and Motivation

Enterprise Wi-Fi (WPA2/3-Enterprise) uses IEEE 802.1X and EAP to authenticate individual users against a central RADIUS Authentication Server (AS). A critical security requirement of this setup is that the client validates the AS's X.509 certificate during the TLS handshake, before submitting any credentials. If this step is skipped or misconfigured, an adversary can run a **rogue access point (Evil Twin)** to harvest credentials.

In practice, studies show that misconfiguration is endemic:

- ~86% of educational institutions worldwide provide configuration guides that lead to insecure setups ([Hue et al., CCS 2021](https://dl.acm.org/doi/10.1145/3460120.3484569))
- ~1 in 5 devices accepted a forged certificate in a recent real-world ethical Evil Twin experiment ([Appana et al., CSNet 2025](https://doi.org/10.1109/CSNet67572.2025.11288146))
- 67% of Eduroam profiles expose real user identities in plain text ([Perković et al., 2020](https://doi.org/10.1155/2020/3731529))

The root cause is a usability gap: Linux offers no middle ground between **"provide a CA certificate manually"** (requires prior infrastructure knowledge) and **"disable validation entirely"** (catastrophically insecure). Other platforms (Android, iOS, macOS, Windows) implement ad-hoc TOFU mechanisms, but each differs in behavior and all have documented security flaws.

This work fills that gap with a **principled, open-source TOFU design** implemented within the Linux networking stack.

---

## 2. Security Findings

During implementation and evaluation, we identified a **vulnerability in wpa_supplicant** where all OpenSSL validation errors (including certificate expiry and malformed fields) were silently ignored when:

- no CA certificate was configured in the connection profile 
- an AS certificate fingerprint was pinned rather than a CA

This effectively disabled certificate validation in common TOFU-adjacent configurations. The issue was **responsibly disclosed** and has been fixed upstream in wpa_supplicant. The patch enforces validity checks regardless of CA configuration.

Due to confidentiality of the author, the exact patches are not quoted.

---

## 3. System Architecture

The TOFU framework operates entirely in user space across three layers:

```
┌─────────────────────────────────────────────────────┐
│                    USER LAYER                       │
│   gnome-shell  │  nm-applet  │  custom agents       │
│   (register as CertificateAgents via D-Bus)         │
└──────────────────────┬──────────────────────────────┘
                       │ D-Bus (CertificateAgent interface)
┌──────────────────────▼──────────────────────────────┐
│          NETWORK MANAGEMENT DAEMON LAYER            │
│              NetworkManager [TOFU core]             │
│  - Detect TOFU session (no CA configured)           │
│  - Receive cert chain from wpa_supplicant           │
│  - Structural + expiry validation                   │
│  - System CA trust store check                      │
│  - Dispatch prompt to CertificateAgent              │
│  - On accept: save CA to                            │
│    /var/lib/NetworkManager/tofu/                    │
│    update connection profile, reconnect             │
│  - On reject: delete profile, disconnect            │
└──────────────────────┬──────────────────────────────┘
                       │ D-Bus
┌──────────────────────▼──────────────────────────────┐
│             SUPPLICANT DAEMON LAYER                 │
│                 wpa_supplicant                      │
│  - EAP/TLS handshake                                │
│  - Emits CertChainAvailable D-Bus signal with PEM   │
│  - Receives response from NM, resumes or aborts     │
└─────────────────────────────────────────────────────┘
```

All interaction between layers uses standard D-Bus APIs. No TLS libraries, EAP protocol internals, or kernel networking components are modified.

---

## 4. Design Principles

The implementation follows the TOFU design guidelines described in the paper:

1. **Configurable Trust Option** — TOFU replaces "No CA certificate required" as an explicit, secure fallback choice.
2. **Anonymous Identity Support** — If the anonymous outer identity field is left empty, the system auto-generates one (e.g., `anonymous@realm`) to protect user privacy during Phase 1 of EAP.
3. **Structural and Expiry Validation** — Expired or malformed certificates cause immediate session termination before any user prompt.
4. **System Trust Store Check** — Before prompting the user, NM checks whether the certificate chain is already trusted by the system CA store. The result appears in the prompt's disclaimer.
5. **Minimal User Interface** — The prompt shows only essentials (SSID, CN, DNS name, disclaimer), with an expandable "More Details" section for issuer, organization, SHA-256 fingerprint, and expiry date.
6. **Trust Persistence** — When a CA certificate is present in the chain, it is saved to `/var/lib/NetworkManager/tofu/` and written into the connection profile. When only a server certificate is sent (no CA), the server cert hash is pinned in `trusted-server-certs.json`. Subsequent connections verify against the stored entry; mismatches trigger a new prompt.
7. **Certificate Rotation Handling** — If the stored CA is still valid but the server cert has rotated under it, the connection proceeds silently. If the CA itself has changed, the user is warned and shown the new certificate.
8. **Logging** — All TOFU events (acceptance, rejection, revalidation) are logged via NM's standard logging infrastructure.

---

## 5. Scope of This Repository

This repository includes:

- NetworkManager core TOFU logic (`src/core/nm-tofu.c`, `nm-device-wifi.c`, `nm-manager.c`, `nm-supplicant-interface.c`)
- `CertificateVerificationRequest` and `CertificateVerificationFailure` D-Bus signal definitions
- CertificateAgent dispatch and registration logic
- Trust persistence: CA cert storage and server-cert fingerprint pinning
- nmtui integration for terminal-based certificate prompts

This repository **does not include**:

- GNOME Shell / GNOME Control Center integration (separate repository)

The TOFU framework works with only this modified NetworkManager and a compatible GUI agent. The other components are optional UI enhancements.

---

## 6. Installation

### 6.1 Prerequisites

Tested on **Ubuntu 22.04 LTS** with:
- NetworkManager built from this repo
- wpa_supplicant 2.12 (upstream no patch required)
- gnome-shell 42.9
- Linux kernel 6.8.0

Install build dependencies:

```bash
sudo apt install meson ninja-build pkg-config \
    libglib2.0-dev libdbus-1-dev libssl-dev \
    libnl-3-dev libnl-genl-3-dev libnl-route-3-dev \
    libsystemd-dev libpolkit-gobject-1-dev \
    libcurl4-gnutls-dev libgnutls28-dev \
    libndp-dev libnewt-dev libjansson-dev \
    libmm-glib-dev libnss3-dev libpsl-dev \
    python3-gi libgirepository1.0-dev \
    hostapd dnsmasq
```

### 6.2 Build and Install (Standalone)

This repo is a complete fork of NetworkManager and can be built and installed directly, no patching of another source tree is required.

**Option A — install system-wide (recommended for evaluation):**

Download the repository from [here](https://anonymous.4open.science/r/Trust_on_First_Use-NetworkManager-938B)
```bash
cd Trust_on_First_Use-NetworkManager-938B

meson setup builddir \
    --prefix=/usr \
    --sysconfdir=/etc \
    --localstatedir=/var \
    -Ddebug=true \
    -Dnmtui=true \
    -Dmodem_manager=false \
    -Dsession_tracking=elogind

ninja -C builddir
sudo ninja -C builddir install
sudo systemctl daemon-reload
sudo systemctl restart NetworkManager
```

**Option B — install to a custom prefix (leaves system NM intact):**

This is useful during development so you can easily switch back.

```bash
meson setup builddir \
    --prefix=$HOME/nm-custom \
    --sysconfdir=/etc \
    --localstatedir=/var \
    -Ddebug=true \
    -Dnmtui=true \
    -Dmodem_manager=false \
    -Dsession_tracking=elogind

ninja -C builddir
ninja -C builddir install

# Stop the system NM first, then run the custom build
sudo systemctl stop NetworkManager
sudo $HOME/nm-custom/sbin/NetworkManager --no-daemon --log-level=DEBUG
```

With Option B, all NM logs appear directly in the terminal. To scope to Wi-Fi logs only:

```bash
sudo NETWORK_MANAGER_LOGGING_BACKEND=stderr \
    $HOME/nm-custom/sbin/NetworkManager \
    --no-daemon --log-level=DEBUG --log-domains=WIFI
```

After subsequent code changes, only these two commands are needed, no need to re-run `meson setup`:

```bash
ninja -C builddir
sudo ninja -C builddir install   # or: ninja -C builddir install (Option B)
```

### 6.3 wpa_supplicant

Upstream wpa_supplicant can be used directly, no custom build or patch is required. The TOFU framework in NM does not depend on any wpa_supplicant modification. The certificate validity vulnerability described in [Security Findings](#2-security-findings) has been fixed upstream; simply use **wpa_supplicant 2.12 or later**, which ships with Ubuntu 22.04.

The system wpa_supplicant service requires no changes. NM manages it automatically.

### 6.4 GUI Agent (nm-applet / GNOME Shell)

To see the graphical TOFU certificate prompt, a GUI agent must be registered with NM. The modified nm-applet or GNOME Shell integration are maintained in separate repositories (links TBD after paper review). The core TOFU flow including terminal-based prompts via the modified nmtui included in this repo, works without them.

---

## 7. Simulated Testbed Setup

The prototype was developed and evaluated using the `mac80211_hwsim` kernel module to emulate wireless interfaces in software. This section describes the full setup.

**Interface roles:** `wlan0` is the virtual AP, `wlan1` is the client managed by NetworkManager.

> **Important:** Do not use Linux network namespaces. NM cannot see or manage interfaces inside namespaces, which breaks TOFU entirely. `wlan0` and `wlan1` should both be visible in the default namespace.

### 7.1 Load Virtual Radios

```bash
# Creates wlan0, wlan1, wlan2, ...
sudo modprobe mac80211_hwsim radios=3

# Confirm interfaces appeared
ip link show | grep wlan
```

Three radios are useful: `wlan0` (AP), `wlan1` (NM-managed client), `wlan2` (optional rogue AP or monitor interface).

### 7.2 Start the AP with hostapd

The AP runs using hostapd's built-in EAP server (`eap_server=1`), so **no separate RADIUS server is required**. However, you do need to generate your own X.509 certificates, the example certs that ship with the hostapd source expire quickly and will cause authentication failures.

The easiest way is to use the FreeRADIUS bootstrap script, which generates a full CA and server certificate in one step:

```bash
sudo apt install freeradius
cd /etc/freeradius/3.0/certs
sudo make bootstrap
```

This produces `ca.pem`, `server.pem`, and `server.key` in `/etc/freeradius/3.0/certs/`, which you can point hostapd at directly. To verify the certificates are valid before starting hostapd:

```bash
openssl x509 -in /etc/freeradius/3.0/certs/server.pem -noout -startdate -enddate
```

Create `/etc/hostapd/hostapd.conf`:

```ini
interface=wlan0
driver=nl80211
ssid=testnetwork
hw_mode=g
channel=1

# 802.1X / EAP
ieee8021x=1
eap_server=1
eap_user_file=/etc/hostapd/hostapd.eap_user

# Server certificate — use the example certs from the hostapd source tree
# (hostapd/hostapd/certs/ or hostapd/wpa_supplicant/eap_example/certs/)
ca_cert=/path/to/hostapd/certs/ca.pem # change the path certificates created by freeradius
server_cert=/path/to/hostapd/certs/server.pem # change the path certificates created by freeradius
private_key=/path/to/hostapd/certs/server.key # change the path certificates created by freeradius
private_key_passwd=whatever

# WPA2
wpa=2
wpa_key_mgmt=WPA-EAP
rsn_pairwise=CCMP

# Disable PMKSA caching so full EAP authentication runs on every connection
disable_pmksa_caching=1
okc=0
```

Create `/etc/hostapd/hostapd.eap_user`:

```
# Phase 1 — outer identity (accepts any anonymous identity)
"*"         PEAP

# Phase 2 — inner authentication (MSCHAPv2 credentials)
"testuser"  MSCHAPV2    "password"  [2]
```

Start the AP:

```bash
sudo hostapd /etc/hostapd/hostapd.conf
```

**Testing specific edge cases:**

- **Rogue AP (Evil Twin test):** Run a second hostapd instance on `wlan2` with the same SSID but a different (e.g., self-signed or mismatched) server certificate. Point the client at `wlan2` and TOFU will detect the mismatch and block the connection.
- **Leaf-cert-only (no CA in chain):** Comment out `ca_cert` in hostapd.conf. The server will send only its own certificate with no CA chain. TOFU handles this by pinning the server cert hash instead of storing a CA.
- **Expired certificate test:** Replace `server.pem` with an expired certificate. TOFU will reject it before showing any prompt.

### 7.3 Set Up DHCP

Without DHCP, NM will loop EAPOL indefinitely after successful EAP authentication because it cannot complete IP configuration. Use dnsmasq on the AP interface:

```bash
sudo nano /etc/dnsmasq.d/hostapd-dhcp.conf
```

```ini
port=0                            # disable DNS to avoid port 53 conflict
interface=wlan0
dhcp-range=192.168.50.10,192.168.50.100,12h
```

Assign a static IP to the AP interface so dnsmasq has a gateway:

```bash
sudo ip addr add 192.168.50.1/24 dev wlan0
sudo systemctl restart dnsmasq
```

### 7.4 Connect the Client via NetworkManager

Create a WPA-Enterprise connection profile **without a CA certificate** — the absence of `802-1x.ca-cert` is the TOFU trigger:

```bash
nmcli connection add \
    type wifi \
    con-name testnetwork \
    ifname wlan1 \
    ssid testnetwork \
    -- \
    wifi-sec.key-mgmt wpa-eap \
    802-1x.eap peap \
    802-1x.identity "testuser" \
    802-1x.anonymous-identity "anonymous@testnetwork" \
    802-1x.password "password" \
    802-1x.phase2-auth mschapv2 \
    ipv4.method auto
```

Activate the connection:

```bash
nmcli connection up testnetwork ifname wlan1
```

**What happens on first connection:**

1. NM detects no CA certificate is configured → activates TOFU mode
2. wpa_supplicant completes the TLS handshake and sends the full certificate chain to NM over D-Bus
3. NM validates structure and expiry, checks against the system CA store, then disconnects from the AP temporarily
4. NM dispatches a `CertificateVerificationRequest` to the registered GUI agent (nm-applet or nmtui)
5. The user sees the certificate prompt with SSID, server name, DNS name, issuer, fingerprint, and a disclaimer
6. **On accept:** NM saves the CA cert to `/var/lib/NetworkManager/tofu/`, updates the `.nmconnection` profile with `ca-cert=`, re-enables auto-connect, and immediately re-activates the connection — this second attempt uses full CA validation
7. **On reject:** NM deletes the connection profile and disables auto-connect

**What happens on subsequent connections:** The stored CA is validated against the server certificate silently. A prompt only reappears if the CA has changed or the server certificate cannot be verified.

### 7.5 Connecting via GNOME Settings

Once the modified NM and GNOME Control Center (or nm-applet) are installed, connecting through the graphical Wi-Fi settings works as well. The "No CA certificate required" option is renamed to "Trust on First Use (TOFU)". Selecting it and filling in the EAP credentials triggers the certificate prompt automatically on first connect no CLI steps needed.

---

## 8. Evaluation Scenarios

| Scenario | Expected Behavior | Result |
|---|---|---|
| First connection — TOFU mode (no CA configured) | Cert prompt shown; CA saved on accept; profile updated; immediate re-connection with full validation | Pass |
| Subsequent connection — same CA valid | Silent auto-connect, no prompt | Pass |
| Server cert rotation under same CA | Silent auto-connect (CA still validates server cert) | Pass |
| Rogue AP — mismatched certificate | Warning prompt; no credentials transmitted | Pass |
| Server sends leaf cert only (no CA in chain) | Server cert hash pinned; mismatch on next connection triggers prompt | Pass |
| Expired certificate presented | Immediate rejection before any prompt or credential exchange | Pass |

Overhead introduced by D-Bus communication and GUI rendering was negligible (~100 ms beyond the standard TLS handshake).

---

## 9. Debugging Tips

**Live NM logs when running with `--no-daemon`** (Option B install):

```bash
sudo $HOME/nm-custom/sbin/NetworkManager --no-daemon --log-level=DEBUG
```

**Enable debug logging on a running system NM:**

```bash
sudo nmcli general logging level DEBUG domains ALL
sudo journalctl -u NetworkManager -f
```

**Watch wpa_supplicant events live:**

```bash
sudo journalctl -u wpa_supplicant -f
```

**Monitor D-Bus traffic** (observe the TOFU signal flow in real time):

```bash
sudo dbus-monitor --system "interface=org.freedesktop.NetworkManager"
```

**Check which NM logging domains are active:**

```bash
nmcli general logging
```

**Common issue — EAPOL loop after authentication:** This means DHCP is not working. Confirm that dnsmasq is running, `wlan0` has IP `192.168.50.1/24`, and the `dhcp-range` interface in dnsmasq matches `wlan0`.

**Common issue — NM skips EAP due to PMKSA cache:** Ensure `disable_pmksa_caching=1` and `okc=0` are set in hostapd.conf. NM/wpa_supplicant will flush the cache automatically on disconnect, but a stale cache from a previous run can cause this.

---

## 10. Related Repositories

| Component | Description | Link |
|---|---|---|
| **NetworkManager (this repo)** | TOFU core, CertificateAgent D-Bus interface, nmtui prompts | [anonymous.4open.science](https://anonymous.4open.science/r/Trust_on_First_Use-NetworkManager-938B) |
| GNOME Shell / Control Center | Shell-level prompt; settings page TOFU option | TBD (post-review) |
| wpa_supplicant upstream fix | Certificate validity patch | Fixed in wpa_supplicant ≥ 2.12 |

---

## 11. Security Considerations

- NM **never implicitly trusts** a certificate. Every first-use decision requires explicit user confirmation.
- Expired or structurally invalid certificates cause immediate session termination, before any prompt or credential exchange.
- Accepted CA certificates are stored in `/var/lib/NetworkManager/tofu/` an NM-owned, writable path appropriate for runtime-generated certs. They are **not** written to `/etc/ssl/certs/` (the system trust bundle managed by `update-ca-certificates`).
- No UI code runs in the privileged NM daemon process. All display logic runs in the registered agent.
- D-Bus access to the CertificateAgent interface is restricted via polkit policy rules.
- All TOFU events are logged through NM's standard logging infrastructure for administrative auditability.
- The **upstream wpa_supplicant fix** is strongly recommended independently of this TOFU implementation. Unpatched versions silently accept expired certificates even when TOFU is not in use.

---

## 12. Disclaimer

This is a **research prototype** extending NetworkManager for the purpose of studying and improving enterprise Wi-Fi certificate validation. It is not an official upstream release of NetworkManager.

Feedback, peer review, and discussion are welcome, please open an issue or get in touch.

---