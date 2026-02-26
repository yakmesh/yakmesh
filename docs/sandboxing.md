# Yakmesh Sandboxing Guide

## Overview

This document describes how to run Yakmesh in a sandboxed environment on Linux and macOS. While the core security features (SANGHA, FS Hardening, Memory Safety, etc.) work on all platforms, OS-level sandboxing provides an additional defense layer.

## Linux Sandboxing

### Option 1: systemd Service with Sandboxing

Create `/etc/systemd/system/yakmesh.service`:

```ini
[Unit]
Description=Yakmesh P2P Mesh Network Node
After=network.target

[Service]
Type=simple
User=yakmesh
Group=yakmesh
WorkingDirectory=/opt/yakmesh
ExecStart=/usr/bin/node server/index.js
Restart=always
RestartSec=10

# Sandboxing directives
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
LockPersonality=yes
SystemCallFilter=@system-service
SystemCallArchitectures=native

# Allow only necessary capabilities
CapabilityBoundingSet=
AmbientCapabilities=

# Filesystem access
ReadWritePaths=/opt/yakmesh/data
ReadOnlyPaths=/opt/yakmesh

# Resource limits
LimitNOFILE=65535
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable yakmesh
sudo systemctl start yakmesh
```

### Option 2: Firejail

Install firejail and create profile `/etc/firejail/yakmesh.profile`:

```
# Yakmesh Firejail profile
include /etc/firejail/default.profile

# Restrict to yakmesh directory
whitelist /opt/yakmesh
read-only /opt/yakmesh
read-write /opt/yakmesh/data

# Network access
net eth0

# Capabilities
caps.drop all
caps.keep net_bind_service

# Seccomp
seccomp

# Memory
memory-deny-write-execute

# Disable unneeded features
no3d
nodvd
nogroups
nonewprivs
nosound
notv
novideo
```

Run:
```bash
firejail --profile=/etc/firejail/yakmesh.profile node /opt/yakmesh/server/index.js
```

### Option 3: Docker with seccomp/AppArmor

Dockerfile:
```dockerfile
FROM node:24-slim

# Create non-root user
RUN groupadd -r yakmesh && useradd -r -g yakmesh yakmesh

# Set up app
WORKDIR /app
COPY --chown=yakmesh:yakmesh . .
RUN npm ci --production

# Switch to non-root
USER yakmesh

# Expose ports
EXPOSE 3080 9080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD curl -f http://localhost:3080/health || exit 1

CMD ["node", "server/index.js"]
```

Docker Compose with security options:
```yaml
version: '3.8'
services:
  yakmesh:
    build: .
    security_opt:
      - no-new-privileges:true
      - seccomp:unconfined  # Or use custom seccomp profile
    cap_drop:
      - ALL
    read_only: true
    tmpfs:
      - /tmp
    volumes:
      - ./data:/app/data:rw
    ports:
      - "3080:3080"
      - "9080:9080"
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
```

### Option 4: bubblewrap (bwrap)

Minimal sandboxing with bubblewrap:

```bash
#!/bin/bash
bwrap \
  --ro-bind /usr /usr \
  --ro-bind /lib /lib \
  --ro-bind /lib64 /lib64 \
  --ro-bind /opt/yakmesh /opt/yakmesh \
  --bind /opt/yakmesh/data /opt/yakmesh/data \
  --tmpfs /tmp \
  --proc /proc \
  --dev /dev \
  --unshare-all \
  --share-net \
  --die-with-parent \
  --new-session \
  --hostname yakmesh \
  --chdir /opt/yakmesh \
  /usr/bin/node server/index.js
```

## macOS Sandboxing

### Option 1: App Sandbox (sandbox-exec)

Create `yakmesh.sb`:

```scheme
(version 1)
(deny default)

; Allow basic operations
(allow process-exec)
(allow process-fork)
(allow signal (target self))

; Network access
(allow network*)

; File access - read-only for code
(allow file-read* (subpath "/opt/yakmesh"))
(allow file-read* (subpath "/usr/local/lib/node_modules"))

; File access - read-write for data
(allow file-read* file-write* (subpath "/opt/yakmesh/data"))

; System libraries
(allow file-read* (subpath "/usr/lib"))
(allow file-read* (subpath "/System/Library"))

; Sysctl for system info
(allow sysctl-read)

; Mach IPC for Node.js
(allow mach-lookup)
```

Run:
```bash
sandbox-exec -f yakmesh.sb node /opt/yakmesh/server/index.js
```

### Option 2: launchd with sandboxing

Create `/Library/LaunchDaemons/com.yakmesh.node.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.yakmesh.node</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/node</string>
        <string>/opt/yakmesh/server/index.js</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/opt/yakmesh</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>UserName</key>
    <string>yakmesh</string>
    <key>GroupName</key>
    <string>yakmesh</string>
    <key>SandboxProfile</key>
    <string>/opt/yakmesh/yakmesh.sb</string>
</dict>
</plist>
```

Load:
```bash
sudo launchctl load /Library/LaunchDaemons/com.yakmesh.node.plist
```

## Best Practices

### 1. Create Dedicated User

```bash
# Linux
sudo useradd -r -s /bin/false -d /opt/yakmesh yakmesh
sudo chown -R yakmesh:yakmesh /opt/yakmesh

# macOS
sudo dscl . -create /Users/yakmesh
sudo dscl . -create /Users/yakmesh UserShell /usr/bin/false
```

### 2. Filesystem Permissions

```bash
# Code: read-only
chmod -R 555 /opt/yakmesh
chmod 755 /opt/yakmesh

# Data: read-write for service user only
chmod 700 /opt/yakmesh/data
chown yakmesh:yakmesh /opt/yakmesh/data

# Identity files: restrictive
chmod 400 /opt/yakmesh/data/machine-seed.json
chmod 600 /opt/yakmesh/data/node-key.json
```

### 3. Network Restrictions

Use iptables/nftables (Linux) or pf (macOS) to restrict network:

```bash
# Linux iptables - allow only HTTP, WebSocket, and bootstrap
iptables -A OUTPUT -p tcp --dport 3080 -j ACCEPT  # HTTP
iptables -A OUTPUT -p tcp --dport 9080 -j ACCEPT  # WebSocket
iptables -A OUTPUT -p tcp --dport 9081 -j ACCEPT  # LAN node
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT   # NTP
iptables -A OUTPUT -p tcp -j DROP                  # Block other TCP
```

### 4. Resource Limits

Use cgroups v2 (Linux) for fine-grained resource control:

```bash
# Create cgroup
sudo mkdir /sys/fs/cgroup/yakmesh
echo "+cpu +memory +io" | sudo tee /sys/fs/cgroup/cgroup.subtree_control

# Set limits
echo 200000 | sudo tee /sys/fs/cgroup/yakmesh/cpu.max  # 200% CPU
echo 2G | sudo tee /sys/fs/cgroup/yakmesh/memory.max   # 2GB RAM
```

## Integration with SANGHA

The sandboxing layer works WITH Yakmesh's built-in security:

| Layer | Responsibility |
|-------|----------------|
| **OS Sandbox** | Process isolation, syscall filtering, capability dropping |
| **SANGHA** | Collective attestation, anomaly detection |
| **FS Hardening** | File integrity, lock critical files |
| **Memory Safety** | Canary-based corruption detection |
| **Secure Config** | Oracle-attested configuration |

The OS sandbox is the outermost ring. If an attacker bypasses SANGHA and exploits a Node.js vulnerability, the OS sandbox prevents:
- Privilege escalation
- Access to system files
- Network pivoting
- Spawning new processes

## Monitoring

### Check sandbox status (Linux)
```bash
# systemd
systemctl status yakmesh
journalctl -u yakmesh -f

# Check security context
cat /proc/$(pgrep -f yakmesh)/status | grep -E 'Seccomp|Cap'
```

### Check sandbox status (macOS)
```bash
# launchd
sudo launchctl list | grep yakmesh

# Check sandbox violations
log show --predicate 'process == "sandboxd"' --last 1h
```

## Troubleshooting

### "Permission denied" errors
- Check file permissions: `ls -la /opt/yakmesh/data`
- Verify user context: `whoami` within sandbox
- Check seccomp logs: `dmesg | grep seccomp`

### Network connectivity issues
- Verify sandbox allows network: check profile allows `AF_INET`
- Check firewall rules: `iptables -L` or `pfctl -sr`

### Node.js features not working
- Some features require syscalls blocked by sandbox
- Adjust seccomp profile or sandbox rules as needed
- Test incrementally: start permissive, then restrict

## Recommended Configuration

For production deployment, combine:

1. **systemd sandboxing** (Linux) or **launchd + sandbox-exec** (macOS)
2. **Dedicated non-root user**
3. **Read-only filesystem** except `/data`
4. **Network firewall** limiting outbound
5. **Resource limits** via cgroups/launchd

This provides defense-in-depth when combined with Yakmesh's SANGHA collective security.
