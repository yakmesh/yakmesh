# 🏔️ YAKMESH v2.5.0 — Geographic Exclusion: Physics Don't Lie

Hey Sherpas! 👋

**Version 2.5.0 is here** and it brings something incredible: **speed-of-light geographic proof**.

---

## 🌍 What's Geographic Exclusion?

Ever wanted to **prove** where a node is located without GPS? Now you can — using physics!

**The concept is simple:**
- Light in fiber optic cables travels at ~200,000 km/s (0.67c)
- Round-trip time (RTT) to a landmark gives us **minimum distance**
- If RTT is 40ms, the node **cannot** be closer than ~4,000 km

**We prove where nodes CANNOT be, not precise location.**

---

## ✨ New Features

### 🔬 Speed-of-Light Physics
```
RTT 1ms → ≥100 km
RTT 10ms → ≥1,000 km
RTT 100ms → ≥10,000 km
```

### 🏔️ Landmark Registry
SHERPA beacons now serve as geographic landmarks. Trilaterate from multiple landmarks for tighter exclusion zones.

### 🖥️ CLI Commands
```bash
yakmesh geo status      # Current proof status
yakmesh geo landmarks   # List known landmarks
yakmesh geo prove       # Generate proof
yakmesh geo verify <id> # Verify another node
yakmesh geo physics     # Show constants
```

### 🔌 API Endpoints
- `GET /geo/status` - Proof status
- `GET /geo/landmarks` - Known landmarks
- `POST /geo/prove` - Generate proof
- `POST /geo/verify` - Verify claims

---

## 📊 By the Numbers

- **732+ tests** passing
- **104 new tests** for geo-proof
- **0 GPS required** — pure physics
- **1 formula**: `minDistance = (RTT / 2) × fiberSpeed`

---

## 🚀 Upgrade Now

```bash
npm install yakmesh@2.5.0
```

---

💬 Questions? Ask in #support
🐛 Found a bug? Report in #bug-reports

*Physics is the ultimate validator.* 🌌

— The YAKMESH Team
