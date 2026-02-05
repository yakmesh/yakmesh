# YAKMESH v2.5.0 Roadmap

## Theme: "Geographic Exclusion — Physics Don't Lie"

**Target Release**: February 2026

This release adds geographic proof using speed-of-light physics:
- **RTT-based distance bounds** (minimum distance, not exact location)
- **Landmark trilateration** (exclusion zones from multiple reference points)
- **Time source integration** (precision timing = tighter bounds)

**"You can't be closer than light allows. Network latency only makes you appear farther."**

---

## 🎯 Core Principles

### Physics-Based Proof
- Speed of light in fiber: ~200,000 km/s (0.67c)
- Minimum distance = (RTT / 2) × fiber_speed
- Network overhead only INFLATES RTT, never reduces it

### What We CAN Prove
- ✅ "Node X is NOT within 500km of landmark Y" (exclusion)
- ✅ "Node X is consistent with being in region Z" (plausibility)
- ❌ "Node X is definitely at coordinates (lat, lon)" (NOT provable)

### Honest Limitations
- We prove **exclusion zones**, not exact location
- Network delays make nodes appear farther, never closer
- This is NOT quantum entanglement - it's classical physics

---

## 📐 Distance Precision by Time Source

| Time Source | RTT Precision | Distance Precision |
|-------------|---------------|-------------------|
| QUANTUM | ±1ms | ±1km |
| ATOMIC | ±100μs | ±10km |
| GPS/PTP | ±1ms | ±100km |
| NTP | ±10ms | ±1000km |

Higher precision timing → smaller error bars → better exclusion.

---

## 🏔️ Architecture

### Landmark Nodes
Well-known nodes with verified physical locations:
- ORACLE/ANCHOR tier nodes with GPS coordinates
- Distributed globally for coverage
- Operate SHERPA beacons for RTT measurement

### RTT Measurement
```javascript
import { measureRTT } from 'yakmesh/security/geo-proof';

const measurement = await measureRTT('https://landmark.yakmesh.dev/.well-known/yakmesh/beacon', {
  samples: 5,
  timeout: 10000,
});

console.log(`Min RTT: ${measurement.getMinRTT()}ms`);
console.log(`Reliable: ${measurement.isReliable()}`);
```

### Distance Calculation
```javascript
import { calculateMinDistance, LIGHT_SPEED } from 'yakmesh/security/geo-proof';

// RTT of 40ms via fiber
const minDistance = calculateMinDistance(40, 'FIBER');
// Result: 3997 km (node cannot be closer than this)
```

### Exclusion Zones
```javascript
import { ExclusionZone, GeographicProof } from 'yakmesh/security/geo-proof';

const zone = new ExclusionZone({
  landmarkId: 'landmark-nyc',
  landmarkName: 'NYC-ANCHOR-1',
  minDistanceKm: 4000,
  precisionKm: 100,
  rttMs: 40,
});

// Check if claimed location is possible
const result = zone.isExcluded({ lat: 40.7128, lon: -74.0060 }); // NYC coords
// Result: true (excluded - node claims to be in NYC but RTT proves >4000km away)
```

### Trilateration
With 3+ landmarks, we can narrow down possible regions:

```
Landmark A (NYC): RTT 20ms → max 2000km radius
Landmark B (London): RTT 80ms → max 8000km radius  
Landmark C (Tokyo): RTT 120ms → max 12000km radius

Intersection = possible location region
```

---

## ✅ Phase 1: Core Module (This Release)

### Files
- `security/geo-proof.js` - Core module ✅

### Features
1. **LandmarkRegistry** - Register/manage landmark nodes
2. **RTTMeasurement** - Measure RTT with statistical analysis
3. **ExclusionZone** - Physics-based distance bounds
4. **GeographicProof** - Aggregated proof from multiple landmarks
5. **GeoProofService** - Service class for integration

### Integration Points
- Uses `oracle/time-source.js` for precision timestamps
- Uses `security/trust-tier.js` for tier weights
- Exposes SHERPA-compatible beacon endpoints

---

## 🔜 Phase 2: KHATA Integration (v2.5.1)

### Gossip Messages
Add geo-proof messages to KHATA protocol:
- `GEO_PROOF_REQUEST` - Request proof from peer
- `GEO_PROOF_RESPONSE` - Share proof with peer
- `LANDMARK_ANNOUNCE` - Announce landmark status
- `LANDMARK_VERIFY` - Cross-verify landmark

### Trust Integration
- Geographic consistency as trust factor
- Peers with verified locations get trust bonus
- Inconsistent location claims trigger strikes

---

## 🔜 Phase 3: Dashboard & CLI (v2.5.2)

### Dashboard
- World map visualization of exclusion zones
- Landmark status indicators
- RTT heatmap to landmarks

### CLI Commands
```bash
yakmesh geo status           # Show current proof
yakmesh geo landmarks        # List known landmarks
yakmesh geo measure          # Trigger RTT measurement
yakmesh geo verify <coords>  # Check if coords are possible
```

---

## 📊 Test Plan

### Unit Tests
- Distance calculation accuracy
- Haversine distance formula
- Exclusion zone logic
- RTT statistics (min, median, stddev)

### Integration Tests
- RTT measurement with mock HTTP
- Landmark registry operations
- Proof generation and serialization

### Physics Verification
- Speed of light constants
- Fiber vs vacuum propagation
- Edge cases (same location, antipodal)

---

## 🔗 Dependencies (All Existing)

| Module | Usage |
|--------|-------|
| `oracle/time-source.js` | Precision timestamps |
| `security/trust-tier.js` | Tier weights |
| `mesh/sherpa-discovery.js` | Beacon endpoints |
| `security/khata-trust-integration.js` | Gossip layer |

No new dependencies required.

---

## 📈 Success Metrics

| Metric | Target |
|--------|--------|
| RTT measurement reliability | >95% samples succeed |
| Exclusion zone accuracy | ±10% of physics limit |
| Trilateration coverage | 3+ landmarks per node |
| Test coverage | >90% statements |

---

## 🚀 Migration Path

### From v2.4.0
1. No breaking changes
2. New `security/geo-proof.js` module
3. Optional integration with trust system
4. Landmarks can be added gradually

### Configuration
```javascript
// yakmesh.config.js
export default {
  geoProof: {
    enabled: true,
    landmarks: [
      { 
        name: 'NYC-ANCHOR-1', 
        endpoint: 'https://nyc.yakmesh.dev/.well-known/yakmesh/beacon',
        coordinates: { lat: 40.7128, lon: -74.0060 },
        region: 'NA-EAST',
      },
      // ... more landmarks
    ],
  },
};
```

---

## 📚 References

- Speed of light in fiber: https://en.wikipedia.org/wiki/Fiber-optic_communication
- Haversine formula: https://en.wikipedia.org/wiki/Haversine_formula
- One-way delay measurement: RFC 7679
- v2.4.0 trust tiers: [ROADMAP-2.4.0.md](./ROADMAP-2.4.0.md)

---

## 🏷️ Tags

#yakmesh #v2.5.0 #geo-proof #physics #rtt #trilateration #exclusion-zones
