/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * TRADEMARK NOTICE:
 * YAKMESH™ is a trademark of PeerQuanta, application pending (Serial No. 99594620).
 * Unauthorized use of the YAKMESH™ name, logo, or branding is strictly prohibited.
 *
 * LICENSE:
 * This Source Code Form is subject to the terms of the YAKMESH
 * NETWORK ENGINE LICENSE AGREEMENT, v. 1.0. If a copy of that
 * license agreement was not distributed with this file, You can
 * find a link to the license at https://yakmesh.dev/license
 *
 * This Source Code Form is "Incompatible With Secondary Licenses",
 * as defined by the YAKMESH NETWORK ENGINE LICENSE AGREEMENT, v. 1.0.
 *
 * "The standard is binary. The reality is ternary. The resonance is 432."
 */
// Yakmesh Production Configuration Reference
// ----------------------------------------------------------
// Not loaded at runtime (start.sh uses yakmesh.config.js).
// Kept for reference. This file IS oracle-hashed, so it must
// be byte-identical across all deployments.
// ----------------------------------------------------------
export default {
  node: {
    name: 'Yakmesh Node',
    region: 'production',
  },
  network: {
    httpPort: 3080,
    wsPort: 9080,
  },
  bootstrap: [
    'ws://156.67.75.34:9080',   // Hostinger VPS
  ],
  database: {
    path: './data/yakmesh.db',
    replication: { enabled: true, syncInterval: 5000 },
  },
  oracle: { timeSource: 'auto', phaseWindow: 30000 },
  annex: { enabled: true },
};
