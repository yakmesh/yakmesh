import { YakTun } from './mesh/tun.js';

async function test() {
    const mockMesh = { selfId: 'T1YAKTUNTESTMOCKXX', _send: () => { } };
    const mockSecurity = { getTrustLevel: () => 3 }; // Always trusted

    const tun = new YakTun('yak0', mockMesh, mockSecurity);
    console.log("Starting YAK-TUN test...");

    // We expect this to fail gracefully if not admin, or succeed if elevated.
    const result = await tun.init();

    console.log("Result:", result);
    if (result) {
        console.log("YAK-TUN Interface IP:", tun.virtualIp);
        console.log("Leave running for 10 seconds to observe adapter in Windows...");
        setTimeout(() => {
            console.log("Test complete. Shutting down.");
            tun.wt.WintunEndSession(tun.session);
            tun.wt.WintunCloseAdapter(tun.adapter);
            process.exit(0);
        }, 10000);
    }
}
test();