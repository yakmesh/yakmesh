<?php
/**
 * SHERPA Dynamic Beacon Bridge
 * 
 * Proxies live beacon data from the yakmesh node to external crawlers.
 * Deployed at: https://yakmesh.dev/mesh/beacon.php
 * Rewritten from: /.well-known/yakmesh/beacon (via .htaccess)
 * 
 * Runs under LiteSpeed on port 443 — always reachable through firewalls.
 * Falls back to static beacon file if yakmesh node is down.
 */

header("Content-Type: application/json");
header("Cache-Control: public, max-age=60");
header("X-Sherpa-Version: 1.1");
header("X-Sherpa-Bridge: php");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Accept");

// Handle CORS preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

$backendUrl = "http://127.0.0.1:3080/.well-known/yakmesh/beacon";

$ch = curl_init($backendUrl);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 5);
curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Accept: application/json']);

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$error = curl_error($ch);
curl_close($ch);

if ($response !== false && $httpCode === 200) {
    echo $response;
} else {
    // Fallback: serve static beacon if yakmesh node is down
    $staticBeacon = dirname(__DIR__) . "/.well-known/yakmesh/beacon";
    if (file_exists($staticBeacon)) {
        $static = file_get_contents($staticBeacon);
        // Inject bridge metadata
        $data = json_decode($static, true);
        if ($data) {
            $data['_bridge'] = 'static-fallback';
            $data['_bridgeTs'] = time();
            echo json_encode($data);
        } else {
            echo $static;
        }
    } else {
        http_response_code(503);
        echo json_encode([
            "error" => "Yakmesh node unavailable",
            "fallback" => "no static beacon",
            "timestamp" => time()
        ]);
    }
}
