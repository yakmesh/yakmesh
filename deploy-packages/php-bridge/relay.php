<?php
/**
 * SHERPA HTTP Mesh Relay Bridge
 * 
 * Bridges mesh traffic through HTTPS (port 443) when WebSocket is firewalled.
 * External nodes POST messages here; PHP forwards them to localhost:3080/mesh/relay.
 * 
 * Message flow:
 *   Remote Node → POST https://yakmesh.dev/mesh/relay.php → PHP → http://127.0.0.1:3080/mesh/relay
 *   Remote Node ← JSON response with outbound messages ← PHP ← yakmesh response
 * 
 * This creates a store-and-forward bridge: not real-time like WebSocket,
 * but functional through any firewall that allows HTTPS.
 */

header("Content-Type: application/json");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Accept, X-Yakmesh-NodeId");
header("X-Sherpa-Bridge: php-relay");

// CORS preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

$backendBase = "http://127.0.0.1:3080";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Forward relay POST to yakmesh node
    $input = file_get_contents('php://input');
    
    if (empty($input)) {
        http_response_code(400);
        echo json_encode(["error" => "Empty request body"]);
        exit;
    }
    
    // Validate JSON
    $decoded = json_decode($input, true);
    if ($decoded === null) {
        http_response_code(400);
        echo json_encode(["error" => "Invalid JSON"]);
        exit;
    }
    
    // Rate limit: simple per-IP throttle (60 requests/minute)
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $rateLimitFile = sys_get_temp_dir() . "/yakmesh_relay_" . md5($ip);
    $now = time();
    $window = 60;
    $maxRequests = 60;
    
    $requests = [];
    if (file_exists($rateLimitFile)) {
        $requests = json_decode(file_get_contents($rateLimitFile), true) ?? [];
        $requests = array_filter($requests, function($ts) use ($now, $window) {
            return ($now - $ts) < $window;
        });
    }
    
    if (count($requests) >= $maxRequests) {
        http_response_code(429);
        echo json_encode(["error" => "Rate limit exceeded", "retryAfter" => $window]);
        exit;
    }
    
    $requests[] = $now;
    file_put_contents($rateLimitFile, json_encode(array_values($requests)));
    
    // Forward to yakmesh
    $ch = curl_init("$backendBase/mesh/relay");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $input);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        'Accept: application/json',
        'X-Forwarded-For: ' . $ip,
    ]);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    
    if ($response !== false && $httpCode >= 200 && $httpCode < 300) {
        echo $response;
    } else {
        http_response_code(502);
        echo json_encode([
            "error" => "Backend unavailable",
            "httpCode" => $httpCode,
            "timestamp" => time()
        ]);
    }
    
} elseif ($_SERVER['REQUEST_METHOD'] === 'GET') {
    // Poll for outbound messages
    $nodeId = $_GET['nodeId'] ?? $_SERVER['HTTP_X_YAKMESH_NODEID'] ?? null;
    
    if (!$nodeId) {
        http_response_code(400);
        echo json_encode(["error" => "nodeId query parameter required"]);
        exit;
    }
    
    // URL-encode nodeId for safe path interpolation
    $safeNodeId = urlencode($nodeId);
    
    $ch = curl_init("$backendBase/mesh/relay/$safeNodeId");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($response !== false && $httpCode === 200) {
        echo $response;
    } else {
        http_response_code(502);
        echo json_encode(["error" => "Backend unavailable", "timestamp" => time()]);
    }
}
