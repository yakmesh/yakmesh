<?php
/**
 * YAKMESH Node API Proxy
 * Forwards requests to local Node.js server
 * https://yakmesh.dev/node.php?e=health
 */

header("Content-Type: application/json");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");

// Handle preflight
if ($_SERVER["REQUEST_METHOD"] === "OPTIONS") {
    http_response_code(200);
    exit;
}

// Get the endpoint from query string
$endpoint = isset($_GET["e"]) ? $_GET["e"] : "health";

// Whitelist allowed endpoints
$allowed = [
    "health", 
    "node", 
    "peers", 
    "oracle/status", 
    "network/status", 
    "network/identity", 
    "time/status",
    "gossip",
    "discovered"
];

if (!in_array($endpoint, $allowed)) {
    http_response_code(400);
    echo json_encode(["error" => "Invalid endpoint"]);
    exit;
}

// Forward to local Node.js server
$url = "http://127.0.0.1:3000/" . $endpoint;

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 5);
curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 2);

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$error = curl_error($ch);
curl_close($ch);

if ($response === false) {
    http_response_code(503);
    echo json_encode([
        "error" => "Node unavailable",
        "details" => $error
    ]);
    exit;
}

http_response_code($httpCode);
echo $response;
