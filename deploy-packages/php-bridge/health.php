<?php
/**
 * Yakmesh Health Bridge
 * 
 * Proxies health check to the local yakmesh node.
 * Useful for monitoring and SHERPA liveness checks.
 */

header("Content-Type: application/json");
header("Cache-Control: no-cache");
header("Access-Control-Allow-Origin: *");

$ch = curl_init("http://127.0.0.1:3080/health");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 3);
curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 2);

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($response !== false && $httpCode === 200) {
    echo $response;
} else {
    http_response_code(503);
    echo json_encode([
        "status" => "bridge-only",
        "node" => "unavailable",
        "bridge" => "php",
        "timestamp" => time()
    ]);
}
