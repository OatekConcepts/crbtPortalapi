<?php

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require_once __DIR__ . '/../utils/response.php';
include '../utils/utilityFunctions.php';


// Set CORS and content-type headers
setCorsHeaders();

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    setCorsHeaders();
    http_response_code(200);
    exit;
}

// Reject non-GET requests
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    echo generateResponse(false, "Method not allowed. Use GET.", null, 405);
    exit;
}

require_once __DIR__ . '/../utils/conn.php';
require_once __DIR__ . '/../log.php';
require_once __DIR__ . '/../jwt.php';

// Open DB connection
$conn = getConnection();
log_action("=== CLIENT ME ATTEMPT START ===");

try {
    // Authenticate request via JWT
    $decoded = authenticateRequest($conn);

    // Restrict to user role only
    requireRole($decoded, 'user');

    // Extract caller id from token
    $id = (int) $decoded['id'];

    // Fetch client record — exclude soft-deleted accounts
    $result = $conn->query(
        "SELECT c.id, c.organisation_id, o.name AS organisation_name, c.name, c.email, c.role, c.two_fa, c.token
         FROM clients c
         LEFT JOIN organisations o ON c.organisation_id = o.id
         WHERE c.id=$id AND c.soft_delete=0"
    );

    if (!$result) {
        log_action("Client me query failed: " . $conn->error);
        echo generateResponse(false, "An error occured", null, 500);
        closeConnection($conn);
        exit;
    }

    if ($result->num_rows === 0) {
        log_action("Client me failed: id=$id not found or deleted");
        echo generateResponse(false, "User not found.", null, 404);
        closeConnection($conn);
        exit;
    }

    $user = $result->fetch_assoc();
    log_action("Client me retrieved successfully: id=$id");

    echo generateResponse(true, "User retrieved successfully.", [
        "token" => $user['token'],
        "user"  => [
            "id"                => $user['id'],
            "organisation_id"   => $user['organisation_id'],
            "organisation_name" => $user['organisation_name'],
            "name"              => $user['name'],
            "email"             => $user['email'],
            "role"              => $user['role'],
            "two_fa"            => (int) $user['two_fa']
        ]
    ], 200);
} catch (\Throwable $e) {
    log_action("Client me exception: " . $e->getMessage());
    echo generateResponse(false, "An error occured", null, 500);
} finally {
    closeConnection($conn);
    log_action("=== CLIENT ME ATTEMPT END ===");
}
