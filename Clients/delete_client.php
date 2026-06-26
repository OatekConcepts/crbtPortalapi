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

// Reject non-POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo generateResponse(false, "Method not allowed. Use POST.", null, 405);
    exit;
}

require_once __DIR__ . '/../utils/conn.php';
require_once __DIR__ . '/../log.php';
require_once __DIR__ . '/../jwt.php';

// Open DB connection
$conn = getConnection();
log_action("=== DELETE CLIENT ATTEMPT START ===");

try {
    // Authenticate request via JWT
    $decoded = authenticateRequest($conn);

    // Restrict to super_admin only
    requireRole($decoded, 'super_admin');

    // Read request body
    $data = getRequestBody();
    log_action("Raw Input Data: " . json_encode($data));

    $targetId = isset($data['id']) ? (int) $data['id'] : 0;

    // Validate target id
    if (!$targetId) {
        echo generateResponse(false, "Client id is required.", null, 400);
        closeConnection($conn);
        exit;
    }

    // Verify client exists and is not already deleted
    $checkResult = $conn->query("SELECT name FROM clients WHERE id=$targetId AND soft_delete=0");

    if (!$checkResult) {
        log_action("Delete client check query failed: " . $conn->error);
        echo generateResponse(false, "An error occured", null, 500);
        closeConnection($conn);
        exit;
    }

    if ($checkResult->num_rows === 0) {
        log_action("Delete client failed: id=$targetId not found");
        echo generateResponse(false, "Client not found.", null, 404);
        closeConnection($conn);
        exit;
    }

    $client = $checkResult->fetch_assoc();
    $clientName = $client['name'];

    // Soft-delete the client
    if (!$conn->query("UPDATE clients SET soft_delete=1, updated_at=NOW() WHERE id=$targetId")) {
        log_action("Delete client query failed: " . $conn->error);
        echo generateResponse(false, "An error occured", null, 500);
        closeConnection($conn);
        exit;
    }

    log_action("Client soft-deleted successfully: id=$targetId ($clientName) by caller id={$decoded['id']}");

    // Fetch caller info for audit log
    $callerId = (int) $decoded['id'];
    $callerResult = $conn->query("SELECT firstname, lastname FROM admins WHERE id=$callerId");
    if ($callerResult && $callerResult->num_rows > 0) {
        $caller = $callerResult->fetch_assoc();
        $callerFullName = $caller['firstname'] . ' ' . $caller['lastname'];
        try {
            // Write to activity log
            audit_log($conn, $callerId, $callerFullName, getLogMessage('deletedClient', ['name' => $clientName]), 1);
        } catch (\Throwable $e) {
            log_action("Audit log call failed: " . $e->getMessage());
        }
    }

    echo generateResponse(true, "Client deleted successfully.", null, 200);
} catch (\Throwable $e) {
    log_action("Delete client exception: " . $e->getMessage());
    echo generateResponse(false, "An error occured", null, 500);
} finally {
    closeConnection($conn);
    log_action("=== DELETE CLIENT ATTEMPT END ===");
}
