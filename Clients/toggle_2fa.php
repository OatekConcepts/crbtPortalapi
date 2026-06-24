<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require_once __DIR__ . '/../utils/response.php';
require_once __DIR__ . '/../utils/utilityFunctions.php';

setCorsHeaders();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo generateResponse(false, "Method not allowed. Use POST.", null, 405);
    exit;
}

require_once __DIR__ . '/../utils/conn.php';
require_once __DIR__ . '/../log.php';
require_once __DIR__ . '/../jwt.php';

$conn = getConnection();
log_action("=== CLIENT TOGGLE 2FA ATTEMPT START ===");

try {
    // Authenticate the client
    $decoded = authenticateRequest($conn);

    // Ensure role is 'user'
    if (!isset($decoded['role']) || $decoded['role'] !== 'user') {
        log_action("Toggle 2FA blocked: invalid role " . ($decoded['role'] ?? 'none'));
        echo generateResponse(false, "Access denied. Client role required.", null, 403);
        closeConnection($conn);
        exit;
    }

    $clientId = (int) $decoded['id'];

    // Get current two_fa status
    $statusCheck = $conn->query("SELECT two_fa FROM clients WHERE id = $clientId AND soft_delete = 0");
    if (!$statusCheck || $statusCheck->num_rows === 0) {
        log_action("Toggle 2FA: client not found id=$clientId");
        echo generateResponse(false, "Client not found.", null, 404);
        closeConnection($conn);
        exit;
    }
    $current = $statusCheck->fetch_assoc();
    $newStatus = $current['two_fa'] == 1 ? 0 : 1;

    // Update
    $updateSql = "UPDATE clients SET two_fa = $newStatus WHERE id = $clientId";
    if (!$conn->query($updateSql)) {
        log_action("Failed to toggle 2FA: " . $conn->error);
        throw new Exception("Failed to update 2FA setting.");
    }

    log_action("2FA toggled to $newStatus for client id=$clientId");
    echo generateResponse(true, "Two-factor authentication " . ($newStatus ? "enabled" : "disabled") . ".", [
        'two_fa' => $newStatus
    ], 200);
} catch (\Throwable $e) {
    log_action("Toggle 2FA exception: " . $e->getMessage());
    echo generateResponse(false, "An error occurred: " . $e->getMessage(), null, 500);
} finally {
    closeConnection($conn);
    log_action("=== CLIENT TOGGLE 2FA ATTEMPT END ===");
}
