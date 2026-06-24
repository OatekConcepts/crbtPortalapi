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
log_action("=== ADMIN TOGGLE 2FA ATTEMPT START ===");

try {
    // Authenticate admin
    $decoded = authenticateRequest($conn);

    // Only allow admin or super_admin
    requireAdminRole($decoded);

    $adminId = (int) $decoded['id'];

    $statusCheck = $conn->query("SELECT two_fa FROM admins WHERE id = $adminId AND soft_delete = 0");
    if (!$statusCheck || $statusCheck->num_rows === 0) {
        log_action("Toggle 2FA: admin not found id=$adminId");
        echo generateResponse(false, "Admin not found.", null, 404);
        closeConnection($conn);
        exit;
    }
    $current = $statusCheck->fetch_assoc();
    $newStatus = $current['two_fa'] == 1 ? 0 : 1;

    $updateSql = "UPDATE admins SET two_fa = $newStatus WHERE id = $adminId";
    if (!$conn->query($updateSql)) {
        log_action("Failed to toggle 2FA: " . $conn->error);
        throw new Exception("Failed to update 2FA setting.");
    }

    log_action("Admin 2FA toggled to $newStatus for id=$adminId");
    echo generateResponse(true, "Two-factor authentication " . ($newStatus ? "enabled" : "disabled") . ".", [
        'two_fa' => $newStatus
    ], 200);
} catch (\Throwable $e) {
    log_action("Admin toggle 2FA exception: " . $e->getMessage());
    echo generateResponse(false, "An error occurred: " . $e->getMessage(), null, 500);
} finally {
    closeConnection($conn);
    log_action("=== ADMIN TOGGLE 2FA ATTEMPT END ===");
}
