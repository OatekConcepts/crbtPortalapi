<?php

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require_once __DIR__ . '/../utils/response.php';
include '../utils/utilityFunctions.php';

setCorsHeaders();

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    setCorsHeaders();
    http_response_code(200);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    echo generateResponse(false, "Method not allowed. Use GET.", null, 405);
    exit;
}

require_once __DIR__ . '/../utils/conn.php';
require_once __DIR__ . '/../log.php';
require_once __DIR__ . '/../jwt.php';

$conn = getConnection();
log_action("=== DASHBOARD ANALYTICS ATTEMPT START ===");

try {
    // Authenticate request via JWT
    $decoded = authenticateRequest($conn);

    // Restrict to admins only (admin or super_admin)
    requireAdminRole($decoded);

    // Total organisations (soft_delete not used in organisations)
    $orgResult = $conn->query("SELECT COUNT(*) AS total FROM organisations");
    if (!$orgResult) {
        throw new Exception("Failed to count organisations: " . $conn->error);
    }
    $totalOrganisations = (int) $orgResult->fetch_assoc()['total'];

    // Clients – total, active (soft_delete=0), inactive (soft_delete=1)
    $clientResult = $conn->query("
        SELECT 
            COUNT(*) AS total,
            SUM(CASE WHEN soft_delete = 0 THEN 1 ELSE 0 END) AS active,
            SUM(CASE WHEN soft_delete = 1 THEN 1 ELSE 0 END) AS inactive
        FROM clients
    ");
    if (!$clientResult) {
        throw new Exception("Failed to count clients: " . $conn->error);
    }
    $clientData = $clientResult->fetch_assoc();
    $totalClients   = (int) $clientData['total'];
    $activeClients  = (int) $clientData['active'];
    $inactiveClients = (int) $clientData['inactive'];

    // Admins (soft_delete=0)
    $adminResult = $conn->query("SELECT COUNT(*) AS total FROM admins WHERE soft_delete = 0");
    if (!$adminResult) {
        throw new Exception("Failed to count admins: " . $conn->error);
    }
    $totalAdmins = (int) $adminResult->fetch_assoc()['total'];

    // Total categories
    $catResult = $conn->query("SELECT COUNT(*) AS total FROM categories");
    if (!$catResult) {
        throw new Exception("Failed to count categories: " . $conn->error);
    }
    $totalCategories = (int) $catResult->fetch_assoc()['total'];

    // Report uploads today (based on created_at)
    $today = date('Y-m-d');
    $uploadResult = $conn->query("
        SELECT COUNT(*) AS total 
        FROM report_uploads 
        WHERE DATE(created_at) = '$today'
    ");
    if (!$uploadResult) {
        throw new Exception("Failed to count today's uploads: " . $conn->error);
    }
    $uploadsToday = (int) $uploadResult->fetch_assoc()['total'];

    // Build response
    $data = [
        'total_organisations' => $totalOrganisations,
        'total_clients'       => $totalClients,
        'active_clients'      => $activeClients,
        'inactive_clients'    => $inactiveClients,
        'total_admins'        => $totalAdmins,
        'total_categories'    => $totalCategories,
        'uploads_today'       => $uploadsToday,
    ];

    log_action("Dashboard analytics retrieved successfully.");
    echo generateResponse(true, "Dashboard analytics retrieved successfully.", $data, 200);
} catch (\Throwable $e) {
    log_action("Dashboard analytics error: " . $e->getMessage());
    echo generateResponse(false, "An error occurred: " . $e->getMessage(), null, 500);
} finally {
    closeConnection($conn);
    log_action("=== DASHBOARD ANALYTICS ATTEMPT END ===");
}
