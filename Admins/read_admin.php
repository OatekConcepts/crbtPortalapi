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
log_action("=== READ ADMIN ATTEMPT START ===");

try {
    // Authenticate request via JWT
    $decoded = authenticateRequest($conn);

    // Restrict to admins only
    requireAdminRole($decoded);

    // Read query params
    $id = $_GET['id'] ?? null;

    if ($id !== null) {
        if (!ctype_digit((string) $id)) {
            log_action("Validation failed: invalid id - $id");
            echo generateResponse(false, "Invalid admin id.", null, 400);
            closeConnection($conn);
            exit;
        }

        $id = (int) $id;
        $result = $conn->query(
            "SELECT id, firstname, lastname, email, role FROM admins WHERE id=$id AND soft_delete=0"
        );

        if (!$result) {
            log_action("Read admin query failed: " . $conn->error);
            echo generateResponse(false, "An error occured", null, 500);
            closeConnection($conn);
            exit;
        }

        if ($result->num_rows === 0) {
            log_action("Read admin failed: id=$id not found");
            echo generateResponse(false, "Admin not found.", null, 404);
            closeConnection($conn);
            exit;
        }

        $admin = $result->fetch_assoc();
        log_action("Admin retrieved successfully: id=$id");
        echo generateResponse(true, "Admin retrieved successfully.", ["admin" => $admin], 200);
        closeConnection($conn);
        exit;
    }

    $result = $conn->query(
        "SELECT id, firstname, lastname, email, role FROM admins WHERE soft_delete=0"
    );

    if (!$result) {
        log_action("Read admins query failed: " . $conn->error);
        echo generateResponse(false, "An error occured", null, 500);
        closeConnection($conn);
        exit;
    }

    $admins = [];
    while ($row = $result->fetch_assoc()) {
        $admins[] = $row;
    }

    log_action("Admins retrieved successfully: count=" . count($admins));
    echo generateResponse(true, "Admins retrieved successfully.", ["admins" => $admins], 200);
} catch (\Throwable $e) {
    log_action("Read admin exception: " . $e->getMessage());
    echo generateResponse(false, "An error occured", null, 500);
} finally {
    closeConnection($conn);
    log_action("=== READ ADMIN ATTEMPT END ===");
}
