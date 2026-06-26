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
log_action("=== READ ORGANISATION ATTEMPT START ===");

try {
    // Authenticate request via JWT
    $decoded = authenticateRequest($conn);

    // Restrict to admins only
    requireAdminRole($decoded);

    // Read query params
    $id = $_GET['id'] ?? null;

    // Single organisation lookup by id
    if ($id !== null) {
        if (!ctype_digit((string) $id)) {
            log_action("Validation failed: invalid id - $id");
            echo generateResponse(false, "Invalid organisation id.", null, 400);
            closeConnection($conn);
            exit;
        }

        $id = (int) $id;
        $result = $conn->query(
            "SELECT id, name, email, url, created_at, updated_at FROM organisations WHERE id=$id"
        );

        if (!$result) {
            log_action("Read organisation query failed: " . $conn->error);
            echo generateResponse(false, "An error occured", null, 500);
            closeConnection($conn);
            exit;
        }

        if ($result->num_rows === 0) {
            log_action("Read organisation failed: id=$id not found");
            echo generateResponse(false, "Organisation not found.", null, 404);
            closeConnection($conn);
            exit;
        }

        $organisation = $result->fetch_assoc();
        log_action("Organisation retrieved successfully: id=$id");
        echo generateResponse(true, "Organisation retrieved successfully.", ["organisation" => $organisation], 200);
        closeConnection($conn);
        exit;
    }

    // Fetch all organisations
    $result = $conn->query(
        "SELECT id, name, email, url, created_at, updated_at FROM organisations"
    );

    if (!$result) {
        log_action("Read organisations query failed: " . $conn->error);
        echo generateResponse(false, "An error occured", null, 500);
        closeConnection($conn);
        exit;
    }

    $organisations = [];
    while ($row = $result->fetch_assoc()) {
        $organisations[] = $row;
    }

    log_action("Organisations retrieved successfully: count=" . count($organisations));
    echo generateResponse(true, "Organisations retrieved successfully.", ["organisations" => $organisations], 200);
} catch (\Throwable $e) {
    log_action("Read organisation exception: " . $e->getMessage());
    echo generateResponse(false, "An error occured", null, 500);
} finally {
    closeConnection($conn);
    log_action("=== READ ORGANISATION ATTEMPT END ===");
}
