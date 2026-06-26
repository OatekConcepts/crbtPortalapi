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
log_action("=== READ CLIENT ATTEMPT START ===");

// Fields to select — excludes password, token, and OTP columns
$fields = "c.id, c.organisation_id, o.name AS organisation_name, c.name, c.email, c.role, c.two_fa, c.created_at, c.updated_at";
$join   = "FROM clients c LEFT JOIN organisations o ON c.organisation_id = o.id";

try {
    // Authenticate request via JWT
    $decoded = authenticateRequest($conn);

    // Restrict to admins only
    requireAdminRole($decoded);

    // Read query params
    $id             = $_GET['id']              ?? null;
    $organisationId = $_GET['organisation_id'] ?? null;

    // Single client lookup by id
    if ($id !== null) {
        if (!ctype_digit((string) $id)) {
            echo generateResponse(false, "Invalid client id.", null, 400);
            closeConnection($conn);
            exit;
        }

        $id = (int) $id;
        $result = $conn->query("SELECT $fields $join WHERE c.id=$id AND c.soft_delete=0");

        if (!$result) {
            log_action("Read client query failed: " . $conn->error);
            echo generateResponse(false, "An error occured", null, 500);
            closeConnection($conn);
            exit;
        }

        if ($result->num_rows === 0) {
            log_action("Read client failed: id=$id not found");
            echo generateResponse(false, "Client not found.", null, 404);
            closeConnection($conn);
            exit;
        }

        $client = $result->fetch_assoc();
        log_action("Client retrieved successfully: id=$id");
        echo generateResponse(true, "Client retrieved successfully.", ["client" => $client], 200);
        closeConnection($conn);
        exit;
    }

    // Build WHERE clause — optionally filter by organisation
    $where = "WHERE c.soft_delete=0";
    if ($organisationId !== null) {
        if (!ctype_digit((string) $organisationId)) {
            echo generateResponse(false, "Invalid organisation_id.", null, 400);
            closeConnection($conn);
            exit;
        }
        $where .= " AND c.organisation_id=" . (int) $organisationId;
    }

    // Fetch all matching clients
    $result = $conn->query("SELECT $fields $join $where ORDER BY c.created_at DESC");

    if (!$result) {
        log_action("Read clients query failed: " . $conn->error);
        echo generateResponse(false, "An error occured", null, 500);
        closeConnection($conn);
        exit;
    }

    $clients = [];
    while ($row = $result->fetch_assoc()) {
        $clients[] = $row;
    }

    log_action("Clients retrieved successfully: count=" . count($clients));
    echo generateResponse(true, "Clients retrieved successfully.", ["clients" => $clients], 200);
} catch (\Throwable $e) {
    log_action("Read client exception: " . $e->getMessage());
    echo generateResponse(false, "An error occured", null, 500);
} finally {
    closeConnection($conn);
    log_action("=== READ CLIENT ATTEMPT END ===");
}
