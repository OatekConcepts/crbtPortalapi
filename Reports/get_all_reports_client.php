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
log_action("=== CLIENT GET REPORTS ATTEMPT START ===");

try {
    // Authenticate client (JWT must exist and be valid)
    $decoded = authenticateRequest($conn);

    // Ensure the user is a client (role = 'user')
    if (!isset($decoded['role']) || $decoded['role'] !== 'user') {
        log_action("Client get reports blocked: invalid role " . ($decoded['role'] ?? 'none'));
        echo generateResponse(false, "Access denied.", null, 403);
        closeConnection($conn);
        exit;
    }

    $clientId = (int) $decoded['id'];

    // Fetch client details to get organisation_id and name
    $clientResult = $conn->query("SELECT id, organisation_id, name FROM clients WHERE id = $clientId");
    if (!$clientResult || $clientResult->num_rows === 0) {
        log_action("Client get reports blocked: client id=$clientId not found");
        echo generateResponse(false, "Invalid client token.", null, 401);
        closeConnection($conn);
        exit;
    }
    $client = $clientResult->fetch_assoc();
    $clientOrgId = (int) $client['organisation_id'];
    $clientName = $client['name'];

    // verify organisation exists
    $orgCheck = $conn->query("SELECT id FROM organisations WHERE id = $clientOrgId");
    if (!$orgCheck || $orgCheck->num_rows === 0) {
        log_action("Client get reports blocked: organisation_id=$clientOrgId not found");
        echo generateResponse(false, "Your organisation is invalid.", null, 400);
        closeConnection($conn);
        exit;
    }


    // Parse query parameters (for pagination)

    $limit = isset($_GET['limit']) ? (int) $_GET['limit'] : 50;
    $offset = isset($_GET['offset']) ? (int) $_GET['offset'] : 0;

    // Allow using 'page' instead of offset (optional)
    if (isset($_GET['page'])) {
        $page = (int) $_GET['page'];
        $limit = isset($_GET['limit']) ? (int) $_GET['limit'] : 50;
        $offset = ($page - 1) * $limit;
    }

    // Force filter by client's organisation – no other filters allowed
    $whereClause = "WHERE ru.organisation_id = $clientOrgId";


    // Build the main query (join with upload, org, category)

    $sql = "SELECT 
                r.*,
                ru.id AS upload_id,
                ru.name AS upload_name,
                ru.filename,
                ru.file_path,
                ru.month,
                ru.year,
                ru.gross_revenue,
                ru.revenue_ex_vat,
                ru.revenue_share_percentage,
                ru.revenue_share_amount,
                ru.uploaded_at,
                ru.status AS upload_status,
                org.id AS organisation_id,
                org.name AS organisation_name,
                cat.id AS category_id,
                cat.name AS category_name
            FROM reports r
            INNER JOIN report_uploads ru ON r.report_upload_id = ru.id
            LEFT JOIN organisations org ON ru.organisation_id = org.id
            LEFT JOIN categories cat ON ru.category_id = cat.id
            $whereClause
            ORDER BY r.id DESC
            LIMIT $limit OFFSET $offset";

    $result = $conn->query($sql);
    if (!$result) {
        log_action("Query failed: " . $conn->error);
        throw new Exception("Database error: " . $conn->error);
    }

    $reports = [];
    while ($row = $result->fetch_assoc()) {
        $reports[] = $row;
    }


    // Get total count (for pagination)

    $countSql = "SELECT COUNT(*) AS total FROM reports r 
                 INNER JOIN report_uploads ru ON r.report_upload_id = ru.id
                 $whereClause";
    $countResult = $conn->query($countSql);
    $total = $countResult ? (int) $countResult->fetch_assoc()['total'] : 0;


    // Audit log (optional – you can enable if needed)

    try {
        audit_log($conn, $clientId, $clientName, "Fetched reports (total: $total) for org $clientOrgId", 1);
    } catch (\Throwable $e) {
        log_action("Audit log call failed: " . $e->getMessage());
    }

    log_action("Client get reports successful: client_id=$clientId, org=$clientOrgId, returned " . count($reports) . " records out of $total total.");
    echo generateResponse(true, "Reports retrieved successfully.", [
        'reports' => $reports,
        'total'   => $total,
        'limit'   => $limit,
        'offset'  => $offset
    ], 200);
} catch (\Throwable $e) {
    log_action("Client get reports exception: " . $e->getMessage());
    echo generateResponse(false, "An error occurred: " . $e->getMessage(), null, 500);
} finally {
    if (isset($conn)) closeConnection($conn);
    log_action("=== CLIENT GET REPORTS ATTEMPT END ===");
}
