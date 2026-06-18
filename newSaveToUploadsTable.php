<?php

// --- PHP Configuration Settings ---
ini_set('memory_limit', '2G');
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// --- CORS Headers ---
$allowedOrigins = [
    "http://localhost:3000",
    "http://localhost:5173",
    "https://bulksms.approot.ng",
    "https://smsbulk.redpay.africa",
    "http://34.171.235.246",
    "http://34.122.234.98"
];

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $allowedOrigins)) {
    header("Access-Control-Allow-Origin: $origin");
    header("Access-Control-Allow-Credentials: true");
}
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// --- Load Dependencies ---
require './conn.php';
require './log.php';
require './jwt.php';
require './vendor/autoload.php';

use Box\Spout\Reader\Common\Creator\ReaderEntityFactory;

// Option 2: Multi-line pretty format (easier to read in logs)
log_action("INCOMING REQUEST: " .$_SERVER['REQUEST_METHOD']);
 
$contentType = $_SERVER['CONTENT_TYPE'] ?? '';
$input = file_get_contents('php://input');

// Initialize batch_id as null
$batch_id_check = null;




// --- Helper Functions ---
function dbValue($conn, $value)
{
    return ($value === null || $value === '') ? 'NULL' : "'" . $conn->real_escape_string($value) . "'";
}

function getRequestHeaders()
{
    if (function_exists('apache_request_headers')) return apache_request_headers();
    if (function_exists('getallheaders')) return getallheaders();

    $headers = [];
    foreach ($_SERVER as $key => $value) {
        if (strpos($key, 'HTTP_') === 0) {
            $headerName = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($key, 5)))));
            $headers[$headerName] = $value;
        }
    }

    if (!isset($headers['Authorization']) && isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
        $headers['Authorization'] = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
    }

    return $headers;
}

function validateJwtToken($token)
{
    try {
        $decoded = decodeJWT($token);
        return $decoded['id'] ?? null;
    } catch (Exception $e) {
        log_action("JWT decode failed: " . $e->getMessage());
        return null;
    }
}

function normalizePhoneNumber($number)
{
    $number = preg_replace('/[^0-9]/', '', $number);
    if (strlen($number) === 13 && strpos($number, '234') === 0) return '0' . substr($number, 3);
    if (strlen($number) === 11 && strpos($number, '0') === 0) return $number;
    if (strlen($number) >= 10) {
        if (strpos($number, '234') === 0) return strlen($number) === 13 ? '0' . substr($number, 3) : $number;
        if (strlen($number) === 10 && in_array(substr($number, 0, 2), ['70', '80', '81', '90', '91'])) return '0' . $number;
    }
    return $number;
}

// --- Main Execution ---
$conn = getConnection();
log_action("Database connection established.");

// JWT Authentication
$headers = getRequestHeaders();
if (!isset($headers['Authorization'])) {
    log_action("Authorization Header Missing");
    echo json_encode(['message' => "Authorization header is required", "status" => false]);
    closeConnection($conn);
    exit;
}

$authHeader = $headers['Authorization'];
$tokenParts = explode(' ', $authHeader);
if (count($tokenParts) !== 2 || strcasecmp($tokenParts[0], 'Bearer') !== 0) {
    log_action("Invalid Authorization Header Format");
    echo json_encode(['message' => "Invalid Authorization header. Expected format: 'Bearer <token>'", 'status' => false]);
    closeConnection($conn);
    exit;
}

$userId = validateJwtToken($tokenParts[1]);
if (!$userId) {
    echo json_encode(["status" => false, "message" => "Invalid or expired token"]);
    closeConnection($conn);
    exit;
}

// Fetch user info
$userResult = $conn->query("SELECT full_name FROM users WHERE id = '$userId' LIMIT 1");
if (!$userResult || $userResult->num_rows === 0) {
    log_action("Failed to fetch user info for ID: $userId");
    echo json_encode(["status" => false, "message" => "Failed to retrieve user info."]);
    closeConnection($conn);
    exit;
}
$userData = $userResult->fetch_assoc();
$fullName = $conn->real_escape_string($userData['full_name']);

log_action('about entering file side');
// --- Handle File Upload ---
if (isset($_FILES['file'])) {
      
	log_action(' coming in as new upload');
    // Validate required fields
    $requiredFields = ['ota_offer_text', 'campaign_name'];
    foreach ($requiredFields as $field) {
        if (empty($_POST[$field])) {
            echo json_encode(["status" => 400, "message" => ucfirst(str_replace('_', ' ', $field)) . " is required"]);
            closeConnection($conn);
            exit;
        }
    }

    // Process schedule times
    $scheduledAt = null;
    $endDate = null;

    log_action('about entering entering start_date side');
    if (!empty($_POST['start_date'])) {
        try {
            $date = new DateTime($_POST['start_date']);
            $scheduledAt = $date->format('Y-m-d H:i:s');
        } catch (Exception $e) {
            log_action("Invalid start_date format: " . ($_POST['start_date'] ?? 'NULL'));
        }
    }

    log_action('about entering entering end_date side');
    if (!empty($_POST['end_date'])) {
        try {
            $date = new DateTime($_POST['end_date']);
	    // Set time to end of day
            $date->setTime(23, 59, 59);
	    $endDate = $date->format('Y-m-d H:i:s');
        } catch (Exception $e) {
            log_action("Invalid end_date format: " . ($_POST['end_date'] ?? 'NULL'));
        }
    }

    
    // Validate file upload
    $file = $_FILES['file'];
    if ($file['error'] != UPLOAD_ERR_OK) {
        log_action("File upload failed. Error code: " . ($file['error'] ?? 'N/A'));
        echo json_encode(["status" => false, "message" => "File upload failed or no file selected."]);
        closeConnection($conn);
        exit;
    }

    $fileName = $file['name'];
    $fileTmp = $file['tmp_name'];
    $fileSize = $file['size'];
    $maxSize = 100 * 1024 * 1024; // 100 MB
    $allowedExtensions = ['csv', 'xls', 'xlsx', 'zip'];
    $fileExt = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));

    if ($fileSize > $maxSize) {
        log_action("File too large: $fileSize bytes. Max allowed: $maxSize bytes.");
        echo json_encode(["status" => false, "message" => "File too large (max 100MB)."]);
        closeConnection($conn);
        exit;
    }

    if (!in_array($fileExt, $allowedExtensions)) {
        log_action("Invalid file type: $fileExt");
        echo json_encode(["status" => false, "message" => "Invalid file type. Allowed: " . implode(', ', $allowedExtensions)]);
        closeConnection($conn);
        exit;
    }

    // Prepare upload directory
    $uploadDir = '/var/www/html/comviva/uploads/';
    if (!file_exists($uploadDir) && !mkdir($uploadDir, 0777, true)) {
        log_action("Failed to create upload directory: $uploadDir");
        echo json_encode(["status" => false, "message" => "Server error: Could not create upload directory."]);
        closeConnection($conn);
        exit;
    }

    // Generate unique filename
    $baseName = pathinfo($fileName, PATHINFO_FILENAME);
    $uniqueName = uniqid('upload_') . '_' . $baseName . '.' . $fileExt;
    $targetFile = $uploadDir . $uniqueName;

    if (!move_uploaded_file($fileTmp, $targetFile)) {
        log_action("Failed to move uploaded file. Temp: $fileTmp, Target: $targetFile");
        echo json_encode(["status" => false, "message" => "Failed to store uploaded file."]);
        closeConnection($conn);
        exit;
    }
    log_action("File moved to: $targetFile");

    // Insert initial record
    $batchId = $_POST['batch_id'] ?? '';
    $message = $_POST['ota_offer_text'] ?? '';
    $campaignName = $_POST['campaign_name'] ?? '';
    $otaConfirmation = $_POST['ota_confirm_text'] ?? '';
    $productId = $_POST['product_id'] ?? NULL;
    $policyId = $_POST['policy_id'] ?? NULL;
    $targetList = $_POST['target_list'] ?? NULL;

    $conn->set_charset("utf8mb4");
    $batchId = $conn->real_escape_string($batchId);
    $massage = $conn->real_escape_string($message);
    $campaignName = $conn->real_escape_string($campaignName);
    $otaConfirmation = $conn->real_escape_string($otaConfirmation);
    $productId = $conn->real_escape_string($productId);
    $policyId = $conn->real_escape_string($policyId);
    $targetList = $conn->real_escape_string($targetList);

    $query = "INSERT INTO uploaded_files (
        campaign_name, file_path, status, batch_id, full_name, user_id, 
        ota_confirmation, schedule_time, start_date, end_date, message, product_id, policy_id, target_list
    ) VALUES (
        " . dbValue($conn, $campaignName) . ",
        " . dbValue($conn, $targetFile) . ",
        '0',
        " . dbValue($conn, $batchId) . ",
        " . dbValue($conn, $fullName) . ",
        " . dbValue($conn, $userId) . ",
        " . dbValue($conn, $otaConfirmation) . ",
        " . ($scheduledAt ? dbValue($conn, $scheduledAt) : 'NULL') . ",
        " . ($scheduledAt ? dbValue($conn, $scheduledAt) : 'NULL') . ",
        " . ($endDate ? dbValue($conn, $endDate) : 'NULL') . ",
        " . dbValue($conn, $message) . ",
	" . dbValue($conn, $productId) . ",
	" . dbValue($conn, $policyId) . ",
	" . dbValue($conn, $targetList) . "
    )";

    if (!$conn->query($query)) {
        log_action("Initial DB insert FAILED: " . $conn->error . " Query: " . $query);
        echo json_encode(["status" => false, "message" => "Failed to queue file for processing (initial DB insert failed)."]);
        closeConnection($conn);
        exit;
    }

    $uploadedFileId = $conn->insert_id;
    echo json_encode([
        "status" => true,
        "message" => "File uploaded and queued for processing. You will be notified upon completion.",
        "file" => basename($targetFile),
        "uploaded_file_id" => $uploadedFileId
    ]);

    // Start background processing
    if (function_exists('fastcgi_finish_request')) fastcgi_finish_request();

    // Process file in background
    processUploadedFile($conn, $targetFile, $uploadedFileId, $fileExt);
    closeConnection($conn);
    exit;
} else {
	log_action(' coming in as existing upload');
    // Handle batch update without file upload
    handleBatchUpdate($conn, $userId, $fullName);
    closeConnection($conn);
    exit;
}

// --- Background Processing Function ---
function processUploadedFile($conn, $filePath, $fileId, $fileExt)
{
    log_action("Background processing started for file ID: $fileId");

    try {
        // Convert XLSX to CSV if needed
        if ($fileExt === 'xlsx') {
            $filePath = convertXlsxToCsv($conn, $filePath, $fileId);
        } else {
            normalizeLineEndings($filePath);
        }

        // Process phone numbers
        $phoneStats = processPhoneNumbers($filePath);

        // Update database with results
        $updateQuery = "UPDATE uploaded_files SET
            status = '0',
            total_count = " . (int)$phoneStats['total'] . ",
            total_distinct = " . (int)$phoneStats['unique'] . "
            WHERE id = '$fileId'";

        if (!$conn->query($updateQuery)) {
            log_action("Failed to update file stats: " . $conn->error);
            $conn->query("UPDATE uploaded_files SET status = '6' WHERE id = '$fileId'");
        }

        log_action("Background processing completed for file ID: $fileId");
    } catch (Exception $e) {
        log_action("Background processing failed: " . $e->getMessage());
        $conn->query("UPDATE uploaded_files SET status = '5' WHERE id = '$fileId'");
    }
}

function convertXlsxToCsv($conn, $xlsxPath, $fileId)
{
    log_action("Converting XLSX to CSV: $xlsxPath");

    $reader = ReaderEntityFactory::createXLSXReader();
    $reader->open($xlsxPath);

    $csvFilename = pathinfo($xlsxPath, PATHINFO_FILENAME) . '.csv';
    $csvPath = dirname($xlsxPath) . '/' . $csvFilename;
    $csvHandle = fopen($csvPath, 'w');

    foreach ($reader->getSheetIterator() as $sheet) {
        foreach ($sheet->getRowIterator() as $row) {
            $cells = $row->toArray();
            if (array_filter($cells, fn($v) => trim($v) !== '') !== []) {
                fputcsv($csvHandle, $cells);
            }
        }
        break; // Only first sheet
    }

    fclose($csvHandle);
    $reader->close();

    if (file_exists($xlsxPath)) unlink($xlsxPath);

    $escapedPath = $conn->real_escape_string($csvPath);
    $conn->query("UPDATE uploaded_files SET file_path = '$escapedPath' WHERE id = '$fileId'");

    normalizeLineEndings($csvPath);
    return $csvPath;
}

function normalizeLineEndings($filePath)
{
    $contents = file_get_contents($filePath);
    $normalized = preg_replace("/\r\n?/", "\n", $contents);
    file_put_contents($filePath, $normalized);
}

function processPhoneNumbers($filePath)
{
    $frequency = [];
    $total = 0;
    $phoneColumnIndex = null;

    $csvHandle = fopen($filePath, 'r');
    if ($csvHandle === false) throw new Exception("Failed to open CSV file");

    // Detect phone column
    $headerRow = fgetcsv($csvHandle);
    if ($headerRow === false) throw new Exception("Empty CSV file");

    foreach ($headerRow as $index => $columnName) {
        if (preg_match('/phone|mobile|contact|number/i', $columnName)) {
            $phoneColumnIndex = $index;
            break;
        }
    }
    if ($phoneColumnIndex === null) $phoneColumnIndex = 0;

    // Process rows
    while (($row = fgetcsv($csvHandle)) !== false) {
        if (!isset($row[$phoneColumnIndex]) || trim($row[$phoneColumnIndex]) === '') continue;

        $normalized = normalizePhoneNumber(trim($row[$phoneColumnIndex]));
        if ($normalized === '') continue;

        $total++;
        $frequency[$normalized] = ($frequency[$normalized] ?? 0) + 1;
    }

    fclose($csvHandle);

    return [
        'total' => $total,
        'unique' => count($frequency),
        'duplicates' => $total - count($frequency)
    ];
}

function handleBatchUpdate($conn, $userId, $fullName)
{
    $data = stripos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== false
        ? json_decode(file_get_contents('php://input'), true)
        : $_POST;

    // Validate required fields
    $requiredFields = ['batch_id', 'old_batch_id'];
    foreach ($requiredFields as $field) {
        if (empty($data[$field])) {
            echo json_encode(['status' => false, 'message' => "Missing required field: $field"]);
            return;
        }
    }
	
    // Escape input data
    $conn->set_charset("utf8mb4");
    $batchId = $conn->real_escape_string($data['batch_id']);
    $oldBatchId = $conn->real_escape_string($data['old_batch_id']);
    $message = $conn->real_escape_string($data['ota_offer_text'] ?? '');
    $campaignName = $conn->real_escape_string($data['campaign_name'] ?? '');
    $otaConfirmation = $conn->real_escape_string($data['ota_confirm_text'] ?? '');
    $productId = $conn->real_escape_string($data['product_id'] ?? '');
    $msgCat = $conn->real_escape_string($data['msg_cat'] ?? '');
    $policyId = $conn->real_escape_string($data['policy_id'] ?? NULL);
    $targetList = $conn->real_escape_string($data['target_list'] ?? NULL);

    // Process schedule times
    $scheduledAt = null;
    $endDate = null;

    if (!empty($data['start_date'])) {
        try {
            $date = new DateTime($data['start_date']);
            $scheduledAt = $date->format('Y-m-d H:i:s');
        } catch (Exception $e) {
            log_action("Invalid start_date format: " . ($data['start_date'] ?? 'NULL'));
        }
    }

    if (!empty($data['end_date'])) {
        try {
            $date = new DateTime($data['end_date']);
            $endDate = $date->format('Y-m-d H:i:s');
        } catch (Exception $e) {
            log_action("Invalid end_date format: " . ($data['end_date'] ?? 'NULL'));
        }
    }

    // Get existing record
    $selectQuery = "SELECT file_path, total_count, total_distinct 
                   FROM uploaded_files 
                   WHERE batch_id = '$oldBatchId' 
                   LIMIT 1";

    $result = $conn->query($selectQuery);
    if (!$result || $result->num_rows === 0) {
        log_action("No record found for batch ID $oldBatchId");
        echo json_encode(['status' => false, 'message' => 'Original batch not found']);
        return;
    }

    $existing = $result->fetch_assoc();

    // Create new record
    $query = "INSERT INTO uploaded_files (
        campaign_name, file_path, status, batch_id, full_name, user_id, 
        ota_confirmation, schedule_time, start_date, end_date, message,
        msg_cat, total_count, total_distinct, product_id, policy_id, target_list
    ) VALUES (
        " . dbValue($conn, $campaignName) . ",
        " . dbValue($conn, $existing['file_path']) . ",
        '0',
        " . dbValue($conn, $batchId) . ",
        " . dbValue($conn, $fullName) . ",
        " . dbValue($conn, $userId) . ",
        " . dbValue($conn, $otaConfirmation) . ",
        " . ($scheduledAt ? dbValue($conn, $scheduledAt) : 'NULL') . ",
        " . ($scheduledAt ? dbValue($conn, $scheduledAt) : 'NULL') . ",
        " . ($endDate ? dbValue($conn, $endDate) : 'NULL') . ",
        " . dbValue($conn, $message) . ",
        " . dbValue($conn, $msgCat) . ",
        " . (int)$existing['total_count'] . ",
        " . (int)$existing['total_distinct'] . ",
	" . dbValue($conn, $productId) . ",
	" . dbValue($conn, $policyId) . ",
	" . dbValue($conn, $targetList) . "
    )";

	 log_action('query');
log_action($query);
    if (!$conn->query($query)) {
        log_action("Insert failed: " . $conn->error);
        echo json_encode(['status' => false, 'message' => 'Update failed: ' . $conn->error]);
        return;
    }

    $newId = $conn->insert_id;
    echo json_encode([
        'status' => true,
        'message' => 'Your Campaigne has been queued for processing. You will be notified upon completion.',
        'uploaded_file_id' => $newId,
        'batch_id' => $batchId
    ]);
}
