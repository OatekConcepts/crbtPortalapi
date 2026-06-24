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
log_action("=== CLIENT FORGOT PASSWORD ATTEMPT START ===");

try {
    $data = getRequestBody();
    log_action("Raw Input: " . json_encode($data));

    $email = trim($data['email'] ?? '');
    if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        log_action("Validation failed: invalid email");
        echo generateResponse(false, "Valid email is required.", null, 400);
        closeConnection($conn);
        exit;
    }

    // Check client exists and not soft-deleted
    $clientCheck = $conn->query("SELECT id, name FROM clients WHERE email = '$email' AND soft_delete = 0");
    if (!$clientCheck || $clientCheck->num_rows === 0) {
        log_action("Forgot password: email not found - $email");
        // Return generic message for security 
        echo generateResponse(true, "If the email exists, an OTP has been sent.", null, 200);
        closeConnection($conn);
        exit;
    }
    $client = $clientCheck->fetch_assoc();

    // Generate OTP
    $otp = generateRandomNumbersString(); // 6-digit
    $otpExpires = date('Y-m-d H:i:s', strtotime('+10 minutes'));

    // Store OTP in DB
    $updateSql = "UPDATE clients SET otp = '$otp', otp_expires_at = '$otpExpires', otp_attempts = 0 WHERE id = {$client['id']}";
    if (!$conn->query($updateSql)) {
        log_action("Failed to update OTP: " . $conn->error);
        throw new Exception("Failed to process request.");
    }

    // Send OTP via email
    $subject = "Password Reset OTP";
    $message = "Your OTP for password reset is: $otp. It expires in 10 minutes.";
    $mailSent = sendMails($otp, $email); // Using your existing function to send mail

    if (!$mailSent) {
        log_action("Failed to send OTP email to $email");
        // Still return success to avoid leaking info, but log the error
    }

    log_action("Forgot password OTP sent to email: $email");
    echo generateResponse(true, "If the email exists, an OTP has been sent.", null, 200);
} catch (\Throwable $e) {
    log_action("Forgot password exception: " . $e->getMessage());
    echo generateResponse(false, "An error occurred: " . $e->getMessage(), null, 500);
} finally {
    closeConnection($conn);
    log_action("=== CLIENT FORGOT PASSWORD ATTEMPT END ===");
}
