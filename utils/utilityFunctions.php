<?php

function setCorsHeaders()
{
    header("Access-Control-Allow-Origin: *");
    header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE");
    header("Access-Control-Allow-Headers: Content-Type, Authorization");
    header("Access-Control-Allow-Credentials: true");
    header("Content-Type: application/json");
}

function getHeaders()
{
    if (function_exists('apache_request_headers')) {
        return apache_request_headers();
    } elseif (function_exists('getallheaders')) {
        return getallheaders();
    } else {
        $headers = [];
        foreach ($_SERVER as $key => $value) {
            if (strpos($key, 'HTTP_') === 0) {
                $headerName = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($key, 5)))));
                $headers[$headerName] = $value;
            }
        }
        return $headers;
    }
}

function getRequestBody()
{
    $data = json_decode(file_get_contents("php://input"), true);
    if (!$data) {
        $data = $_REQUEST;
    }
    return $data;
}

function authenticateRequest($conn)
{
    $headers = getHeaders();

    if (!isset($headers['Authorization'])) {
        log_action("Auth blocked: Authorization header missing");
        echo generateResponse(false, "Authorization header is required", null, 400);
        closeConnection($conn);
        exit;
    }

    $authParts = explode(' ', $headers['Authorization']);

    if (count($authParts) !== 2 || strcasecmp($authParts[0], 'Bearer') !== 0) {
        log_action("Auth blocked: invalid Authorization header format");
        echo generateResponse(false, "Invalid Authorization header. Expected format: 'Bearer <token>'", null, 400);
        closeConnection($conn);
        exit;
    }

    $decoded = decodeJWT($authParts[1]);

    if (!$decoded || !isset($decoded['id']) || !isset($decoded['role'])) {
        log_action("Auth blocked: invalid or expired token");
        echo generateResponse(false, "Invalid or expired token.", null, 401);
        closeConnection($conn);
        exit;
    }

    log_action("Authorized caller: id={$decoded['id']} role={$decoded['role']}");
    return $decoded;
}

function requireRole($decoded, $role)
{
    if ($decoded['role'] !== $role) {
        log_action("Auth blocked: caller id={$decoded['id']} role={$decoded['role']} is not authorized");
        echo generateResponse(false, "You are not authorized to perform this action.", null, 403);
        exit;
    }
}

function getBaseUrl($url)
{
    $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
    $host   = strtolower((string) parse_url($url, PHP_URL_HOST));
    $host   = preg_replace('/^www\./i', '', $host);
    return $scheme && $host ? "$scheme://$host" : null;
}

function requireAdminRole($decoded)
{
    if (!in_array($decoded['role'], ['admin', 'super_admin'])) {
        log_action("Auth blocked: caller id={$decoded['id']} role={$decoded['role']} is not an admin");
        echo generateResponse(false, "You are not authorized to perform this action.", null, 403);
        exit;
    }
}

function getLogMessage($key, $context = [])
{
    $name = isset($context['name']) ? ' ' . $context['name'] : '';
    $messages = [
        "createdAdmin" => "Created admin{$name}",
        "updatedAdmin" => "Updated admin{$name}",
        "deletedAdmin" => "Deleted admin{$name}",
        "createdOrganisation" => "Created organisation{$name}",
        "updatedOrganisation" => "Updated organisation{$name}",
        "deletedOrganisation" => "Deleted organisation{$name}",
        "createdCategory" => "Created category{$name}",
        "updatedCategory" => "Updated category{$name}",
        "deletedCategory" => "Deleted category{$name}",
        "createdClient" => "Created client{$name}",
        "updatedClient" => "Updated client{$name}",
        "deletedClient" => "Deleted client{$name}",
        "login" => "Logged in",
        "clientLoggedIn" => "Logged in"
    ];
    return $messages[$key] ?? $key;
}



// Helper: Send OTP Mail

function sendMails($otp, $email)
{

    //correct path
     require_once __DIR__ . '/../vendor/phpmailer/phpmailer/src/PHPMailer.php';
    require_once __DIR__ . '/../vendor/phpmailer/phpmailer/src/SMTP.php';
    require_once __DIR__ . '/../vendor/phpmailer/phpmailer/src/Exception.php';

    $mail = new PHPMailer\PHPMailer\PHPMailer(true);

    try {
        // Server settings
        $mail->isSMTP();
        $mail->Host       = '';
        $mail->SMTPAuth   = true;
        $mail->Username   = '';
        $mail->Password   = '';
        $mail->SMTPSecure = ''; 
        $mail->Port       = '';

        // Sender and recipient
        $mail->setFrom('');
        $mail->addAddress($email); // recipient address

        // Email content
        $mail->isHTML(true);
        $mail->Subject = 'Login OTP';
        $mail->Body    = "
            <html><body style='font-family: Arial, sans-serif; background-color: #f9f9f9; padding: 20px; margin: 0;'>
                <div style='max-width: 600px; margin: 40px auto; background-color: #ffffff; padding: 30px; border-radius: 10px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);'>
                    <h2 style='color: #e11d48; text-align: center;'>  Your Secure Login OTP</h2>
                    <p style='font-size: 16px; color: #333;'>Dear User,</p>
                    <p style='font-size: 15px; color: #555; line-height: 1.6;'>For your security, <strong>never share your OTP</strong> with anyone. Use this code to complete your login on the official platform.</p>
                    <div style='text-align: center; margin: 30px 0;'>
                        <span style='display: inline-block; background-color: #f3f4f6; color: #111827; font-size: 32px; letter-spacing: 5px; padding: 15px 30px; border-radius: 8px; font-weight: bold; border: 1px dashed #e11d48;'>
                            $otp
                        </span>
                    </div>
                    <p style='font-size: 14px; color: #999; text-align: center;'>This OTP expires in 10 minutes. If this wasn't you, please ignore this email.</p>
                </div>
            </body></html>
        ";

        $mail->AltBody = "Your OTP is: $otp";

        $mail->send();
        log_action("PHPMailer: OTP email sent to $email");
        return true;
    } catch (PHPMailer\PHPMailer\Exception $e) {
        log_action("PHPMailer Error: " . $mail->ErrorInfo);
        return false;
    }
}


// Helper: Generate 6-digit OTP
function generateRandomNumbersString()
{
    return str_pad(rand(0, 999999), 6, '0', STR_PAD_LEFT);
}


