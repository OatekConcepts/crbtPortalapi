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


// Helper: Send OTP SMS


function sendMadApiSMS($msisdn, $request_id, $message)
{
    $url = "https://prod5-nigeria.api.mtn.com/v3/sms/messages/sms/outbound";
    $body = [
        "senderAddress" => "COMVIVA",
        "receiverAddress" => [$msisdn],
        "clientCorrelatorId" => $request_id,
        "keyword" => "OTP",
        "serviceCode" => "13111",
        "requestDeliveryReceipt" => false,
        "message" => $message
    ];

    $headers = [
        'x-api-key: S0DfNdzydE9Ae1KRif8kVqIsd6YgZTLQ',
        'Content-Type: application/json'
    ];

    $curl = curl_init();
    curl_setopt_array($curl, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_ENCODING => '',
        CURLOPT_MAXREDIRS => 10,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_SSL_VERIFYHOST => 0,
        CURLOPT_SSL_VERIFYPEER => 0,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
        CURLOPT_CUSTOMREQUEST => 'POST',
        CURLOPT_POSTFIELDS => json_encode($body),
        CURLOPT_HTTPHEADER => $headers
    ]);

    $response = curl_exec($curl);
    $err = curl_error($curl);
    curl_close($curl);

    if ($err) {
        return [
            'success' => false,
            'error' => $err
        ];
    } else {
        return [
            'success' => true,
            'response' => json_decode($response, true)
        ];
    }
}





function sendSms($to, $text, $from = '39602', $smsc = '500') {
    $username = 'tester';
    $password = 'foobar';
    $baseUrl = 'http://10.128.0.13:13013/cgi-bin/sendsms';

    // Build query parameters
    $queryParams = http_build_query([
        'username' => $username,
        'password' => $password,
        'from'     => $from,
        'to'       => $to,
        'text'     => $text,
        'smsc'     => $smsc
    ]);

    // Full URL
    $url = "$baseUrl?$queryParams";

    // Initialize cURL
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

    // Execute request
    $response = curl_exec($ch);
    $error = curl_error($ch);
    // curl_close($ch);

    // Return response or error
    if ($error) {
        return "cURL Error: $error";
    }

    return $response;
}



// Helper: Send OTP Mail

function sendMail($otp, $email)
{
    // require_once './PHPMailer/PHPMailer.php';
    // require_once './PHPMailer/SMTP.php';
    // require_once './PHPMailer/Exception.php';

    require_once __DIR__ . '/PHPMailer/PHPMailer.php';
    require_once __DIR__ . '/PHPMailer/SMTP.php';
    require_once __DIR__ . '/PHPMailer/Exception.php';

    $mail = new PHPMailer\PHPMailer\PHPMailer(true);

    try {
        // Server settings
        $mail->isSMTP();
        $mail->Host       = 'email-smtp.us-east-1.amazonaws.com';
        $mail->SMTPAuth   = true;
        $mail->Username   = 'AKIAX7YTA767FYW7IXJO';
        $mail->Password   = 'BHcB+rfmYUOHkYwa94z3t/BdUM+7VmVD4ux8Eo14x/js';
        $mail->SMTPSecure = 'tls'; // use 'ssl' if using port 465
        $mail->Port       = 587;

        // Sender and recipient
        $mail->setFrom('mail@redtechlimited.com', 'RedTech');
        $mail->addAddress($email); // recipient address

        // Email content
        $mail->isHTML(true);
        $mail->Subject = '🔐 Login OTP';
        $mail->Body    = "
            <html><body style='font-family: Arial, sans-serif; background-color: #f9f9f9; padding: 20px; margin: 0;'>
                <div style='max-width: 600px; margin: 40px auto; background-color: #ffffff; padding: 30px; border-radius: 10px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);'>
                    <h2 style='color: #e11d48; text-align: center;'>🔐  Your Secure Login OTP</h2>
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

function sendMails($otp, $email)
{
    $status = "<html><body style='font-family: Arial, sans-serif; background-color: #f9f9f9; padding: 20px; margin: 0;'>
    <div style='max-width: 600px; margin: 40px auto; background-color: #ffffff; padding: 30px; border-radius: 10px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);'>
      <h2 style='color: #e11d48; text-align: center;'>🔐 Your Secure Login OTP</h2>
      <p style='font-size: 16px; color: #333;'>Dear User,</p>
      <p style='font-size: 15px; color: #555; line-height: 1.6;'>
        For your security, <strong>never share your OTP</strong> with anyone.
        Use this code to complete your login on the official platform.
      </p>
      <div style='text-align: center; margin: 30px 0;'>
        <span style='display: inline-block; background-color: #f3f4f6; color: #111827; font-size: 32px; letter-spacing: 5px; padding: 15px 30px; border-radius: 8px; font-weight: bold; border: 1px dashed #e11d48;'>
          $otp
        </span>
      </div>
      <p style='font-size: 14px; color: #999; text-align: center;'>
        This OTP expires in 10 minutes. If this wasn't you, please ignore this email.
      </p>
    </div></body></html>";

    $data = [
        'From' => 'support@ringo.ng',
        'To' => $email,
        'Subject' => 'Login OTP',
        'HtmlBody' => $status,
    ];
    $json = json_encode($data);

    $ch = curl_init('https://api.postmarkapp.com/email');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
    curl_setopt($ch, CURLOPT_POSTFIELDS, $json);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'X-Postmark-Server-Token: 8d7b61f4-10ae-4949-824c-b53a47b17e7b',
        'Content-Type: application/json',
        'Accept: application/json'
    ]);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);

    $result = curl_exec($ch);
    $response = json_decode($result, true);
    // curl_close($ch);

    if (isset($response['MessageID'])) {
        log_action("Email sent: " . print_r($response, true));
        return true;
    } else {
        log_action("Email send failed: " . $result);
        return false;
    }
}

