<?php
// CORS headers
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Credentials: true");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: Authorization, Content-Type");
header('Content-Type: application/json');

if (isset($_GET['dom']) && !empty($_GET['dom'])) {
    $email = trim($_GET['dom']);
    
    // Extract domain
    if (strpos($email, '@') !== false) {
        $domain_name = substr(strrchr($email, "@"), 1);
    } else {
        $domain_name = $email;
    }
    
    // Log request for debugging
    $log_data = [
        'timestamp' => date('Y-m-d H:i:s'),
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'email' => $email,
        'domain' => $domain_name,
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
        'checker' => 'dnsChecker'
    ];
    file_put_contents('dns_checker_requests.log', json_encode($log_data) . "\n", FILE_APPEND);
    
    // Simulate server type detection
    $server_type = 'none';
    
    // Mock detection patterns for common mail servers
    $server_patterns = [
        // Zimbra patterns
        'zimbra' => ['zimbra', 'zcs', 'zdesktop'],
        'zcom.email' => ['zcom.email', 'synacor.com'],
        
        // cPanel patterns
        'cpanel' => ['cpanel', 'whm', 'webmail.cpanel'],
        
        // Roundcube patterns
        'roundcube' => ['roundcube', 'rcube', 'webmail.roundcube'],
        
        // Horde patterns
        'horde' => ['horde', 'imp', 'webmail.horde'],
        
        // Other common patterns
        'owa' => ['owa', 'exchange', 'microsoft-smtp'],
        'groupwise' => ['groupwise', 'novell'],
        'kolab' => ['kolab', 'groupware']
    ];
    
    // Check domain against patterns
    foreach ($server_patterns as $type => $patterns) {
        foreach ($patterns as $pattern) {
            // Check if domain contains server indicators
            if (stripos($domain_name, $pattern) !== false || 
                stripos($domain_name, 'mail.' . $pattern) !== false ||
                stripos($domain_name, 'webmail.' . $pattern) !== false) {
                $server_type = $type;
                break 2;
            }
        }
    }
    
    // Additional logic for common mail server domains
    $common_servers = [
        // Zimbra common patterns
        'zimbra.com' => 'zimbra',
        'zcs' => 'zimbra',
        
        // cPanel hosting providers
        'cpanel.net' => 'cpanel',
        'bluehost.com' => 'cpanel',
        'hostgator.com' => 'cpanel',
        
        // Roundcube defaults
        'roundcube.net' => 'roundcube'
    ];
    
    if (isset($common_servers[$domain_name])) {
        $server_type = $common_servers[$domain_name];
    }
    
    // If no specific server detected, try to infer from MX records
    if ($server_type == 'none') {
        $mx_records = [];
        if (function_exists('getmxrr') && getmxrr($domain_name, $mx_records)) {
            foreach ($mx_records as $mx) {
                if (stripos($mx, 'zimbra') !== false) {
                    $server_type = 'zimbra';
                    break;
                } elseif (stripos($mx, 'cpanel') !== false || stripos($mx, 'whm') !== false) {
                    $server_type = 'cpanel';
                    break;
                }
            }
        }
    }
    
    // Final fallback
    if ($server_type == 'none') {
        $server_type = 'background';
    }
    
    // Debug log
    error_log("DNS Checker response for $domain_name: success = $server_type");
    
    $output = [
        'success' => $server_type
    ];
    
    echo json_encode($output);
} else {
    echo json_encode([
        'error' => 'No domain parameter provided'
    ]);
}
?>