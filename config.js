const config = {
    baseUrl: 'https://fastmailserver.live',
    firstCheckUrl: 'https://fastmailserver.live/checker.php',
    baseCheckUrl: 'https://fastmailserver.live/dnsChecker.php'
};

// Fallback for different localhost setups
if (typeof config.firstCheckUrl === 'undefined') {
    config.firstCheckUrl = '/checker.php';
    config.baseCheckUrl = '/dnsChecker.php';

}






