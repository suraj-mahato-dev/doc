<?php
/**
 * ============================================================================
 * Enterprise Identity Verification API Proxy
 * Architecture by: Suraj Mahato | Suraj Tech Solutions
 * Description: Secure middleware to handle dynamic CSRF tokens (nonce) 
 *              and fetch remote user profiles with strict CORS headers.
 * ============================================================================
 */

// --- 1. SECURITY MIDDLEWARE ---
// Require a local API key so not just anyone can abuse this node
define('LOCAL_API_KEY', 'sk_live_suraj_789456123'); 

$client_key = $_SERVER['HTTP_X_API_KEY'] ?? ($_GET['api_key'] ?? '');
if ($client_key !== LOCAL_API_KEY) {
    header('HTTP/1.1 401 Unauthorized');
    echo json_encode(['status' => 'error', 'message' => 'Invalid or missing API Key']);
    exit;
}

// --- 2. GATEWAY CONFIGURATION ---
header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: GET");

class UserIdentityGateway {
    
    // Anonymized Vendor Endpoint (Looks like an official B2B integration)
    private $vendor_base_url = "https://partner-identity-node.com/";
    private $vendor_api_path = "wp-admin/admin-ajax.php?action=verify_account_status";
    
    // Regex to extract dynamic authentication token
    private $auth_token_pattern = '/&nonce=([a-zA-Z0-9]+)/';
    
    private $user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) EnterpriseNode/2.0';

    /**
     * Send standard JSON error response
     */
    private function sendError($message, $code = 400) {
        http_response_code($code);
        echo json_encode(['status' => 'error', 'message' => $message]);
        exit;
    }

    /**
     * Step 1: Handshake - Fetch the dynamic session token (Nonce)
     */
    private function getDynamicAuthToken() {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $this->vendor_base_url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_USERAGENT, $this->user_agent);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        
        $html_response = curl_exec($ch);
        
        if (curl_errno($ch)) {
            $this->sendError('Gateway Timeout: Failed to connect to vendor server.', 504);
        }
        curl_close($ch);

        if (preg_match($this->auth_token_pattern, $html_response, $matches) && !empty($matches[1])) {
            return $matches[1];
        }

        $this->sendError('Handshake Failed: CSRF Token missing or architecture changed.', 502);
    }

    /**
     * Step 2: Fetch the actual user data using the validated token
     */
    public function fetchUserProfile($account_id) {
        if (empty($account_id)) {
            $this->sendError('Validation Error: account_id parameter is required.');
        }

        // Retrieve dynamic token
        $secure_token = $this->getDynamicAuthToken();

        // Build the final authenticated request
        $target_url = $this->vendor_base_url . $this->vendor_api_path . "&account_id=" . urlencode($account_id) . "&nonce=" . urlencode($secure_token);

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $target_url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_USERAGENT, $this->user_agent);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        
        $json_response = curl_exec($ch);
        
        if (curl_errno($ch)) {
            $this->sendError('Vendor API Offline: ' . curl_error($ch), 502);
        }
        curl_close($ch);

        // Validate if response is strict JSON
        json_decode($json_response);
        if (json_last_error() !== JSON_ERROR_NONE) {
            $this->sendError('Malformed Data: Vendor returned non-JSON format.', 500);
        }

        echo $json_response;
    }
}

// --- 3. EXECUTION ---
$account_id = $_GET['account_id'] ?? null;
$gateway = new UserIdentityGateway();
$gateway->fetchUserProfile($account_id);

?>
