// AWS
rule AWS_Secret_Access_Key {
    meta:
        description = "AWS Secret Access Key"
    strings:
        $aws_secret = /AKIA[0-9A-Z]{16}/
        $aws_secret2 = /ASIA[0-9A-Z]{16}/
        $aws_secret3 = /A3T[A-Z0-9]{16}/
    condition:
        any of them
}

rule AWS_Secret_Key {
    meta:
        description = "AWS Secret Key (40 chars)"
    strings:
        $aws_key = /[A-Za-z0-9\/+=]{40}/
    condition:
        $aws_key
}

// Azure
rule Azure_Client_Secret {
    meta:
        description = "Azure Client Secret"
    strings:
        $az1 = /[a-z0-9]{32}\.[a-z0-9\-]{6,}\.[a-z0-9\-]{27}/
    condition:
        $az1
}

// Google
rule Google_API_Key {
    meta:
        description = "Google API Key"
    strings:
        $gapi = /AIza[0-9A-Za-z\-_]{35}/
    condition:
        $gapi
}

// Slack
rule Slack_Token {
    meta:
        description = "Slack Token"
    strings:
        $slack1 = /xox[baprs]-([0-9a-zA-Z]{10,48})?/
    condition:
        $slack1
}

// Stripe
rule Stripe_Secret_Key {
    meta:
        description = "Stripe Secret Key"
    strings:
        $stripe1 = /sk_live_[0-9a-zA-Z]{24}/
        $stripe2 = /sk_test_[0-9a-zA-Z]{24}/
    condition:
        any of them
}

// GitHub
rule GitHub_Token {
    meta:
        description = "GitHub Personal Access Token"
    strings:
        $ghp = /ghp_[A-Za-z0-9]{36}/
    condition:
        $ghp
}

// JWT
rule JWT_Token {
    meta:
        description = "JWT token string"
    strings:
        $jwt = /eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/
    condition:
        $jwt
}

// Private Keys
rule Private_Key_Block {
    meta:
        description = "Private key PEM block"
    strings:
        $pem1 = "-----BEGIN PRIVATE KEY-----"
        $pem2 = "-----BEGIN RSA PRIVATE KEY-----"
        $pem3 = "-----BEGIN DSA PRIVATE KEY-----"
        $pem4 = "-----BEGIN EC PRIVATE KEY-----"
        $pem5 = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $pem6 = "-----BEGIN ENCRYPTED PRIVATE KEY-----"
    condition:
        any of them
}

// SSH
rule SSH_Pub_Key {
    meta:
        description = "SSH Public Key"
    strings:
        $ssh1 = "ssh-rsa"
        $ssh2 = "ssh-ed25519"
        $ssh3 = "ecdsa-sha2-nistp256"
        $ssh4 = "ecdsa-sha2-nistp384"
        $ssh5 = "ecdsa-sha2-nistp521"
    condition:
        any of them
}

// Database URIs
rule Database_URI {
    meta:
        description = "Database URI (Postgres, MySQL, Mongo, etc)"
    strings:
        $pg = /postgres:\/\/[A-Za-z0-9:_\-]+@[A-Za-z0-9.:-]+\/[A-Za-z0-9_\-]+/
        $my = /mysql:\/\/[A-Za-z0-9:_\-]+@[A-Za-z0-9.:-]+\/[A-Za-z0-9_\-]+/
        $mg = /mongodb:\/\/[A-Za-z0-9:_\-]+@[A-Za-z0-9.:-]+\/[A-Za-z0-9_\-]+/
    condition:
        any of them
}

// Generic Passwords
rule Generic_Password {
    meta:
        description = "Generic password assignment or variable"
    strings:
        $pw1 = /password\s*[=:]\s*[^\s]+/ nocase
        $pw2 = /passwd\s*[=:]\s*[^\s]+/ nocase
        $pw3 = /pwd\s*[=:]\s*[^\s]+/ nocase
        $pw4 = /secret\s*[=:]\s*[^\s]+/ nocase
        $pw5 = /token\s*[=:]\s*[^\s]+/ nocase
        $pw6 = /api[_-]?key\s*[=:]\s*[^\s]+/ nocase
    condition:
        any of them
}

// Email
rule Email_Address {
    meta:
        description = "Email address"
    strings:
        $email = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/
    condition:
        $email
}

// Google OAuth
rule Google_OAuth_Refresh_Token {
    meta:
        description = "Google OAuth Refresh Token"
    strings:
        $refresh = /1\/[A-Za-z0-9\-_]{43}/
    condition:
        $refresh
}

// Facebook Access Token
rule Facebook_Access_Token {
    meta:
        description = "Facebook Access Token"
    strings:
        $fb = /EAACEdEose0cBA[0-9A-Za-z]+/
    condition:
        $fb
}

// Heroku API Key
rule Heroku_API_Key {
    meta:
        description = "Heroku API Key"
    strings:
        $heroku = /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/
    condition:
        $heroku
}

// DigitalOcean Token
rule DigitalOcean_Token {
    meta:
        description = "DigitalOcean Token"
    strings:
        $do = /dop_v1_[a-z0-9]{64}/
    condition:
        $do
}

// Generic API Key
rule Generic_API_Key {
    meta:
        description = "Generic API Key (32+ chars, alphanumeric)"
    strings:
        $api = /[A-Za-z0-9]{32,}/
    condition:
        $api
} 