"""Remediation guidance for each secret type."""

REMEDIATION_MAP: dict[str, str] = {
    # AWS
    "aws-access-key": (
        "1. Go to AWS IAM Console: https://console.aws.amazon.com/iam/\n"
        "2. Find the access key under your user's Security Credentials\n"
        "3. Deactivate the compromised key immediately\n"
        "4. Create a new access key pair\n"
        "5. Update all services using the old key\n"
        "6. Delete the old key after confirming nothing breaks\n"
        "7. Use AWS Secrets Manager or environment variables instead of hardcoding"
    ),
    "aws-secret-key": (
        "1. Immediately rotate the AWS access key pair in IAM Console\n"
        "2. Check CloudTrail for unauthorized usage\n"
        "3. Use AWS Secrets Manager or SSM Parameter Store for secrets\n"
        "4. Enable MFA on the AWS account"
    ),
    "aws-session-token": (
        "1. Session tokens are temporary but may still grant access\n"
        "2. Revoke the associated IAM role session if possible\n"
        "3. Check CloudTrail for any unauthorized actions"
    ),

    # GCP
    "gcp-api-key": (
        "1. Go to Google Cloud Console > APIs & Services > Credentials\n"
        "2. Delete or restrict the compromised API key\n"
        "3. Create a new key with appropriate API restrictions\n"
        "4. Add IP or referrer restrictions to the new key"
    ),
    "gcp-service-account": (
        "1. Go to Google Cloud Console > IAM & Admin > Service Accounts\n"
        "2. Delete the compromised key from the service account\n"
        "3. Create a new key and distribute securely\n"
        "4. Audit all actions performed with the compromised key"
    ),
    "gcp-oauth-client": (
        "1. Go to Google Cloud Console > APIs & Services > Credentials\n"
        "2. Reset the OAuth client secret\n"
        "3. Update all applications using this client"
    ),

    # GitHub
    "github-pat": (
        "1. Go to GitHub Settings > Developer settings > Personal access tokens\n"
        "2. Revoke the compromised token immediately\n"
        "3. Create a new token with minimum required scopes\n"
        "4. Use fine-grained PATs with repo-specific access"
    ),
    "github-oauth": "1. Revoke the OAuth token in GitHub Settings\n2. Re-authorize the application",
    "github-app-token": "1. Regenerate the app token in GitHub App settings\n2. Rotate all installation tokens",
    "github-fine-grained": "1. Revoke at GitHub Settings > Developer settings > Fine-grained tokens\n2. Create a replacement with minimum permissions",

    # Stripe
    "stripe-secret": (
        "1. Go to Stripe Dashboard > Developers > API keys\n"
        "2. Roll the secret key (creates new key, old one still works briefly)\n"
        "3. Update all services with the new key\n"
        "4. Check Stripe logs for unauthorized charges\n"
        "5. Use restricted keys with minimum permissions"
    ),
    "stripe-restricted": "1. Delete the restricted key in Stripe Dashboard\n2. Create a new restricted key with minimum permissions",
    "stripe-publishable": "1. While publishable keys are less sensitive, still roll them\n2. Ensure they are loaded from environment variables",

    # OpenAI
    "openai-api-key": "1. Delete the key at https://platform.openai.com/api-keys\n2. Create a new key\n3. Check usage logs for unauthorized spending",
    "openai-api-key-v2": "1. Delete the project key at https://platform.openai.com/api-keys\n2. Create a new project-scoped key",

    # JWT
    "jwt-token": "1. If this is a signing secret, rotate it immediately\n2. Invalidate all existing sessions\n3. If it's just a token, it will expire naturally",
    "jwt-secret": "1. Rotate the JWT signing secret immediately\n2. All existing JWTs will be invalidated\n3. Store secrets in environment variables or a vault",

    # Private Keys
    "rsa-private-key": "1. Generate a new RSA key pair\n2. Replace the public key everywhere the old one was trusted\n3. Consider the old key fully compromised",
    "ec-private-key": "1. Generate a new EC key pair\n2. Update all trust stores with the new public key",
    "openssh-private-key": "1. Generate a new SSH key: ssh-keygen -t ed25519\n2. Remove the old public key from all authorized_keys files\n3. Update CI/CD systems with the new key",
    "pgp-private-key": "1. Revoke the PGP key\n2. Generate a new key pair\n3. Publish the revocation certificate",
    "pkcs8-private-key": "1. Generate a new private key\n2. Update all certificates using this key\n3. Consider a full certificate reissuance",

    # Database
    "postgres-url": "1. Change the PostgreSQL user password immediately\n2. Update all connection strings\n3. Review pg_hba.conf access rules\n4. Check for unauthorized queries in logs",
    "mysql-url": "1. Change the MySQL user password: ALTER USER 'user' IDENTIFIED BY 'new_pass'\n2. Update all connection strings\n3. Check general_log for unauthorized access",
    "mongodb-url": "1. Change the MongoDB user password\n2. Update all connection strings\n3. Enable audit logging\n4. Check for data exfiltration",
    "redis-url": "1. Change the Redis password with CONFIG SET requirepass\n2. Update all connection strings\n3. Ensure Redis is not exposed to the internet",

    # Slack
    "slack-token": "1. Revoke the token at https://api.slack.com/apps\n2. Create a new token with minimum scopes\n3. Check Slack audit logs for unauthorized access",
    "slack-webhook": "1. Regenerate the webhook URL in Slack App settings\n2. Update all services using the old URL",

    # Generic
    "generic-api-key": "1. Identify the service this key belongs to\n2. Rotate the key in that service's dashboard\n3. Move to environment variables or a secret manager",
    "generic-secret": "1. Identify what this secret protects\n2. Rotate the value immediately\n3. Use a secret manager (Vault, AWS SM, etc.)",
    "generic-token": "1. Identify the service and rotate the token\n2. Check for unauthorized usage\n3. Store in environment variables",
    "basic-auth-url": "1. Change the password for the embedded credentials\n2. Use environment variables for connection strings\n3. Never embed credentials in URLs in code",
    "private-key-inline": "1. Generate a new key pair\n2. Store private keys in files, not inline in code\n3. Use a secret manager or encrypted config",

    # Others
    "ssh-password": "1. Change the SSH password immediately\n2. Switch to key-based authentication",
    "twilio-api-key": "1. Delete the key in Twilio Console > Account > API Keys\n2. Create a new key",
    "twilio-auth-token": "1. Rotate in Twilio Console > Account > General Settings\n2. Update all integrations",
    "sendgrid-api-key": "1. Revoke at SendGrid > Settings > API Keys\n2. Create a new key with minimum permissions",
    "mailchimp-api-key": "1. Regenerate at Mailchimp > Account > Extras > API keys",
    "heroku-api-key": "1. Regenerate at Heroku Dashboard > Account Settings > API Key",
    "npm-token": "1. Revoke at npmjs.com > Access Tokens\n2. Create a new token with appropriate permissions",
    "pypi-token": "1. Delete at pypi.org > Account Settings > API tokens\n2. Create a new scoped token",
    "azure-storage-key": "1. Regenerate the key in Azure Portal > Storage Account > Access Keys\n2. Update all connection strings",
    "azure-connection-string": "1. Regenerate the storage account key\n2. Use Azure Managed Identity instead of key-based access",
    "supabase-service-key": "1. Rotate at Supabase Dashboard > Settings > API\n2. Use anon key for client-side access",
    "firebase-api-key": "1. Restrict the key in Google Cloud Console\n2. Add app check enforcement",
    "shopify-access-token": "1. Revoke in Shopify Admin > Apps > Private apps\n2. Create a new access token",
    "docker-auth": "1. Run: docker logout <registry>\n2. Re-authenticate with docker login\n3. Consider using a credential helper",
    "terraform-cloud-token": "1. Revoke at Terraform Cloud > User Settings > Tokens\n2. Create a new token",
    "datadog-api-key": "1. Revoke at Datadog > Organization Settings > API Keys\n2. Create a new key",
    "cloudflare-api-token": "1. Revoke at Cloudflare > Profile > API Tokens\n2. Create a new token with minimum permissions",
    "digitalocean-token": "1. Revoke at DigitalOcean > API > Tokens\n2. Create a new token",
    "vercel-token": "1. Delete at Vercel > Settings > Tokens\n2. Create a new token",
    "linear-api-key": "1. Revoke at Linear > Settings > API > Personal API keys\n2. Create a new key",
}


def get_remediation(pattern_id: str) -> str:
    """Get remediation steps for a pattern ID."""
    return REMEDIATION_MAP.get(
        pattern_id,
        "1. Identify the service this credential belongs to\n"
        "2. Rotate the credential immediately\n"
        "3. Move secrets to environment variables or a secret manager\n"
        "4. Add the file to .gitignore if applicable"
    )
