"""
Secret detection patterns: 50+ regex patterns for various secret types.
Each pattern includes metadata for scoring and remediation.
"""

import re
from dataclasses import dataclass


@dataclass
class SecretPattern:
    """A pattern definition for detecting a specific type of secret."""
    id: str
    name: str
    pattern: re.Pattern
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    category: str
    description: str
    entropy_threshold: float = 3.0  # Minimum Shannon entropy to consider


PATTERNS: list[SecretPattern] = [
    # ──── AWS ─────────────────────────────────────────
    SecretPattern(
        id="aws-access-key",
        name="AWS Access Key ID",
        pattern=re.compile(r'(?:^|["\'\s=:])(?P<secret>AKIA[0-9A-Z]{16})(?:["\'\s]|$)'),
        severity="CRITICAL",
        category="AWS",
        description="AWS Access Key ID (starts with AKIA)",
    ),
    SecretPattern(
        id="aws-secret-key",
        name="AWS Secret Access Key",
        pattern=re.compile(r'(?:aws_secret_access_key|secret_key|aws_secret)\s*[=:]\s*["\']?(?P<secret>[A-Za-z0-9/+=]{40})["\']?'),
        severity="CRITICAL",
        category="AWS",
        description="AWS Secret Access Key (40-char base64)",
        entropy_threshold=4.0,
    ),
    SecretPattern(
        id="aws-session-token",
        name="AWS Session Token",
        pattern=re.compile(r'(?:aws_session_token|session_token)\s*[=:]\s*["\']?(?P<secret>[A-Za-z0-9/+=]{100,})'),
        severity="CRITICAL",
        category="AWS",
        description="AWS Session Token",
    ),

    # ──── GCP ─────────────────────────────────────────
    SecretPattern(
        id="gcp-api-key",
        name="GCP API Key",
        pattern=re.compile(r'(?:^|["\'\s=:])(?P<secret>AIza[0-9A-Za-z_-]{35})'),
        severity="HIGH",
        category="Google Cloud",
        description="Google Cloud API Key (starts with AIza)",
    ),
    SecretPattern(
        id="gcp-service-account",
        name="GCP Service Account Key",
        pattern=re.compile(r'"type"\s*:\s*"service_account"'),
        severity="CRITICAL",
        category="Google Cloud",
        description="GCP service account JSON key file",
        entropy_threshold=0.0,  # Structure-based detection
    ),
    SecretPattern(
        id="gcp-oauth-client",
        name="GCP OAuth Client Secret",
        pattern=re.compile(r'(?:client_secret)\s*[=:]\s*["\']?(?P<secret>[A-Za-z0-9_-]{24,})'),
        severity="HIGH",
        category="Google Cloud",
        description="Google OAuth client secret",
    ),

    # ──── GitHub ──────────────────────────────────────
    SecretPattern(
        id="github-pat",
        name="GitHub Personal Access Token",
        pattern=re.compile(r'(?:^|["\'\s=:])(?P<secret>ghp_[A-Za-z0-9]{36,})'),
        severity="CRITICAL",
        category="GitHub",
        description="GitHub Personal Access Token (ghp_)",
    ),
    SecretPattern(
        id="github-oauth",
        name="GitHub OAuth Token",
        pattern=re.compile(r'(?:^|["\'\s=:])(?P<secret>gho_[A-Za-z0-9]{36,})'),
        severity="CRITICAL",
        category="GitHub",
        description="GitHub OAuth Access Token (gho_)",
    ),
    SecretPattern(
        id="github-app-token",
        name="GitHub App Token",
        pattern=re.compile(r'(?:^|["\'\s=:])(?P<secret>(?:ghu|ghs|ghr)_[A-Za-z0-9]{36,})'),
        severity="CRITICAL",
        category="GitHub",
        description="GitHub App/Installation/Refresh Token",
    ),
    SecretPattern(
        id="github-fine-grained",
        name="GitHub Fine-Grained PAT",
        pattern=re.compile(r'(?:^|["\'\s=:])(?P<secret>github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})'),
        severity="CRITICAL",
        category="GitHub",
        description="GitHub Fine-Grained Personal Access Token",
    ),

    # ──── Stripe ──────────────────────────────────────
    SecretPattern(
        id="stripe-secret",
        name="Stripe Secret Key",
        pattern=re.compile(r'(?:^|["\'\s=:])(?P<secret>sk_live_[A-Za-z0-9]{24,})'),
        severity="CRITICAL",
        category="Stripe",
        description="Stripe live secret key",
    ),
    SecretPattern(
        id="stripe-restricted",
        name="Stripe Restricted Key",
        pattern=re.compile(r'(?:^|["\'\s=:])(?P<secret>rk_live_[A-Za-z0-9]{24,})'),
        severity="HIGH",
        category="Stripe",
        description="Stripe restricted API key",
    ),
    SecretPattern(
        id="stripe-publishable",
        name="Stripe Publishable Key",
        pattern=re.compile(r'(?:^|["\'\s=:])(?P<secret>pk_live_[A-Za-z0-9]{24,})'),
        severity="LOW",
        category="Stripe",
        description="Stripe publishable key (low risk, but shouldn't be hardcoded)",
    ),

    # ──── OpenAI ──────────────────────────────────────
    SecretPattern(
        id="openai-api-key",
        name="OpenAI API Key",
        pattern=re.compile(r'(?:^|["\'\s=:])(?P<secret>sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,})'),
        severity="HIGH",
        category="OpenAI",
        description="OpenAI API key",
    ),
    SecretPattern(
        id="openai-api-key-v2",
        name="OpenAI API Key (new format)",
        pattern=re.compile(r'(?:^|["\'\s=:])(?P<secret>sk-proj-[A-Za-z0-9_-]{40,})'),
        severity="HIGH",
        category="OpenAI",
        description="OpenAI project API key (new format)",
    ),

    # ──── JWT ─────────────────────────────────────────
    SecretPattern(
        id="jwt-token",
        name="JWT Token",
        pattern=re.compile(r'(?:^|["\'\s=:])(?P<secret>eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})'),
        severity="MEDIUM",
        category="JWT",
        description="JSON Web Token (may contain sensitive claims)",
        entropy_threshold=4.0,
    ),
    SecretPattern(
        id="jwt-secret",
        name="JWT Secret/Signing Key",
        pattern=re.compile(r'(?:jwt_secret|jwt_key|signing_key|JWT_SECRET)\s*[=:]\s*["\']?(?P<secret>[A-Za-z0-9+/=_-]{16,})'),
        severity="CRITICAL",
        category="JWT",
        description="JWT signing secret",
    ),

    # ──── Private Keys ────────────────────────────────
    SecretPattern(
        id="rsa-private-key",
        name="RSA Private Key",
        pattern=re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),
        severity="CRITICAL",
        category="Cryptographic Key",
        description="RSA private key in PEM format",
        entropy_threshold=0.0,
    ),
    SecretPattern(
        id="ec-private-key",
        name="EC Private Key",
        pattern=re.compile(r'-----BEGIN EC PRIVATE KEY-----'),
        severity="CRITICAL",
        category="Cryptographic Key",
        description="Elliptic Curve private key in PEM format",
        entropy_threshold=0.0,
    ),
    SecretPattern(
        id="openssh-private-key",
        name="OpenSSH Private Key",
        pattern=re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),
        severity="CRITICAL",
        category="Cryptographic Key",
        description="OpenSSH private key",
        entropy_threshold=0.0,
    ),
    SecretPattern(
        id="pgp-private-key",
        name="PGP Private Key",
        pattern=re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
        severity="CRITICAL",
        category="Cryptographic Key",
        description="PGP/GPG private key block",
        entropy_threshold=0.0,
    ),
    SecretPattern(
        id="pkcs8-private-key",
        name="PKCS8 Private Key",
        pattern=re.compile(r'-----BEGIN PRIVATE KEY-----'),
        severity="CRITICAL",
        category="Cryptographic Key",
        description="PKCS#8 private key in PEM format",
        entropy_threshold=0.0,
    ),

    # ──── Database URLs ───────────────────────────────
    SecretPattern(
        id="postgres-url",
        name="PostgreSQL Connection URL",
        pattern=re.compile(r'(?P<secret>postgres(?:ql)?://[^:]+:[^@]+@[^/\s]+)'),
        severity="CRITICAL",
        category="Database",
        description="PostgreSQL connection string with credentials",
    ),
    SecretPattern(
        id="mysql-url",
        name="MySQL Connection URL",
        pattern=re.compile(r'(?P<secret>mysql://[^:]+:[^@]+@[^/\s]+)'),
        severity="CRITICAL",
        category="Database",
        description="MySQL connection string with credentials",
    ),
    SecretPattern(
        id="mongodb-url",
        name="MongoDB Connection URL",
        pattern=re.compile(r'(?P<secret>mongodb(?:\+srv)?://[^:]+:[^@]+@[^/\s]+)'),
        severity="CRITICAL",
        category="Database",
        description="MongoDB connection string with credentials",
    ),
    SecretPattern(
        id="redis-url",
        name="Redis Connection URL",
        pattern=re.compile(r'(?P<secret>redis://[^:]*:[^@]+@[^/\s]+)'),
        severity="HIGH",
        category="Database",
        description="Redis connection string with credentials",
    ),

    # ──── SSH ─────────────────────────────────────────
    SecretPattern(
        id="ssh-password",
        name="SSH Password in Config",
        pattern=re.compile(r'(?:sshpass|ssh_pass|ssh_password)\s*[=:]\s*["\']?(?P<secret>\S{6,})'),
        severity="CRITICAL",
        category="SSH",
        description="SSH password in configuration",
    ),

    # ──── Slack ───────────────────────────────────────
    SecretPattern(
        id="slack-token",
        name="Slack Token",
        pattern=re.compile(r'(?:^|["\'\s=:])(?P<secret>xox[bpors]-[A-Za-z0-9-]{10,})'),
        severity="HIGH",
        category="Slack",
        description="Slack API token (xoxb, xoxp, xoxo, xoxr, xoxs)",
    ),
    SecretPattern(
        id="slack-webhook",
        name="Slack Webhook URL",
        pattern=re.compile(r'(?P<secret>https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+)'),
        severity="MEDIUM",
        category="Slack",
        description="Slack incoming webhook URL",
    ),

    # ──── Twilio ──────────────────────────────────────
    SecretPattern(
        id="twilio-api-key",
        name="Twilio API Key",
        pattern=re.compile(r'(?:^|["\'\s=:])(?P<secret>SK[0-9a-fA-F]{32})'),
        severity="HIGH",
        category="Twilio",
        description="Twilio API Key SID",
    ),
    SecretPattern(
        id="twilio-auth-token",
        name="Twilio Auth Token",
        pattern=re.compile(r'(?:twilio_auth_token|TWILIO_AUTH_TOKEN)\s*[=:]\s*["\']?(?P<secret>[0-9a-f]{32})'),
        severity="CRITICAL",
        category="Twilio",
        description="Twilio Auth Token",
    ),

    # ──── SendGrid ────────────────────────────────────
    SecretPattern(
        id="sendgrid-api-key",
        name="SendGrid API Key",
        pattern=re.compile(r'(?:^|["\'\s=:])(?P<secret>SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})'),
        severity="HIGH",
        category="SendGrid",
        description="SendGrid API key",
    ),

    # ──── Mailchimp ───────────────────────────────────
    SecretPattern(
        id="mailchimp-api-key",
        name="Mailchimp API Key",
        pattern=re.compile(r'(?P<secret>[0-9a-f]{32}-us[0-9]{1,2})'),
        severity="MEDIUM",
        category="Mailchimp",
        description="Mailchimp API key",
        entropy_threshold=3.5,
    ),

    # ──── Heroku ──────────────────────────────────────
    SecretPattern(
        id="heroku-api-key",
        name="Heroku API Key",
        pattern=re.compile(r'(?:heroku_api_key|HEROKU_API_KEY)\s*[=:]\s*["\']?(?P<secret>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'),
        severity="HIGH",
        category="Heroku",
        description="Heroku API key (UUID format)",
    ),

    # ──── NPM ─────────────────────────────────────────
    SecretPattern(
        id="npm-token",
        name="NPM Access Token",
        pattern=re.compile(r'(?:^|["\'\s=:])(?P<secret>npm_[A-Za-z0-9]{36})'),
        severity="HIGH",
        category="NPM",
        description="NPM access token",
    ),

    # ──── PyPI ─────────────────────────────────────────
    SecretPattern(
        id="pypi-token",
        name="PyPI API Token",
        pattern=re.compile(r'(?:^|["\'\s=:])(?P<secret>pypi-[A-Za-z0-9_-]{50,})'),
        severity="HIGH",
        category="PyPI",
        description="PyPI API token",
    ),

    # ──── Azure ───────────────────────────────────────
    SecretPattern(
        id="azure-storage-key",
        name="Azure Storage Account Key",
        pattern=re.compile(r'(?:AccountKey|account_key)\s*[=:]\s*["\']?(?P<secret>[A-Za-z0-9+/=]{88})'),
        severity="CRITICAL",
        category="Azure",
        description="Azure Storage account key",
    ),
    SecretPattern(
        id="azure-connection-string",
        name="Azure Connection String",
        pattern=re.compile(r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=(?P<secret>[A-Za-z0-9+/=]{88})'),
        severity="CRITICAL",
        category="Azure",
        description="Azure Storage connection string with key",
    ),

    # ──── Supabase ────────────────────────────────────
    SecretPattern(
        id="supabase-service-key",
        name="Supabase Service Role Key",
        pattern=re.compile(r'(?:supabase_service_role_key|SUPABASE_SERVICE_ROLE_KEY)\s*[=:]\s*["\']?(?P<secret>eyJ[A-Za-z0-9_-]{100,})'),
        severity="CRITICAL",
        category="Supabase",
        description="Supabase service role key (bypasses RLS)",
    ),

    # ──── Firebase ────────────────────────────────────
    SecretPattern(
        id="firebase-api-key",
        name="Firebase API Key",
        pattern=re.compile(r'(?:firebase_api_key|FIREBASE_API_KEY)\s*[=:]\s*["\']?(?P<secret>AIza[0-9A-Za-z_-]{35})'),
        severity="MEDIUM",
        category="Firebase",
        description="Firebase API key",
    ),

    # ──── Generic ─────────────────────────────────────
    SecretPattern(
        id="generic-api-key",
        name="Generic API Key",
        pattern=re.compile(r'(?:api_key|apikey|api-key|API_KEY)\s*[=:]\s*["\']?(?P<secret>[A-Za-z0-9_-]{20,})'),
        severity="MEDIUM",
        category="Generic",
        description="Generic API key pattern",
        entropy_threshold=3.5,
    ),
    SecretPattern(
        id="generic-secret",
        name="Generic Secret",
        pattern=re.compile(r'(?:secret|SECRET|password|PASSWORD|passwd|PASSWD)\s*[=:]\s*["\']?(?P<secret>[^\s"\']{8,})'),
        severity="MEDIUM",
        category="Generic",
        description="Generic secret/password assignment",
        entropy_threshold=3.0,
    ),
    SecretPattern(
        id="generic-token",
        name="Generic Token",
        pattern=re.compile(r'(?:token|TOKEN|bearer|BEARER)\s*[=:]\s*["\']?(?P<secret>[A-Za-z0-9_.-]{20,})'),
        severity="MEDIUM",
        category="Generic",
        description="Generic token assignment",
        entropy_threshold=3.5,
    ),
    SecretPattern(
        id="basic-auth-url",
        name="Basic Auth in URL",
        pattern=re.compile(r'(?P<secret>https?://[^:]+:[^@]+@[^/\s]+)'),
        severity="HIGH",
        category="Authentication",
        description="Credentials embedded in URL",
    ),
    SecretPattern(
        id="private-key-inline",
        name="Private Key (Inline)",
        pattern=re.compile(r'-----BEGIN (?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----'),
        severity="CRITICAL",
        category="Cryptographic Key",
        description="Private key found inline in code",
        entropy_threshold=0.0,
    ),

    # ──── Shopify ─────────────────────────────────────
    SecretPattern(
        id="shopify-access-token",
        name="Shopify Access Token",
        pattern=re.compile(r'(?:^|["\'\s=:])(?P<secret>shpat_[A-Fa-f0-9]{32})'),
        severity="HIGH",
        category="Shopify",
        description="Shopify Admin API access token",
    ),

    # ──── Docker ──────────────────────────────────────
    SecretPattern(
        id="docker-auth",
        name="Docker Auth Config",
        pattern=re.compile(r'"auth"\s*:\s*"(?P<secret>[A-Za-z0-9+/=]{20,})"'),
        severity="HIGH",
        category="Docker",
        description="Docker registry auth token (base64 credentials)",
        entropy_threshold=4.0,
    ),

    # ──── Terraform ───────────────────────────────────
    SecretPattern(
        id="terraform-cloud-token",
        name="Terraform Cloud Token",
        pattern=re.compile(r'(?:^|["\'\s=:])(?P<secret>[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9]{60,})'),
        severity="HIGH",
        category="Terraform",
        description="Terraform Cloud/Enterprise API token",
    ),

    # ──── Datadog ─────────────────────────────────────
    SecretPattern(
        id="datadog-api-key",
        name="Datadog API Key",
        pattern=re.compile(r'(?:dd_api_key|datadog_api_key|DD_API_KEY)\s*[=:]\s*["\']?(?P<secret>[0-9a-f]{32})'),
        severity="HIGH",
        category="Datadog",
        description="Datadog API key",
    ),

    # ──── Cloudflare ──────────────────────────────────
    SecretPattern(
        id="cloudflare-api-token",
        name="Cloudflare API Token",
        pattern=re.compile(r'(?:cloudflare_api_token|CF_API_TOKEN)\s*[=:]\s*["\']?(?P<secret>[A-Za-z0-9_-]{40})'),
        severity="HIGH",
        category="Cloudflare",
        description="Cloudflare API token",
    ),

    # ──── DigitalOcean ────────────────────────────────
    SecretPattern(
        id="digitalocean-token",
        name="DigitalOcean PAT",
        pattern=re.compile(r'(?:^|["\'\s=:])(?P<secret>dop_v1_[a-f0-9]{64})'),
        severity="HIGH",
        category="DigitalOcean",
        description="DigitalOcean personal access token",
    ),

    # ──── Vercel ──────────────────────────────────────
    SecretPattern(
        id="vercel-token",
        name="Vercel Token",
        pattern=re.compile(r'(?:^|["\'\s=:])(?P<secret>[A-Za-z0-9]{24})(?=\s|$|"|\')'),
        severity="LOW",
        category="Vercel",
        description="Possible Vercel token (low confidence)",
        entropy_threshold=4.0,
    ),

    # ──── Linear ──────────────────────────────────────
    SecretPattern(
        id="linear-api-key",
        name="Linear API Key",
        pattern=re.compile(r'(?:^|["\'\s=:])(?P<secret>lin_api_[A-Za-z0-9]{40,})'),
        severity="MEDIUM",
        category="Linear",
        description="Linear API key",
    ),
]


def get_all_patterns() -> list[SecretPattern]:
    """Return all secret detection patterns."""
    return PATTERNS
