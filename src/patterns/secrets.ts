import { SecurityPattern } from "../types/index.js";

export const secretPatterns: SecurityPattern[] = [
  // Cloud Provider Keys

  {
    id: "AWS_ACCESS_KEY_ID",
    regex: /(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])/,
    severity: "critical",
    category: "secrets",
    cweId: "CWE-798",
    message: "AWS Access Key ID detected. Exposed AWS credentials can lead to full account compromise.",
    remediation: "Remove the key immediately, rotate it in AWS IAM console, and use environment variables or AWS Secrets Manager.",
    languages: ["*"],
  },
  {
    id: "AWS_SECRET_KEY",
    regex: /(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*['"][A-Za-z0-9/+=]{40}['"]/i,
    severity: "critical",
    category: "secrets",
    cweId: "CWE-798",
    message: "AWS Secret Access Key detected in source code.",
    remediation: "Rotate the key immediately. Use environment variables or IAM roles instead of hardcoded credentials.",
    languages: ["*"],
    matchScope: "literal",
  },
  {
    id: "GCP_SERVICE_ACCOUNT",
    regex: /"type"\s*:\s*"service_account"[\s\S]*"private_key"/,
    severity: "critical",
    category: "secrets",
    cweId: "CWE-798",
    message: "Google Cloud service account key file content detected in source code.",
    remediation: "Use GCP Workload Identity or Secret Manager. Never commit service account JSON keys to source control.",
    languages: ["*"],
    matchScope: "literal",
  },

  // API Keys & Tokens

  {
    id: "GITHUB_TOKEN",
    regex: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/,
    severity: "critical",
    category: "secrets",
    cweId: "CWE-798",
    message: "GitHub Personal Access Token detected. This grants access to repositories and user data.",
    remediation: "Revoke the token at github.com/settings/tokens and use environment variables.",
    languages: ["*"],
  },
  {
    id: "STRIPE_SECRET_KEY",
    regex: /sk_(?:live|test)_[A-Za-z0-9]{20,}/,
    severity: "critical",
    category: "secrets",
    cweId: "CWE-798",
    message: "Stripe secret key detected. This can be used to process payments and access customer data.",
    remediation: "Rotate the key in Stripe Dashboard. Use environment variables for API keys.",
    languages: ["*"],
  },
  {
    id: "SLACK_TOKEN",
    regex: /xox[bporas]-[A-Za-z0-9-]{10,}/,
    severity: "high",
    category: "secrets",
    cweId: "CWE-798",
    message: "Slack token detected. Can be used to read messages and impersonate users.",
    remediation: "Regenerate the token in Slack API settings. Store in environment variables.",
    languages: ["*"],
  },
  {
    id: "OPENAI_API_KEY",
    regex: /sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}/,
    severity: "high",
    category: "secrets",
    cweId: "CWE-798",
    message: "OpenAI API key detected. This can incur significant billing charges.",
    remediation: "Rotate the key at platform.openai.com. Use environment variables.",
    languages: ["*"],
  },

  // Cryptographic Secrets

  {
    id: "PRIVATE_KEY_RSA",
    regex: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/,
    severity: "critical",
    category: "secrets",
    cweId: "CWE-321",
    message: "RSA private key detected in source code. Private keys must never be committed.",
    remediation: "Remove the key from source code. Store in a secrets manager or encrypted vault. Rotate if exposed.",
    languages: ["*"],
  },
  {
    id: "PRIVATE_KEY_EC",
    regex: /-----BEGIN\s+EC\s+PRIVATE\s+KEY-----/,
    severity: "critical",
    category: "secrets",
    cweId: "CWE-321",
    message: "EC private key detected in source code.",
    remediation: "Remove immediately. Use a secrets manager for key storage.",
    languages: ["*"],
  },
  {
    id: "PRIVATE_KEY_OPENSSH",
    regex: /-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----/,
    severity: "critical",
    category: "secrets",
    cweId: "CWE-321",
    message: "OpenSSH private key detected in source code.",
    remediation: "Remove immediately. SSH keys should be stored in ~/.ssh with proper permissions (600).",
    languages: ["*"],
  },

  // JWT Tokens

  {
    id: "JWT_TOKEN",
    regex: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+/,
    severity: "high",
    category: "secrets",
    cweId: "CWE-798",
    message: "JWT token detected in source code. Tokens contain encoded claims and should not be hardcoded.",
    remediation: "Remove the token. JWTs should be generated dynamically and stored securely (httpOnly cookies or secure storage).",
    languages: ["*"],
  },

  // Database Connection Strings

  {
    id: "DATABASE_URL_PASSWORD",
    regex: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp):\/\/[^:]+:[^@]+@[^/\s'"]+/i,
    severity: "critical",
    category: "secrets",
    cweId: "CWE-798",
    message: "Database connection string with credentials detected. Database access should use environment variables.",
    remediation: "Move the connection string to an environment variable (DATABASE_URL). Never commit database credentials.",
    languages: ["*"],
    matchScope: "literal",
  },

  // Generic Password/Secret Patterns

  {
    id: "GENERIC_PASSWORD_ASSIGN",
    regex: /(?:password|passwd|pwd|secret_?key|secret|api_?key|access_?token|auth_?token|private_?key)\s*[:=]\s*['"][^'"]{8,}['"]/i,
    severity: "high",
    category: "secrets",
    cweId: "CWE-798",
    message: "Possible hardcoded credential detected. Variable name suggests this is a secret value.",
    remediation: "Use environment variables for all secrets: process.env.API_KEY or os.environ['API_KEY'].",
    languages: ["*"],
    matchScope: "literal",
  },
  {
    id: "GENERIC_SECRET_CONST",
    regex: /(?:const|let|var|final|static)\s+\w*(?:secret|password|token|key|credential|auth)\w*\s*=\s*['"][^'"]{8,}['"]/i,
    severity: "high",
    category: "secrets",
    cweId: "CWE-798",
    message: "Hardcoded secret in variable declaration. Secret variable names suggest sensitive data.",
    remediation: "Replace with environment variable references. Use a .env file (gitignored) for local development.",
    languages: ["*"],
    matchScope: "literal",
  },

  // Sendgrid / Twilio / Other SaaS

  {
    id: "SENDGRID_API_KEY",
    regex: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/,
    severity: "high",
    category: "secrets",
    cweId: "CWE-798",
    message: "SendGrid API key detected. Can be used to send emails on your behalf.",
    remediation: "Rotate the key in SendGrid dashboard. Use environment variables.",
    languages: ["*"],
  },
  {
    id: "TWILIO_API_KEY",
    regex: /SK[0-9a-fA-F]{32}/,
    severity: "high",
    category: "secrets",
    cweId: "CWE-798",
    message: "Twilio API key detected.",
    remediation: "Rotate the key in Twilio console. Use environment variables.",
    languages: ["*"],
  },
  {
    id: "HEROKU_API_KEY",
    regex: /(?:heroku_api_key|HEROKU_API_KEY)\s*[:=]\s*['"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"]/i,
    severity: "high",
    category: "secrets",
    cweId: "CWE-798",
    message: "Heroku API key detected.",
    remediation: "Rotate the key. Use environment variables.",
    languages: ["*"],
    matchScope: "literal",
  },
];
