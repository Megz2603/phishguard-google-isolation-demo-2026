from scanner.languages import KEYWORDS_BY_LANGUAGE


SUSPICIOUS_KEYWORDS = list(dict.fromkeys(
    keyword
    for language_keywords in KEYWORDS_BY_LANGUAGE.values()
    for keyword, _ in language_keywords
))

# Selected account and authentication URL paths from SecLists' common web
# paths list. SecLists is MIT-licensed; see README.md for attribution.
SECLISTS_URL_PATH_KEYWORDS = [
    "account",
    "account_edit",
    "account_history",
    "accounts",
    "accountsettings",
    "acct_login",
    "access",
    "accessgranted",
    "activate",
    "activation",
    "admin",
    "auth",
    "authentication",
    "authorize",
    "autologin",
    "bank",
    "banking",
    "billing",
    "card",
    "change-password",
    "change_password",
    "checkout",
    "confirm",
    "create_account",
    "credentials",
    "creditcards",
    "customer_login",
    "email",
    "emails",
    "forgot-password",
    "forgot_password",
    "forgotpassword",
    "identity",
    "inbox",
    "invoice",
    "login",
    "login-redirect",
    "login_check",
    "login_sendpass",
    "logon",
    "lostpassword",
    "mail_password",
    "mailbox",
    "my-account",
    "myaccount",
    "oauth",
    "open-account",
    "order",
    "payment",
    "payments",
    "paypal",
    "pass",
    "password",
    "profile",
    "recoverpassword",
    "recovery",
    "register",
    "registration",
    "secure",
    "secure_login",
    "security",
    "session",
    "signin",
    "sign-up",
    "sign_up",
    "signon",
    "signup",
    "user",
    "userlogin",
    "username"
]

SUSPICIOUS_EXTENSIONS = [
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".vbs",
    ".js"
]

KNOWN_BRANDS = [
    "paypal",
    "microsoft",
    "google",
    "apple",
    "facebook",
    "instagram",
    "netflix",
    "amazon",
    "absa",
    "fnb",
    "standardbank"
]
