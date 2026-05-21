"""Small built-in wordlists for directory / subdomain brute-forcing."""
from __future__ import annotations

COMMON_DIRS = [
    "admin", "administrator", "login", "login.php", "dashboard", "api", "api/v1", "api/v2",
    "config", "config.php", "setup", "setup.php", "install", "install.php",
    "wp-admin", "wp-login.php", "wp-content",
    "phpmyadmin", "backup", "backup.zip", "db.sql", "database.sql",
    "server-status", "server-info", "test", "dev", "staging",
    "uploads", "files", "images", "assets", "static",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "info.php", "phpinfo.php",
    ".git/config", ".env", ".svn/entries", ".htaccess", ".htpasswd",
    "actuator", "actuator/env", "actuator/health", "console",
    "graphql", "swagger", "swagger-ui.html", "openapi.json",
    # PHP application paths
    "vulnerabilities", "vulnerabilities/sqli", "vulnerabilities/sqli_blind",
    "vulnerabilities/xss_r", "vulnerabilities/xss_s", "vulnerabilities/xss_d",
    "vulnerabilities/exec", "vulnerabilities/csrf", "vulnerabilities/fi",
    "vulnerabilities/upload", "vulnerabilities/brute", "vulnerabilities/captcha",
    "vulnerabilities/insecure_captcha", "vulnerabilities/sqli_blind",
    "vulnerabilities/view_source", "vulnerabilities/weak_id",
    "vulnerabilities/csp", "vulnerabilities/javascript",
    "security", "dvwa", "index.php", "main.php", "logout.php",
    "instructions.php", "about.php", "setup.php",
    "phpids", "acknowledgements.php", "CHANGELOG.md",
    # Common CMS and framework paths
    "wp-json", "wp-includes", "wp-content/uploads",
    "administrator/", "components/", "modules/", "templates/",
    "user/login", "user/register", "admin/login", "auth/login",
    "cgi-bin", "bin", "scripts", "includes", "lib", "tmp", "temp", "log", "logs",
]

COMMON_SUBDOMAINS = [
    "www", "api", "dev", "staging", "test", "admin", "portal", "mail",
    "smtp", "pop", "imap", "ftp", "sftp", "vpn", "git", "gitlab",
    "jenkins", "ci", "cd", "docs", "help", "support", "blog",
    "shop", "store", "beta", "alpha", "internal", "intranet",
    "cdn", "static", "img", "assets", "m", "mobile",
]
