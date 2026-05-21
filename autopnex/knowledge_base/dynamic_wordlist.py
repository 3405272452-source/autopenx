"""Generate technology-aware wordlists for directory busting."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List

log = logging.getLogger(__name__)

_COMMON_PATHS_FILE = Path(__file__).parent / "wordlists" / "common_paths.txt"

TECH_WORDLISTS: Dict[str, List[str]] = {
    "wordpress": [
        "/wp-admin/",
        "/wp-login.php",
        "/wp-content/uploads/",
        "/wp-json/wp/v2/users",
        "/xmlrpc.php",
        "/wp-includes/",
        "/.wp-config.php.bak",
        "/wp-content/debug.log",
        "/wp-config.php~",
        "/wp-cron.php",
        "/wp-content/plugins/",
        "/wp-content/themes/",
        "/readme.html",
    ],
    "django": [
        "/admin/",
        "/api/",
        "/__debug__/",
        "/static/",
        "/media/",
        "/accounts/login/",
        "/.env",
        "/settings.py",
        "/django/contrib/admin/",
    ],
    "laravel": [
        "/.env",
        "/storage/logs/laravel.log",
        "/telescope",
        "/horizon",
        "/api/",
        "/_debugbar/",
        "/storage/framework/sessions/",
        "/vendor/composer/installed.json",
        "/public/storage/",
    ],
    "spring": [
        "/actuator",
        "/actuator/health",
        "/actuator/env",
        "/actuator/configprops",
        "/actuator/heapdump",
        "/actuator/mappings",
        "/actuator/beans",
        "/actuator/info",
        "/actuator/loggers",
        "/actuator/threaddump",
        "/swagger-ui.html",
        "/swagger-ui/index.html",
        "/v2/api-docs",
        "/v3/api-docs",
        "/api-docs",
    ],
    "express": [
        "/api/",
        "/.env",
        "/package.json",
        "/node_modules/",
        "/.git/config",
        "/server.js",
        "/app.js",
    ],
    "flask": [
        "/console",
        "/debug",
        "/static/",
        "/.env",
        "/config.py",
        "/instance/config.py",
    ],
    "php": [
        "/phpinfo.php",
        "/phpmyadmin/",
        "/info.php",
        "/.htaccess",
        "/composer.json",
        "/vendor/",
        "/adminer.php",
        "/server-info",
        "/server-status",
    ],
    "joomla": [
        "/administrator/",
        "/configuration.php",
        "/htaccess.txt",
        "/api/index.php/v1/config/application?public=true",
        "/language/en-GB/en-GB.xml",
        "/plugins/system/",
    ],
    "drupal": [
        "/user/login",
        "/admin/",
        "/sites/default/files/",
        "/CHANGELOG.txt",
        "/core/install.php",
        "/update.php",
        "/sites/default/settings.php",
        "/core/CHANGELOG.txt",
    ],
    "tomcat": [
        "/manager/html",
        "/manager/status",
        "/host-manager/html",
        "/WEB-INF/web.xml",
        "/META-INF/context.xml",
        "/examples/",
        "/docs/",
    ],
    "asp.net": [
        "/web.config",
        "/elmah.axd",
        "/trace.axd",
        "/bin/",
        "/App_Data/",
        "/Global.asax",
    ],
    "rails": [
        "/rails/info/properties",
        "/rails/info/routes",
        "/.env",
        "/config/database.yml",
        "/Gemfile",
        "/config/secrets.yml",
    ],
    "ruby on rails": [
        "/rails/info/properties",
        "/rails/info/routes",
        "/.env",
        "/config/database.yml",
    ],
    "next.js": [
        "/_next/data/",
        "/api/",
        "/.next/",
        "/.env.local",
        "/next.config.js",
    ],
    "react": [
        "/static/js/",
        "/manifest.json",
        "/asset-manifest.json",
        "/.env",
        "/service-worker.js",
    ],
    "vue.js": [
        "/static/js/",
        "/manifest.json",
        "/.env",
        "/dist/",
    ],
    "ghost": [
        "/ghost/",
        "/ghost/api/v3/admin/",
        "/content/images/",
    ],
    "nginx": [
        "/nginx_status",
        "/nginx.conf",
        "/status",
        "/.nginx.conf",
        "/basic_status",
    ],
    "golang": [
        "/debug/vars",
        "/debug/pprof/",
        "/debug/pprof/goroutine",
        "/debug/pprof/heap",
        "/debug/pprof/profile",
        "/metrics",
        "/healthz",
        "/readyz",
        "/swagger/",
    ],
    "graphql": [
        "/graphql",
        "/graphiql",
        "/playground",
        "/altair",
        "/graphql/schema",
        "/graphql/console",
        "/.graphql",
        "/api/graphql",
    ],
    "kubernetes": [
        "/healthz",
        "/readyz",
        "/livez",
        "/metrics",
        "/api/v1",
        "/apis",
        "/version",
        "/.kube/config",
    ],
    "swagger": [
        "/swagger-ui.html",
        "/swagger-ui/index.html",
        "/swagger-ui/",
        "/swagger.json",
        "/swagger.yaml",
        "/v2/api-docs",
        "/v3/api-docs",
        "/openapi.json",
        "/openapi.yaml",
        "/api-docs",
        "/redoc",
    ],
    "minio": [
        "/minio/health/live",
        "/minio/health/ready",
        "/minio/health/cluster",
        "/minio/login",
    ],
    "iis": [
        "/web.config",
        "/iisstart.htm",
        "/_vti_bin/",
        "/_vti_inf.html",
        "/aspnet_client/",
        "/elmah.axd",
        "/trace.axd",
    ],
    "fastapi": [
        "/docs",
        "/redoc",
        "/openapi.json",
        "/.env",
        "/api/",
    ],
    "nuxt": [
        "/_nuxt/",
        "/api/",
        "/_loading/",
        "/.env",
        "/nuxt.config.js",
    ],
    "strapi": [
        "/admin",
        "/api/",
        "/uploads/",
        "/_health",
        "/users-permissions/",
    ],
}


def _load_common_paths() -> List[str]:
    if not _COMMON_PATHS_FILE.is_file():
        log.warning("Common paths wordlist not found: %s", _COMMON_PATHS_FILE)
        return []
    lines = _COMMON_PATHS_FILE.read_text(encoding="utf-8").splitlines()
    paths: List[str] = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#"):
            entry = line if line.startswith("/") else f"/{line}"
            paths.append(entry)
    return paths


def generate_wordlist(
    technologies: List[str],
    include_common: bool = True,
) -> List[str]:
    """Build a de-duplicated, ordered wordlist tailored to the detected stack."""
    paths: List[str] = []
    if include_common:
        paths.extend(_load_common_paths())
    for tech in technologies:
        tech_lower = tech.lower()
        for key, wordlist in TECH_WORDLISTS.items():
            if key in tech_lower or tech_lower in key:
                paths.extend(wordlist)
    return list(dict.fromkeys(paths))
