# PW Security Helpers

PW Security Helpers is a lightweight WordPress plugin that adds opt-in hardening controls to common attack surfaces and delivers optional HTTP security headers. The plugin is designed to be safe-by-default, requiring administrators to explicitly enable each mitigation so it plays well with a wide variety of site configurations.

## Features
- Toggle REST API user enumeration protections that block suspicious queries to `/wp-json/wp/v2/users`.
- Prevent classic `/?author=1` probing for author archives.
- Disable the legacy `xmlrpc.php` endpoint when it is not required.
- Restrict the REST API to authenticated users only.
- Enable and configure a suite of HTTP security headers including:
  - `Strict-Transport-Security`
  - `Content-Security-Policy`
  - `X-Frame-Options`
  - `X-Content-Type-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`
- Tabbed settings page for easy navigation between core protections and header controls.

## Requirements
- WordPress 6.4 or newer (tested up to the latest stable release at the time of writing).
- Administrator capability to manage site settings.

## Installation
1. Copy the plugin directory into your WordPress installation under `wp-content/plugins/pw-security-helpers`.
2. Log in to the WordPress admin dashboard and activate **PW Security Helpers** from the Plugins screen.

## Usage
1. Navigate to `Settings → PW Security Helpers`.
2. Use the **Core Protections** tab to enable REST and XML-RPC hardening features as needed.
3. Switch to the **Security Headers** tab to enable the headers appropriate for your site. Adjust directive values before enabling to avoid breaking legitimate functionality (for example, configure Content Security Policy directives that match your theme and plugins).
4. Save changes after updating each tab.

### Notes on Security Headers
- `Strict-Transport-Security` is automatically skipped on non-HTTPS requests to avoid trapping users on HTTP-only environments.
- Use caution when enabling `Content-Security-Policy` or `Permissions-Policy`; incorrect directives can prevent required scripts or browser features from functioning.
- The plugin does not automatically add preload entries for HSTS. Submit your domain to [hstspreload.org](https://hstspreload.org/) when you are confident the configuration is correct.

## Development
- Source code is contained in `pw-security-helpers.php`.
- Options are stored in the single `pwsh_options` option entry for easy export.
- Coding standards follow modern WordPress best practices and sanitization patterns.

## Support & Contributions
This plugin is maintained as a helper for personal projects. Bug reports and improvement ideas are welcome; please open an issue or submit a pull request if you have suggestions.

## License
GPL-2.0-or-later. See the plugin header for license details.
