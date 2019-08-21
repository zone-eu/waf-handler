# WAF-handler

Custom Apache error page with ModSecurity + OWASP CRS false-positive reporting to email and/or Slack.

**Note:** This is not production-ready, as there is currently no rate-limiting and single unique-id can be used to spam target mailbox / slack channel.

## Installation and configuration

* copy `index.php` to `/waf-handler/index.php` under your docroot
* specify custom ErrorDocument in Apache configuration:
    `ErrorDocument 403 /waf-handler/index.php?email=monitoring@example.com&slack=https://hooks.slack.com/services/T12...3T/B12...3B/hU12...3Uh`