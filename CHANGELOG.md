# Changelog

## Unreleased
* Always verify the Identity provider's TLS certificate: the `disable_ssl_validation`
  setting is gone (SPR-554). It switched off verification for Bearer-token checks and,
  through HTTParty's global defaults, for every HTTParty call in the process. A value left
  in the database is ignored; a failing handshake is logged with the reason.
* Stop writing the Redmine `admin` flag from the token or the `admin_group` setting (SPR-383).
  Clients sent different `groups` claims, so the flag flipped from request to request; the
  tracker's role model (redmine_extended_api) now decides who is an administrator.
* Enforce Identity organization membership on the server: new `organization`
  setting (falls back to `KEYCLOAK_ORG_ALIAS`) rejects browser logins and
  Bearer-token API requests whose token does not list this tenant's organization

## ??? 0.9.5
* Pull server-side errors from locale files
* Log-messages/some less prominent errors hard-coded in English again 
* Do not render `rpiframe`, if OpenID config does not contain a `check_session_iframe`
* Some more documentation about setting up

## 0.9.4
* Support Redmine 4
* Upgrade deprecated calls

## 0.9.3
* fix problem with symbols vs. strings usage

## 0.9.2
* fix settings page
* move to github
* Avoid error if members_of is empty during check
* Add disable ssl validation
* Add protocol to hostname
