Vaultwarden tries to prevent security issues but there could always slip something through.
If you believe you've found a security issue in our application, we encourage you to
notify us. We welcome working with you to resolve the issue promptly. Thanks in advance!

# Disclosure Policy

- Let us know as soon as possible upon discovery of a potential security issue, and we'll make every
  effort to quickly resolve the issue.
- Provide us a reasonable amount of time to resolve the issue before any disclosure to the public or a
  third-party. We may publicly disclose the issue before resolving it, if appropriate.
- Vaultwarden has no hosted service. Test only on instances you run yourself, and make a good faith effort
  to avoid privacy violations, destruction of data, and interruption or degradation of other people's
  servers. Only interact with accounts you own or with explicit permission of the account holder.

# What happens after a report

This is how we usually handle reports. We decide each one on its own.

- **It affects a tagged release:** we publish an advisory, request a CVE and list it in the release notes. Advisories are published about 14 days after the release containing the fix, so users have time to update.
- **It only ever existed on `main` / `testing`:** we publish an advisory and credit the reporter, but there is no CVE or release notes entry, because no released version was affected.
- **Low-impact issues, including low-impact differences from upstream Bitwarden, and most denial of service or resource exhaustion:** we usually fix these as ordinary hardening in a public pull request, with no advisory.
- **A bug in the web vault we bundle:** if it's in Bitwarden's code, the advisory and CVE belong to Bitwarden, so report it to them. Tell us as well, and we'll ship a security release that references theirs. If our own patches added it, report it to us.
- **Credit** goes on the advisory and needs a GitHub account or email address. If several people report the same issue, we close the later reports and link them to the first advisory, and credit their reporters as finders on it as long as the fix isn't public yet. A fix is public from the moment its pull request is opened, so reports of the same issue after that point are normally not credited.
- **Rewards:** Vaultwarden is an open source project and does not offer rewards.

# In-scope

- Security issues in any current release of Vaultwarden. Source code is available at https://github.com/dani-garcia/vaultwarden. This includes the current `latest` release and `main / testing` release.

Our [threat model](THREAT_MODEL.md) describes who is trusted with what, how we rate severity, and behaviour we have already reviewed and consider intended. Please read it before reporting.

# Exclusions

The following bug classes are out-of scope:

- Bugs that are already reported on Vaultwarden's issue tracker (https://github.com/dani-garcia/vaultwarden/issues)
- Bugs that are not part of Vaultwarden, like in Bitwarden's web-vault code or the mobile and desktop clients. These issues need to be reported to Bitwarden through their [HackerOne program](https://hackerone.com/bitwarden/). We are not associated with Bitwarden. Bugs that our own web vault patches add are in scope
- Issues in an upstream software dependency (ex: Rust, or External Libraries) or base image that are not shown to be reachable through Vaultwarden
- Attacks requiring physical access to a user's device
- Issues related to software or protocols not under Vaultwarden's control, including things attached to it like log parsers (Fail2Ban and similar) and misconfigured reverse proxies, and attacks that need another component to violate its own specification
- Vulnerabilities in outdated versions of Vaultwarden
- Missing security best practices that do not directly lead to a vulnerability (You may still report them as a normal issue)
- Actions of someone who already holds the admin token or has access to the host, which are trusted by design

While researching, we'd like to ask you to refrain from:

- Denial of service against servers you do not run. Availability issues that still apply behind a reverse proxy can be reported, so reproduce them on your own instance
- Spamming
- Social engineering (including phishing) of Vaultwarden developers, contributors or users

Thank you for helping keep Vaultwarden and our users safe!

# How to contact us

- You can open a [private vulnerability report](https://github.com/dani-garcia/vaultwarden/security/advisories/new) on GitHub.
- You can send an ![security-contact](/.github/security-contact.gif) to report a security issue.<br>
  If you want to send an encrypted email you can use the following GPG key: 13BB3A34C9E380258CE43D595CB150B31F6426BC<br>
  It can be found on several public GPG key servers.<br>
    * https://keys.openpgp.org/search?q=security%40vaultwarden.org
    * https://keys.mailvelope.com/pks/lookup?op=get&search=security%40vaultwarden.org
    * https://pgpkeys.eu/pks/lookup?search=security%40vaultwarden.org&fingerprint=on&op=index
    * https://keyserver.ubuntu.com/pks/lookup?search=security%40vaultwarden.org&fingerprint=on&op=index
- You can contact us on Matrix for questions, without vulnerability details: https://matrix.to/#/#vaultwarden:matrix.org (users: `@danig:matrix.org` and/or `@blackdex:matrix.org`)

A good report states the version or commit you tested, the lowest privileges needed, any non-default settings, and the steps to reproduce it.
