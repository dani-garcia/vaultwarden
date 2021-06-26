Vaultwarden tries to prevent security issues but there could always slip something through.
If you believe you've found a security issue in our application, we encourage you to
notify us. We welcome working with you to resolve the issue promptly. Thanks in advance!

# Disclosure Policy

- Let us know as soon as possible upon discovery of a potential security issue, and we'll make every
  effort to quickly resolve the issue.
- Provide us a reasonable amount of time to resolve the issue before any disclosure to the public or a
  third-party. We may publicly disclose the issue before resolving it, if appropriate.
- Make a good faith effort to avoid privacy violations, destruction of data, and interruption or
  degradation of our service. Only interact with accounts you own or with explicit permission of the
  account holder.

# In-scope

- Security issues in any current release of Vaultwarden. Source code is available at https://github.com/dani-garcia/vaultwarden. This includes the current `latest` release and `main / testing` release.

# Exclusions

The following bug classes are out-of scope:

- Bugs that are already reported on Vaultwarden's issue tracker (https://github.com/dani-garcia/vaultwarden/issues)
- Bugs that are not part of Vaultwarden, like on the the web-vault or mobile and desktop clients. These issues need to be reported in the respective project issue tracker at https://github.com/bitwarden to which we are not associated
- Issues in an upstream software dependency (ex: Rust, or External Libraries) which are already reported to the upstream maintainer
- Attacks requiring physical access to a user's device
- Issues related to software or protocols not under Vaultwarden's control
- Vulnerabilities in outdated versions of Vaultwarden
- Missing security best practices that do not directly lead to a vulnerability (You may still report them as a normal issue)
- Issues that do not have any impact on the general public

While researching, we'd like to ask you to refrain from:

- Denial of service
- Spamming
- Social engineering (including phishing) of Vaultwarden developers, contributors or users

Thank you for helping keep Vaultwarden and our users safe!

# How to contact us

- You can contact us on Matrix https://matrix.to/#/#vaultwarden:matrix.org (user: `@danig:matrix.org`)
- You can send an ![security-contact](/.github/security-contact.gif) to report a security issue.
  - If you want to send an encrypted email you can use the following GPG key:<br>
    https://keyserver.ubuntu.com/pks/lookup?search=0xB9B7A108373276BF3C0406F9FC8A7D14C3CD543A&fingerprint=on&op=index
