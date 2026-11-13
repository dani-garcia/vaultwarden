Vaultwarden tries to prevent security issues, but something could always slip through. If you believe you've found a security issue in our application, we encourage you to notify us. We welcome working with you to resolve the issue promptly. Thanks in advance!

# Scope

Security issues in the current release of Vaultwarden and in the `main` branch (the `testing` image) are in scope. Our [threat model](THREAT_MODEL.md) describes who is trusted with what, what is out of scope, and how we rate severity. Please read it before reporting.

# How to report a security issue

- Let us know as soon as possible upon discovery of a potential security issue, and we'll make every effort to quickly resolve the issue.
- Provide us a reasonable amount of time to resolve the issue before any disclosure to the public or a third party. We may publicly disclose the issue before resolving it, if appropriate.
- Credit goes on the advisory and needs a GitHub account or email address. Reports of an issue whose fix is already public, from the moment its pull request is opened, are normally not credited.
- Vaultwarden is an open source project and does not offer rewards.

Vaultwarden has no hosted service. Test only on instances you run yourself, and make a good-faith effort to avoid privacy violations, destruction of data, and interruption or degradation of other people's servers. Only interact with accounts you own or with the explicit permission of the account holder.

While researching, we'd like to ask you to refrain from:

- Denial of service against servers you do not run. You can still report availability issues you reproduce on your own instance.
- Spamming.
- Social engineering (including phishing) of Vaultwarden developers, contributors or users.

A good report covers one root cause and states the version or commit you tested, the lowest privileges needed, what the attacker gains, any non-default settings, the steps to reproduce it, and whether you ran them or only read the code.

If you use AI tools, you remain responsible for what you send. Reproduce the issue on your own instance before reporting it, check its scope and severity against our threat model rather than the tool's assessment, and include the requests, responses or logs that show it.

# How to contact us

- You can open a [private vulnerability report](https://github.com/dani-garcia/vaultwarden/security/advisories/new) on GitHub.
- You can send an ![security-contact](/.github/security-contact.gif) to report a security issue.<br>
  If you want to send an encrypted email, you can use the following GPG key: `13BB3A34C9E380258CE43D595CB150B31F6426BC`<br>
  It can be found on several public GPG key servers.<br>
    - https://keys.openpgp.org/search?q=security%40vaultwarden.org
    - https://keys.mailvelope.com/pks/lookup?op=get&search=security%40vaultwarden.org
    - https://pgpkeys.eu/pks/lookup?search=security%40vaultwarden.org&fingerprint=on&op=index
    - https://keyserver.ubuntu.com/pks/lookup?search=security%40vaultwarden.org&fingerprint=on&op=index
- You can contact us on Matrix for questions, without vulnerability details: https://matrix.to/#/#vaultwarden:matrix.org (users: `@danig:matrix.org` and/or `@blackdex:matrix.org`).

Thank you for helping keep Vaultwarden and our users safe!
