# SB-TS-RW-065: LDAP email-based account linking enables account takeover / privilege escalation in n8n

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-c545-x2rh-82fc`
- CVE: `CVE-2026-33665`
- Vulnerable commit: `6c484fd4e85bd12025ff13eb88c37e701b468bbe` (release n8n@1.120.4)
- Fix commit: `b3af602ed08e11591e17597183cca9c2ab1ff37c` (release n8n@1.121.0)

## Vulnerability
The first-login linking decision trusts the LDAP email attribute as a unique identity proof: if emailUser.email === emailAttributeValue it binds the LDAP id to the pre-existing local user with no check that the email is unique within the directory and no out-of-band confirmation. Since users can often modify their own LDAP email attribute, this lets an attacker impersonate any local user by matching that user's email.

## Source / Carrier / Sink
- Source: The email attribute returned for the authenticating LDAP user (emailAttributeValue from mapLdapAttributesToUser), which an LDAP user can set to a victim's email.
- Carrier: emailAttributeValue is passed to getUserByEmail(emailAttributeValue) and the result drives the createLdapAuthIdentity(emailUser, ldapId) link inside the if (!ldapAuthIdentity) branch of handleLdapLogin.
- Sink: createLdapAuthIdentity(emailUser, ldapId) followed by updateLdapUserOnLocalDb, which permanently binds the attacker's LDAP id to the victim's local account and returns that account as the authenticated user.
- Missing guard: No verification that the LDAP email is unique across the directory (no duplicate-email/uniqueness check) and no requirement that account linking be confirmed by the legitimate account owner before the LDAP id is attached.

## Fix
The fix (commit b3af602, released in 1.121.0) adds an enforceEmailUniqueness config (defaulted to true for existing instances) and a hasEmailDuplicatesInLdap LDAP search; before linking to an existing local user it blocks the login (returns undefined) when more than one LDAP entry shares the email, and fails closed on search errors, preventing email-collision-based account linking.

## Scanner Expectation
Flag the authentication flow that links an LDAP identity to an existing local account based only on an attacker-controllable email match as an authentication bypass / account takeover (CWE-287): identity established without verifying the asserted email is uniquely owned by the LDAP principal.
