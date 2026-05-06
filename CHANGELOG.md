<!-- Copyright (c) 2026, AgriTheory and contributors
For license information, please see license.txt-->

# Changelog

This changelog was automatically generated from GitHub releases and pull requests.

## Unreleased

Added pre-commit hooks to streamline code quality checks. Updated workflows for generating and overriding changelogs. Adjusted configuration for pre-commit hooks and removed unused user data in the SAML directory.

## [v15.4.0] - 2025-07-28

### Release Notes

## v15.4.0 (2025-07-28)

### Features

- Allow bulk update in saml mappings ([#23](https://github.com/agritheory/saml/pull/23), [`862d795`](https://github.com/agritheory/saml/commit/862d795febc6d3a4cf8f33676e9ba43dbad87d68))

---

**Detailed Changes**: [v15.3.1...v15.4.0](https://github.com/agritheory/saml/compare/v15.3.1...v15.4.0)


### Changes from Pull Requests

Users can now update multiple SAML mappings at once. This feature simplifies bulk management and reduces the time required for updates.
  _Source: PR #23_

## [v15.3.1] - 2025-07-28

### Release Notes

## v15.3.1 (2025-07-28)

### Bug Fixes

- More url construction fixes ([#22](https://github.com/agritheory/saml/pull/22), [`08416dd`](https://github.com/agritheory/saml/commit/08416ddc198c80c25197c28b5c185f7beddd882b))

### Continuous Integration

- Lxml fixes ([#22](https://github.com/agritheory/saml/pull/22), [`08416dd`](https://github.com/agritheory/saml/commit/08416ddc198c80c25197c28b5c185f7beddd882b))

---

**Detailed Changes**: [v15.3.0...v15.3.1](https://github.com/agritheory/saml/compare/v15.3.0...v15.3.1)


### Changes from Pull Requests

Fixed issues with URL construction and updated dependencies. Improved SAML login functionality.
  _Source: PR #22_

## [v15.3.0] - 2025-07-25

### Release Notes

## v15.3.0 (2025-07-25)

### Features

- Fix url construction, handle no param response from Entra ([`9ea7d58`](https://github.com/agritheory/saml/commit/9ea7d581e375d12b1ce307b95f9c11822b225556))

---

**Detailed Changes**: [v15.2.2...v15.3.0](https://github.com/agritheory/saml/compare/v15.2.2...v15.3.0)


### Changes from Pull Requests

Fixed URL construction and handled responses from Entra without parameters.
  _Source: PR #20_

## [v15.2.2] - 2025-07-21

### Release Notes

## v15.2.2 (2025-07-21)

### Bug Fixes

- Get_settings ([`6baf713`](https://github.com/agritheory/saml/commit/6baf713199d3f6cf32e552f89f16e885ad849781))

---

**Detailed Changes**: [v15.2.1...v15.2.2](https://github.com/agritheory/saml/compare/v15.2.1...v15.2.2)


### Changes from Pull Requests

Fixed an issue in the `get_settings` function. Now returns correct settings values.
  _Source: PR #19_

## [v15.2.1] - 2025-07-02

### Release Notes

## v15.2.1 (2025-07-02)

### Bug Fixes

- Login for saml ([`9de97bb`](https://github.com/agritheory/saml/commit/9de97bb99cd1ea908c27a1cf0524512734b353c2))

---

**Detailed Changes**: [v15.2.0...v15.2.1](https://github.com/agritheory/saml/compare/v15.2.0...v15.2.1)


### Changes from Pull Requests

Fixed SAML login issue. Users can now log in using their SAML credentials.
  _Source: PR #18_

## [v15.2.0] - 2025-05-30

### Release Notes

## v15.2.0 (2025-05-30)

### Features

- Force SAML login for provided domains ([`77165c2`](https://github.com/agritheory/saml/commit/77165c2dcf2a86c172bc272c29dca8bfe4d0e3eb))

---

**Detailed Changes**: [v15.1.0...v15.2.0](https://github.com/agritheory/saml/compare/v15.1.0...v15.2.0)


### Changes from Pull Requests

Forced SAML login for specified domains now available. Resolves #14.
  _Source: PR #16_

## [v15.1.0] - 2025-05-26

### Release Notes

## v15.1.0 (2025-05-26)

### Bug Fixes

- Only include custom field in customizations ([`a7e4df9`](https://github.com/agritheory/saml/commit/a7e4df98c82b15f7acbc567fac3160d71096ee9b))

### Features

- Disallow password reset for SAML-managed users ([`09d3a24`](https://github.com/agritheory/saml/commit/09d3a24380e5992022685bc934a827610c8a9c15))

---

**Detailed Changes**: [v0.1.0...v15.1.0](https://github.com/agritheory/saml/compare/v0.1.0...v15.1.0)


### Changes from Pull Requests

Disallow password reset for SAML-managed users. Fixed issue with custom field inclusion in customizations.
  _Source: PR #13_

## [v15.0.0] - 2025-04-02

### Release Notes

## v15.0.0 (2025-04-02)

### Bug Fixes

- Add SAML keycloak fixtures ([#7](https://github.com/agritheory/saml/pull/7), [`3ab5c03`](https://github.com/agritheory/saml/commit/3ab5c032a70b64b464ac7c9bdebafd807cd9f8b8))

* fix: update poetry config

* fix: provision Keycloak realm in test

* ci: add xmlsec to build

---------

Co-authored-by: Rohan Bansal <rohan@agritheory.dev>

- Update Keycloak test roles ([`efbe004`](https://github.com/agritheory/saml/commit/efbe004be65c268b17eb846d5653f9c57f5a49c1))

### Chores

- Black  ([`44ed0b4`](https://github.com/agritheory/saml/commit/44ed0b4c599208ee68de1b27ed5d4fd2366b68b8))

- Prettier  ([`117c8ae`](https://github.com/agritheory/saml/commit/117c8ae6c77aad8d53234a3996e9dba87e28c8ef))

### Continuous Integration

- Setup bench services to generate test data ([`602c3b0`](https://github.com/agritheory/saml/commit/602c3b0a533b95f8d34fa1995a41fd1e19b0b0e6))

### Documentation

- Update readme ([`14db38d`](https://github.com/agritheory/saml/commit/14db38da15e4026b420202b387adbf3ca6a4452d))

### Features

- Initialize App ([`be3d683`](https://github.com/agritheory/saml/commit/be3d6833fbb2b30f344eefbd29319cd49de99d24))

- Map SAML role to a Frappe user role ([`83e65e1`](https://github.com/agritheory/saml/commit/83e65e136a10a964762879378451558457d5f853))

- Role profile integration ([`5cc7164`](https://github.com/agritheory/saml/commit/5cc71649a1ff82e2705eb0bf3d63c631eb78da8e))

- Saml integration ([`47d7d1d`](https://github.com/agritheory/saml/commit/47d7d1de9855443701fb40715ef1a6333c0be846))

Co-authored-by:devansh19299 Co-authored-by:revant

### Testing

- Add role profile fixture ([`591bc84`](https://github.com/agritheory/saml/commit/591bc844ea7d1ade21bbbb3ff198268b9431e13f))

- Add test setup function ([`720cc8d`](https://github.com/agritheory/saml/commit/720cc8dc56f84c83b8300a21b6f2f248a45bd170))

- Apply SAML roles using new toggle ([`7868a6d`](https://github.com/agritheory/saml/commit/7868a6dd5ed458496bdbeaabb8e223d7dcc26074))

- Detect bench port to generate realm export file ([`e4d4a48`](https://github.com/agritheory/saml/commit/e4d4a480aae21039314848b1a5d51876db0e06a1))


### Changes from Pull Requests

Maps SAML roles to Frappe user roles and role profiles, fixing issues with role management.
  _Source: PR #8_

Added SAML keycloak fixtures for improved testing and configuration. Fixed issues with poetry config and provisioned Keycloak realm in tests. Updated README and added new files for SAML support.
  _Source: PR #7_
