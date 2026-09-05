# Changelog

## [0.7.0](https://github.com/workos/workos-ios/compare/v0.6.0...v0.7.0) (2026-09-05)


### Features

* **pipes:** SDK surface change: Parameter "requestOptions" moved from position 3 to 4 on "Pipes.createDataIntegrationCredential" ([#28](https://github.com/workos/workos-ios/issues/28)) ([164233e](https://github.com/workos/workos-ios/commit/164233edac998b8f7d9631af043f69a4b02db4c7))

## [0.6.0](https://github.com/workos/workos-ios/compare/v0.5.0...v0.6.0) (2026-09-01)


### ⚠ BREAKING CHANGES

* **agents:** SDK surface change: Parameter "sessionSettings" moved from position 1 to 4 on "Agents.createBlueprint" ([#27](https://github.com/workos/workos-ios/issues/27))

### Features

* **agents:** Add blueprint, instance, and session endpoints ([#23](https://github.com/workos/workos-ios/issues/23)) ([9af71f0](https://github.com/workos/workos-ios/commit/9af71f015b36051b35a40c58f6b3de7945c18e31))
* **agents:** SDK surface change: Parameter "sessionSettings" moved from position 1 to 4 on "Agents.createBlueprint" ([#27](https://github.com/workos/workos-ios/issues/27)) ([b0b3a37](https://github.com/workos/workos-ios/commit/b0b3a37461a76ba22b16b91c053cbc35c2df002f))
* **audit_logs:** Change retentionPeriodInDays param to a retention union supporting retention periods ([#23](https://github.com/workos/workos-ios/issues/23)) ([9af71f0](https://github.com/workos/workos-ios/commit/9af71f015b36051b35a40c58f6b3de7945c18e31))
* **organizations:** Add IT contacts endpoints ([#23](https://github.com/workos/workos-ios/issues/23)) ([9af71f0](https://github.com/workos/workos-ios/commit/9af71f015b36051b35a40c58f6b3de7945c18e31))
* **platform_teams:** Add Platform Teams service ([#23](https://github.com/workos/workos-ios/issues/23)) ([9af71f0](https://github.com/workos/workos-ios/commit/9af71f015b36051b35a40c58f6b3de7945c18e31))
* **sso:** Add connection management and SAML certificate endpoints ([#23](https://github.com/workos/workos-ios/issues/23)) ([9af71f0](https://github.com/workos/workos-ios/commit/9af71f015b36051b35a40c58f6b3de7945c18e31))
* **sso:** Make code optional on getProfileAndToken ([#23](https://github.com/workos/workos-ios/issues/23)) ([9af71f0](https://github.com/workos/workos-ios/commit/9af71f015b36051b35a40c58f6b3de7945c18e31))
* **user_management:** Add email-completion grant and waitlist endpoints ([#23](https://github.com/workos/workos-ios/issues/23)) ([9af71f0](https://github.com/workos/workos-ios/commit/9af71f015b36051b35a40c58f6b3de7945c18e31))
* **webhooks:** Add agent instance and blueprint webhook event types ([#23](https://github.com/workos/workos-ios/issues/23)) ([9af71f0](https://github.com/workos/workos-ios/commit/9af71f015b36051b35a40c58f6b3de7945c18e31))


### Bug Fixes

* **sso:** Remove DiscordOAuth, GrokOAuth, and XOAuth from connection type enums ([#23](https://github.com/workos/workos-ios/issues/23)) ([9af71f0](https://github.com/workos/workos-ios/commit/9af71f015b36051b35a40c58f6b3de7945c18e31))


### Miscellaneous Chores

* release 0.6.0 ([3dfad4a](https://github.com/workos/workos-ios/commit/3dfad4aaf726d828cd903ca822c056886319b2cb))

## [0.5.0](https://github.com/workos/workos-ios/compare/v0.4.0...v0.5.0) (2026-08-11)


### Features

* **events:** Change required status for parameter `Events.list.events` ([#20](https://github.com/workos/workos-ios/issues/20)) ([3aa63f0](https://github.com/workos/workos-ios/commit/3aa63f031e866d21b4f2975025295f952b84e130))
* **groups:** SDK surface change: Parameter "requestOptions" moved from position 5 to 6 on "Groups.listOrganizationGroups" ([#20](https://github.com/workos/workos-ios/issues/20)) ([3aa63f0](https://github.com/workos/workos-ios/commit/3aa63f031e866d21b4f2975025295f952b84e130))
* **user_management:** SDK surface change: Parameter type changed for "verificationId" on "UserManagement.authenticateWithRadarSmsChallenge" ([#20](https://github.com/workos/workos-ios/issues/20)) ([3aa63f0](https://github.com/workos/workos-ios/commit/3aa63f031e866d21b4f2975025295f952b84e130))


### Bug Fixes

* parse AuthKit Actions request into flat ActionContext ([#19](https://github.com/workos/workos-ios/issues/19)) ([8ee6a8d](https://github.com/workos/workos-ios/commit/8ee6a8d0388d0a995829dd9d14ca918d8bbbf52f))

## [0.4.0](https://github.com/workos/workos-ios/compare/v0.3.0...v0.4.0) (2026-07-28)


### Features

* **generated:** SSO (batch 16283437) ([#16](https://github.com/workos/workos-ios/issues/16)) ([9a64edc](https://github.com/workos/workos-ios/commit/9a64edc7e10ae212993525ae0b9220ebb2a0ab24))
* **pipes:** SDK surface change: Parameter "requestOptions" moved from position 4 to 5 on "Pipes.authorizeDataIntegration" ([#14](https://github.com/workos/workos-ios/issues/14)) ([6849ca5](https://github.com/workos/workos-ios/commit/6849ca515b48e13d65a271f29b0640fd3fe024b0))

## [0.3.0](https://github.com/workos/workos-ios/compare/v0.2.1...v0.3.0) (2026-07-27)


### Features

* **helpers:** clientId override on PKCE code exchanges ([#12](https://github.com/workos/workos-ios/issues/12)) ([1653f68](https://github.com/workos/workos-ios/commit/1653f68c6184a056e8f7a07bd80f777f90145a4a))

## [0.2.1](https://github.com/workos/workos-ios/compare/v0.2.0...v0.2.1) (2026-07-27)


### Bug Fixes

* Detect revoked refresh token via invalid_grant regardless of status ([#10](https://github.com/workos/workos-ios/issues/10)) ([736e2db](https://github.com/workos/workos-ios/commit/736e2dbdd145e779b35e6036f4cadb1f58478b95))
* identify as iOS in the User-Agent header ([51d78f9](https://github.com/workos/workos-ios/commit/51d78f9c65c8efdf9ad89e35ba57c7bb675b76fa))

## [0.2.0](https://github.com/workos/workos-ios/compare/v0.1.1...v0.2.0) (2026-07-23)


### Features

* lower deployment targets to the iOS 16 generation ([#7](https://github.com/workos/workos-ios/issues/7)) ([8060ff2](https://github.com/workos/workos-ios/commit/8060ff28ccf593084e20b83328f7259616e325b8))

## [0.1.1](https://github.com/workos/workos-ios/compare/v0.1.0...v0.1.1) (2026-07-22)


### Bug Fixes

* **docs:** add root redirect to documentation landing page ([a746573](https://github.com/workos/workos-ios/commit/a74657356c1804455d0a9332efb0e346a6593acc))

## [0.1.0](https://github.com/workos/workos-ios/compare/v0.0.1...v0.1.0) (2026-07-21)


### Features

* hand-maintained non-spec endpoints and helper layer (H01-H19) ([6e63a62](https://github.com/workos/workos-ios/commit/6e63a62b0f58b8c2856b48268313a34842aaba3d))
* regenerate the docs content ([39e225a](https://github.com/workos/workos-ios/commit/39e225ae5547d9290c36ab6b01931bdd4a912cc8))


### Bug Fixes

* track Sources/WorkOS and Tests/WorkOSTests with canonical casing ([a1c6376](https://github.com/workos/workos-ios/commit/a1c6376405091be82633214e58d92cfce870edf1))

## [0.0.1]

First commit
