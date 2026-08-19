# Changelog

## [0.5.2](https://github.com/KroderDev/hydra-kratos-login-consent/compare/v0.5.1...v0.5.2) (2026-08-19)


### Bug Fixes

* **ci:** clear stale Trivy DB cache on PR container scans ([3547fc9](https://github.com/KroderDev/hydra-kratos-login-consent/commit/3547fc954db1be22b4f014c8965d1b42da10b761))
* **deps:** upgrade golang.org/x/sys to resolve Trivy vulnerability scan failure ([ebaa1fd](https://github.com/KroderDev/hydra-kratos-login-consent/commit/ebaa1fdb8c2e50c46ca1ad4079d0f30663111cdc))
* **deps:** upgrade golang.org/x/sys to resolve Trivy vulnerability scan failure ([2de6b06](https://github.com/KroderDev/hydra-kratos-login-consent/commit/2de6b061e83a6417c93047046d86a5fb66c4cf7a))

## [0.5.1](https://github.com/KroderDev/hydra-kratos-login-consent/compare/v0.5.0...v0.5.1) (2026-08-19)


### Bug Fixes

* **container:** upgrade Alpine base OS packages to resolve Trivy vulnerability scan failure ([3ec982b](https://github.com/KroderDev/hydra-kratos-login-consent/commit/3ec982b0b189e6ba07a5471bbdc4656718993916))
* **container:** upgrade Alpine base OS packages to resolve Trivy vulnerability scan failure ([69d4295](https://github.com/KroderDev/hydra-kratos-login-consent/commit/69d429522fe702ca48497f105411e25f8ba60cad))


### Documentation

* **configuration:** clarify default 2048, max limit 4096, and server 16 KB header limit for MAX_CHALLENGE_LENGTH ([1daec98](https://github.com/KroderDev/hydra-kratos-login-consent/commit/1daec98a38e1a66703b9658f44ab1fcd6d4c4186))

## [0.5.0](https://github.com/KroderDev/hydra-kratos-login-consent/compare/v0.4.3...v0.5.0) (2026-08-19)


### Features

* **config:** make Hydra challenge length configurable ([30a348e](https://github.com/KroderDev/hydra-kratos-login-consent/commit/30a348ed4a66dcaf9fb7640ff3dc8ba7c2b3a2f0))
* **config:** make Hydra challenge length configurable ([ce7c4cb](https://github.com/KroderDev/hydra-kratos-login-consent/commit/ce7c4cb4f73322e58f2ebe4f3c49472736710be5))


### Bug Fixes

* **config:** adjust MaxChallengeLengthLimit to 4096 bytes for HTTP MaxHeaderBytes budget ([1ada15f](https://github.com/KroderDev/hydra-kratos-login-consent/commit/1ada15f39ace09af092b8f867f18af837afb393a))
* **config:** enforce upper bound limit and add security test suite for challenge validation ([181fd0f](https://github.com/KroderDev/hydra-kratos-login-consent/commit/181fd0fc9003785686c7d00cb02f4eb56b5fdfa0))


### Dependencies

* **deps:** bump github.com/redis/go-redis/v9 in the go-non-major group ([b8add00](https://github.com/KroderDev/hydra-kratos-login-consent/commit/b8add00bb0b69d95dceba537e28dec76abb2a5ad))


### Tests

* **application:** expand statement and branch coverage for helper methods ([7762f38](https://github.com/KroderDev/hydra-kratos-login-consent/commit/7762f3843051d17127f6c444e5d1b7a579bd5a9f))

## [0.4.3](https://github.com/KroderDev/hydra-kratos-login-consent/compare/v0.4.2...v0.4.3) (2026-08-16)


### Bug Fixes

* **security:** isolate HTTPS browser state cookies ([98fb1f7](https://github.com/KroderDev/hydra-kratos-login-consent/commit/98fb1f76bcaffa56e904ea8b7d5781eee783c749))
* **security:** isolate HTTPS browser state cookies ([643f23c](https://github.com/KroderDev/hydra-kratos-login-consent/commit/643f23c46bf8a7b6c0fe7976f2def1df5860eabf))


### Tests

* **security:** cover HTTP browser state cookie fallback ([2c706f2](https://github.com/KroderDev/hydra-kratos-login-consent/commit/2c706f2c91c12672ae45900fee3a35cdf1009b3b))

## [0.4.2](https://github.com/KroderDev/hydra-kratos-login-consent/compare/v0.4.1...v0.4.2) (2026-08-16)


### Bug Fixes

* **config:** allow loopback HTTP client redirects ([9874e6d](https://github.com/KroderDev/hydra-kratos-login-consent/commit/9874e6d6fc23ca7b86f7d04c181e97e7ad60b3c2))
* **config:** allow loopback HTTP client redirects ([a92dc18](https://github.com/KroderDev/hydra-kratos-login-consent/commit/a92dc18c061125a1490e7db9ec1fa21fa77e01aa))
* **config:** restrict loopback redirects to IP literals ([5444528](https://github.com/KroderDev/hydra-kratos-login-consent/commit/5444528c6889842d3c4d8cebf2c8bc62ecc33c87))
* **config:** scope loopback HTTP exception to client redirects ([98a99ed](https://github.com/KroderDev/hydra-kratos-login-consent/commit/98a99ed1a334af35021dddfd8c678c12223114c5))


### Tests

* **config:** drop redundant comments in loopback helper ([1699f7a](https://github.com/KroderDev/hydra-kratos-login-consent/commit/1699f7a4eb652edb0808bc1d69c97992b8f578bd))

## [0.4.1](https://github.com/KroderDev/hydra-kratos-login-consent/compare/v0.4.0...v0.4.1) (2026-08-13)


### Dependencies

* **deps:** bump actions/labeler from 6 to 7 ([a74a738](https://github.com/KroderDev/hydra-kratos-login-consent/commit/a74a738cab40096abdbd61124605245c57e9ee8b))
* **deps:** bump redis in the compose-non-major group ([68b0707](https://github.com/KroderDev/hydra-kratos-login-consent/commit/68b0707cd2fc12036f5bf2114ba255aabd1c13c5))
* **deps:** bump the actions-non-major group with 2 updates ([e25aed4](https://github.com/KroderDev/hydra-kratos-login-consent/commit/e25aed4cadf83937fa0e2f4cc8bb35aa2dca47b8))

## [0.4.0](https://github.com/KroderDev/hydra-kratos-login-consent/compare/v0.3.3...v0.4.0) (2026-08-08)


### Features

* **claims:** add configurable OIDC identity mappings ([c1c6049](https://github.com/KroderDev/hydra-kratos-login-consent/commit/c1c6049aa85df28e9bf3b18dab40e3028b16e4d5))
* **claims:** add configurable OIDC identity mappings ([58da547](https://github.com/KroderDev/hydra-kratos-login-consent/commit/58da5475675f358efdfa5224752020a72aff96be))


### Bug Fixes

* **claims:** restrict uri/url format to HTTP(S) and expand coverage ([a18bb83](https://github.com/KroderDev/hydra-kratos-login-consent/commit/a18bb835e65af0b44029b6d48c9eeea52b4ef401))

## [0.3.3](https://github.com/KroderDev/hydra-kratos-login-consent/compare/v0.3.2...v0.3.3) (2026-08-07)


### Bug Fixes

* **auth:** restore nested return_to callback state ([6f0d6e4](https://github.com/KroderDev/hydra-kratos-login-consent/commit/6f0d6e45520e7ac4acf4070c13725ce833f4a874))
* **auth:** restore nested return_to callback state ([a9878d4](https://github.com/KroderDev/hydra-kratos-login-consent/commit/a9878d4c4699367b8dfc677fa764352e61bd5850))

## [0.3.2](https://github.com/KroderDev/hydra-kratos-login-consent/compare/v0.3.1...v0.3.2) (2026-08-07)


### Bug Fixes

* apply CodeRabbit auto-fixes ([6802b5e](https://github.com/KroderDev/hydra-kratos-login-consent/commit/6802b5e0a013bcdfeb8d2249c794de349c358f8e))
* **auth:** preserve nested return_to query parameters ([f5db0fa](https://github.com/KroderDev/hydra-kratos-login-consent/commit/f5db0fae525578a10baaa661db013584e70c920e))
* **auth:** preserve nested return_to query parameters ([1e14e4c](https://github.com/KroderDev/hydra-kratos-login-consent/commit/1e14e4c3c0a010f021ff752c91a5ba30a3d49557))

## [0.3.1](https://github.com/KroderDev/hydra-kratos-login-consent/compare/v0.3.0...v0.3.1) (2026-08-07)


### Bug Fixes

* **challenge:** bump max length from 512 to 2048 for Hydra v26 compatibility ([575b491](https://github.com/KroderDev/hydra-kratos-login-consent/commit/575b4919d4dad9d29a3876c9bc62d592b439c9bd))
* **challenge:** bump max length from 512 to 2048 for Hydra v26 compatibility ([8b356d5](https://github.com/KroderDev/hydra-kratos-login-consent/commit/8b356d5d1c311598e55ed48a57fe839cbcc7327a)), closes [#20](https://github.com/KroderDev/hydra-kratos-login-consent/issues/20)


### Tests

* **application:** cover challenge length validation boundaries ([985cc6b](https://github.com/KroderDev/hydra-kratos-login-consent/commit/985cc6b91be4ccec4732477933218786186c6190))

## [0.3.0](https://github.com/KroderDev/hydra-kratos-login-consent/compare/v0.2.0...v0.3.0) (2026-08-03)


### Features

* **policy:** add versioned HTTP policy backend ([7dca99c](https://github.com/KroderDev/hydra-kratos-login-consent/commit/7dca99cc0c3ea7eeda090b027ac88dff0c4320d1))
* **policy:** add versioned HTTP policy backend ([13c3c3a](https://github.com/KroderDev/hydra-kratos-login-consent/commit/13c3c3a0efc9a9fb82799e88c236854989176808))


### Bug Fixes

* **policy:** address review feedback ([b229be6](https://github.com/KroderDev/hydra-kratos-login-consent/commit/b229be6a6cc27f7dd95980c76563ede1f2366817))
* **release:** harden immutable image promotion ([89a62b4](https://github.com/KroderDev/hydra-kratos-login-consent/commit/89a62b48abb27de100d0a5438d00bd705e38dea1))


### Build System

* **container:** cross-compile multi-arch images ([0e77837](https://github.com/KroderDev/hydra-kratos-login-consent/commit/0e778373dfba3358239e124ee5c48fdce80d3498))


### Dependencies

* **deps:** bump redis in the compose-non-major group ([514b2bc](https://github.com/KroderDev/hydra-kratos-login-consent/commit/514b2bcc76a0171c0ccc2c6769471aac7082337c))


### Documentation

* **deployment:** document production runtime contract ([5738950](https://github.com/KroderDev/hydra-kratos-login-consent/commit/573895089e85caaac00edaf89800e59f423993bb))
* **deployment:** document production runtime contract ([404ab3e](https://github.com/KroderDev/hydra-kratos-login-consent/commit/404ab3e4c72ab6878bd782bee4c47098e7dcc33f))
* **release:** clarify tag immutability contract ([08d88fa](https://github.com/KroderDev/hydra-kratos-login-consent/commit/08d88fa8a9207e3f45c6049e165ac4cb5c1e4c18))


### Tests

* **policy:** cover remote authorization failure modes ([4608b8b](https://github.com/KroderDev/hydra-kratos-login-consent/commit/4608b8b1c8f39ef5db717402ec60abe0d30e70f4))
* **policy:** cover remote authorization failure modes ([baef6c4](https://github.com/KroderDev/hydra-kratos-login-consent/commit/baef6c4dbc771479a00d2b8581b861e8caa3bf50))


### Continuous Integration

* add pull request labeler workflow and configuration ([532e263](https://github.com/KroderDev/hydra-kratos-login-consent/commit/532e263c98622b21bda43141fd3ce59e38cffdff))
* **release:** isolate container promotion approvals ([15d9adf](https://github.com/KroderDev/hydra-kratos-login-consent/commit/15d9adf999ea6ae8d6d6c4f0d6179c8976a418f8))
* **release:** publish signed OCI images ([a9d3b19](https://github.com/KroderDev/hydra-kratos-login-consent/commit/a9d3b19dfd5ddd40c3432d9ccdc8216382c721e7))
* **release:** skip duplicate multi-arch image tests ([a7451e2](https://github.com/KroderDev/hydra-kratos-login-consent/commit/a7451e2fbd6a151958713d0b9603d4ee97285b5e))

## [0.2.0](https://github.com/KroderDev/hydra-kratos-login-consent/compare/v0.1.0...v0.2.0) (2026-08-03)


### Features

* **provider:** add Hydra Kratos login consent service ([5faebd1](https://github.com/KroderDev/hydra-kratos-login-consent/commit/5faebd1673a6e274eba08559d6c64b09e875cad9))


### Bug Fixes

* **http:** restrict redirect targets to HTTP schemes ([bff8182](https://github.com/KroderDev/hydra-kratos-login-consent/commit/bff8182b892e5c4497115a8d9a2601ed324faab0))
* **security:** harden browser authentication flows ([c4d5992](https://github.com/KroderDev/hydra-kratos-login-consent/commit/c4d59927de912fa16b0cb53f6ba0dde488df9aa9))


### Build System

* **container:** add production image ([4b86548](https://github.com/KroderDev/hydra-kratos-login-consent/commit/4b86548471e88a42ffb6668ba6cc36461d59d811))


### Dependencies

* **deps:** bump codecov/codecov-action from 5 to 7 ([a614751](https://github.com/KroderDev/hydra-kratos-login-consent/commit/a614751bb9afdb13295f3b37923b0feefcd14bf3))
* **deps:** bump github.com/go-chi/chi/v5 in the go-non-major group ([49d3a21](https://github.com/KroderDev/hydra-kratos-login-consent/commit/49d3a21eef425cc08eef646082a1f61f97232e7f))
* **deps:** bump redis from 7.4.2-alpine to 8.0.0-alpine ([5e69178](https://github.com/KroderDev/hydra-kratos-login-consent/commit/5e691785ef72c21ed04ea96c4a7796e8ac5f5f49))
* **deps:** bump the docker-non-major group with 2 updates ([de1494a](https://github.com/KroderDev/hydra-kratos-login-consent/commit/de1494a6123cb44230047f633d5b5695484fc991))


### Documentation

* add contribution guidelines ([94f57e3](https://github.com/KroderDev/hydra-kratos-login-consent/commit/94f57e39afa7c468ccd3e5b0b18c93aff524c8fc))
* add repository guide ([0af7d8b](https://github.com/KroderDev/hydra-kratos-login-consent/commit/0af7d8b5454df620d511415a411b41991a475f2e))
* improve OSS project documentation ([97f68d3](https://github.com/KroderDev/hydra-kratos-login-consent/commit/97f68d35cd7d708b21e96287e92cfd234a60fa72))
* **readme:** add project status badges ([236e8c6](https://github.com/KroderDev/hydra-kratos-login-consent/commit/236e8c6b80b8fa0a89f0fb4d9d2299ecabe622bc))


### Tests

* **e2e:** cover container readiness ([4eac3ac](https://github.com/KroderDev/hydra-kratos-login-consent/commit/4eac3acc05b2f39093720e5764b02707393d9920))
* **e2e:** run Redis fixture on localhost ([0d4ac7c](https://github.com/KroderDev/hydra-kratos-login-consent/commit/0d4ac7c43c8625d95a2897c366d110dfc9f77dc6))
* **provider:** cover failure and lifecycle contracts ([d6951ec](https://github.com/KroderDev/hydra-kratos-login-consent/commit/d6951ec7ce7dad4d2223d28dd38fad3a52b115e5))
* **server:** constrain state store, logger, and startup helper contracts ([f3050e0](https://github.com/KroderDev/hydra-kratos-login-consent/commit/f3050e067b77eb683301c9dff8b7c550646fa39c))


### Continuous Integration

* avoid duplicate Go cache setup ([3a27c00](https://github.com/KroderDev/hydra-kratos-login-consent/commit/3a27c007151402a4fc7ab70830f79ab7e5513410))
* **dependabot:** fix docker cooldown settings ([67be39f](https://github.com/KroderDev/hydra-kratos-login-consent/commit/67be39fbc0c896ab5e6abe134c49ce9b49e0b75e))
* **dependabot:** remove unsupported compose cooldowns ([9925700](https://github.com/KroderDev/hydra-kratos-login-consent/commit/9925700252d69bbb32eae20ee473afd7a402abe5))
* **dependabot:** track GitHub Actions updates ([cb31f42](https://github.com/KroderDev/hydra-kratos-login-consent/commit/cb31f4277424723370793995d7dde0a75cee0602))
* fix lint and security workflows ([86bd27d](https://github.com/KroderDev/hydra-kratos-login-consent/commit/86bd27de69103b96c3c57b67ae4a903c001a3d70))
* pin govulncheck Go version ([5133175](https://github.com/KroderDev/hydra-kratos-login-consent/commit/5133175067384eef62124baa666b31899259cbf3))
* **release:** add GoReleaser workflow ([409d179](https://github.com/KroderDev/hydra-kratos-login-consent/commit/409d179b95ae58c03df5d27ebc5e34fccad3ae05))
* **release:** configure Release Please ([606f084](https://github.com/KroderDev/hydra-kratos-login-consent/commit/606f084673a057d545f63bb8867e195426b909f9))
* rename workflow for main branch ([f2bddde](https://github.com/KroderDev/hydra-kratos-login-consent/commit/f2bddde745fed18539f2319e9e4ebec561ece908))
* upload coverage reports ([7b7a71e](https://github.com/KroderDev/hydra-kratos-login-consent/commit/7b7a71ea0b071ac3bf1f6a41691ceb685f450f14))
