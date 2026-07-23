# Changelog

## [1.5.0](https://github.com/AdrianTworek/go-auth/compare/v1.4.0...v1.5.0) (2026-07-23)


### Features

* **core:** add session management endpoints ([d23e2d4](https://github.com/AdrianTworek/go-auth/commit/d23e2d4e8110859620eb5c0c44e65569e5e2647c))
* **core:** add session management endpoints (list/revoke) ([6186a8e](https://github.com/AdrianTworek/go-auth/commit/6186a8ef384d7bffae23fa3aa3ba4bf65a3b11d1))

## [1.4.0](https://github.com/AdrianTworek/go-auth/compare/v1.3.2...v1.4.0) (2026-07-15)


### Features

* **adapters:** share canonical route paths and add a conformance test ([d4fa9ad](https://github.com/AdrianTworek/go-auth/commit/d4fa9ad82c6dddb77a50776bd765d3a1adb7e03c))
* **adapters:** share canonical route paths and add a conformance test ([845c03c](https://github.com/AdrianTworek/go-auth/commit/845c03ca5814b00f30efd91f5e43404c61c7b3a6))
* **core:** add cancel link and completion notice to email change ([18b5cdf](https://github.com/AdrianTworek/go-auth/commit/18b5cdfc190b6abe4d15a84132576f44839f6a94))
* **core:** add protected change-password and change-email handlers ([0517da9](https://github.com/AdrianTworek/go-auth/commit/0517da9671f39e594fc3321d947b4c0a9452afb2))
* **core:** add protected change-password and change-email handlers ([5557f84](https://github.com/AdrianTworek/go-auth/commit/5557f84547e73504e6e98e4aadb35a760f74e1cd))
* **core:** add resend-verification endpoint ([7d11e06](https://github.com/AdrianTworek/go-auth/commit/7d11e06e480a49c1f3ff53209d850c8be5ed0d63))
* **core:** add resend-verification endpoint ([f0c0914](https://github.com/AdrianTworek/go-auth/commit/f0c09149a9856da24ee37d9e2c73ab1ccae0364f))
* **core:** configurable session and token durations ([e279bf2](https://github.com/AdrianTworek/go-auth/commit/e279bf20a8eed9e6d452c66244985183fb21e2a1))
* **core:** configurable session and token durations ([6d62bcc](https://github.com/AdrianTworek/go-auth/commit/6d62bcc80a41067b1fe4b5ed2a9fc62805e6acbe))
* **core:** harden email change — old-address notification, cancel link, completion notice ([75d82a5](https://github.com/AdrianTworek/go-auth/commit/75d82a5d4039eeb7ec8083c24e7a3d002b0eb149))
* **core:** notify the old address when an email change is requested ([97450d8](https://github.com/AdrianTworek/go-auth/commit/97450d83d916d6754fc045bfa6b89239d6e93718))


### Bug Fixes

* bump the go-minor-patch group with 3 updates ([9f6f160](https://github.com/AdrianTworek/go-auth/commit/9f6f160918cf3df2a6e9c5f91984911b4bcdf2db))
* bump the go-minor-patch group with 3 updates ([6aab48b](https://github.com/AdrianTworek/go-auth/commit/6aab48b4946cddb47cdb83985e200dfdb3b95778))

## [1.3.2](https://github.com/AdrianTworek/go-auth/compare/v1.3.1...v1.3.2) (2026-06-28)


### Bug Fixes

* bump the go-minor-patch group with 2 updates ([0c61779](https://github.com/AdrianTworek/go-auth/commit/0c61779d27d5f933e45b817ce30202323a8669cf))
* bump the go-minor-patch group with 2 updates ([a2e746e](https://github.com/AdrianTworek/go-auth/commit/a2e746e25f7b65b75153f606dcebe626649bd13b))

## [1.3.1](https://github.com/AdrianTworek/go-auth/compare/v1.3.0...v1.3.1) (2026-06-28)


### Miscellaneous Chores

* release 1.3.1 ([887bb50](https://github.com/AdrianTworek/go-auth/commit/887bb506a5b917ae8278405fbe5fccf60aa55872))

## [1.3.0](https://github.com/AdrianTworek/go-auth/compare/v1.2.0...v1.3.0) (2026-06-28)


### Features

* **core:** configurable verified-email policy, longer passwords, TEXT user_agent ([9f88595](https://github.com/AdrianTworek/go-auth/commit/9f885955fa4cfd8da3773ba0e574cf0e0e29ee5e))
* **core:** secure-by-default session cookie and OAuth secret validation, examples update ([7960974](https://github.com/AdrianTworek/go-auth/commit/796097435b3cb566f3b9975a3d94e92ab52f73f3))
* **examples:** add gorilla mux ([574da64](https://github.com/AdrianTworek/go-auth/commit/574da6468c6bbf03ac66c8841037090212b7b7ae))
* **examples:** add net/http standard library example and adapter ([d0f292d](https://github.com/AdrianTworek/go-auth/commit/d0f292d724f01c65d4e9e1c012456e5013c7e843))


### Bug Fixes

* **core:** atomic single-use tokens and session revocation on password reset ([1d5867a](https://github.com/AdrianTworek/go-auth/commit/1d5867a5948ed70d2e1deb5a616f05aa7ede513c))
* **core:** honor email-verification-failed hook and verify magic-link users ([5ad96e5](https://github.com/AdrianTworek/go-auth/commit/5ad96e540f8ce7d33fe95754a006e356c6aab361))
* **core:** OAuth account-linking panic, typo fixes, and broader test coverage ([9677ce5](https://github.com/AdrianTworek/go-auth/commit/9677ce51bf507fbd8eb853468922e6758e105def))
* **core:** stop leaking internal errors and reduce account enumeration ([6b20db2](https://github.com/AdrianTworek/go-auth/commit/6b20db2e9af0023fe0ec02102b8083eff7cb46b4))
* **core:** store session and verification tokens as SHA-256 hashes ([dc4e1bb](https://github.com/AdrianTworek/go-auth/commit/dc4e1bb0dc9c46956c12a7652e353e0ff4963767))
* **core:** update session config default and improve error handling in handlers ([b9d4992](https://github.com/AdrianTworek/go-auth/commit/b9d4992535cb15aaf0049eedf7ca4238d0070550))

## [1.2.0](https://github.com/AdrianTworek/go-auth/compare/v1.1.0...v1.2.0) (2026-06-07)


### Features

* **chi:** router adapter and example ([0cbfdc7](https://github.com/AdrianTworek/go-auth/commit/0cbfdc7bfa50302ba52fe0a0ba30487d1ad76a3f))
* **core:** add additional guard to ensure user does not setup goth if not oauth config is provided ([cf818d4](https://github.com/AdrianTworek/go-auth/commit/cf818d47c3036ea59715445891d014bd7dc81b6e))
* **core:** add more hook events ([b2411d6](https://github.com/AdrianTworek/go-auth/commit/b2411d673fdaea8d94c8a8d46bbee29df6f2a23c))
* **core:** add option to prematurely respond from hook functions ([f90872f](https://github.com/AdrianTworek/go-auth/commit/f90872fc226ca1c798bda650f748207da1497481))
* **core:** add redirect response to hook functions ([2fae884](https://github.com/AdrianTworek/go-auth/commit/2fae88427092a19b4bbe61a927e640f6b7a99e5d))
* **core:** finalize magic link flow ([f9ff4db](https://github.com/AdrianTworek/go-auth/commit/f9ff4db160a3b25bb1b4a2ae100d5f296f8ba9e7))
* **core:** handlers, middleware and utils ([1a5c367](https://github.com/AdrianTworek/go-auth/commit/1a5c367b0b4cea65b9fd417f1071ce3341e33a7a))
* **core:** implement hooks that work triggered by events ([6707c20](https://github.com/AdrianTworek/go-auth/commit/6707c20cdf46a940c198467a6defd3362f3b90a9))
* **core:** initial auth client and config ([7e9a170](https://github.com/AdrianTworek/go-auth/commit/7e9a170a051ab16356e3533738938cfadc94543d))
* **core:** internal implementations - db, auth, store ([7f02210](https://github.com/AdrianTworek/go-auth/commit/7f02210477ffd426fddbab2a04461832550899f6))
* **core:** oauth with user configuration ([fba97fd](https://github.com/AdrianTworek/go-auth/commit/fba97fdcdbac39e0b9f28c0e3c544d5c4ee174b9))
* **core:** redirect to frontend after one time password login ([886dcb1](https://github.com/AdrianTworek/go-auth/commit/886dcb1184ae3d57af553e6a4f79fb67a10b07b2))
* env config and default mailer implementation ([0e84bcf](https://github.com/AdrianTworek/go-auth/commit/0e84bcff7df10213b0af95eaafb39b39f9610357))
* **examples:** add echo ([870dd49](https://github.com/AdrianTworek/go-auth/commit/870dd4950eda038786c65a26b66cf1ec92efa0f1))
* **fiber:** router adapter and example ([5c20a2f](https://github.com/AdrianTworek/go-auth/commit/5c20a2f2499d2cb5dfb00c1c943d1198884c7b02))
* **gin:** router adapter and example ([d983855](https://github.com/AdrianTworek/go-auth/commit/d98385514071a0c8fcf0111650deae77ed950207))
* login after registration option ina auth client conifg ([3c9ac85](https://github.com/AdrianTworek/go-auth/commit/3c9ac85b29352960c33fce16cb59bad6ca3f1033))
* setup and prepare app testing with testcontainers ([51b7fbb](https://github.com/AdrianTworek/go-auth/commit/51b7fbb1bcbd196a4a053c414d000ca0af6841dd))


### Bug Fixes

* **core:** add defered tx rollback after transaction is created ([74852ef](https://github.com/AdrianTworek/go-auth/commit/74852efa82421f714498f187ee9e06ff610e9d59))
* **core:** handle potential transaction error ([9667846](https://github.com/AdrianTworek/go-auth/commit/96678467f0dd2cd60e6abf470f7293e371697f1a))
* **core:** unhandled error ([3e7d7b2](https://github.com/AdrianTworek/go-auth/commit/3e7d7b23ad7ede4e1a59b32b4b935299432367b1))
* **core:** update all store methods to have tx as second arg ([4348011](https://github.com/AdrianTworek/go-auth/commit/4348011f90e4c2d6e97ffe64e18fa38818bcc0d5))
* **examples:** github oauth email scope ([439699c](https://github.com/AdrianTworek/go-auth/commit/439699c6204ab5be8e0171b5f2417bd315baad53))
* **examples:** hook function in example did not return redirect ([44caeb4](https://github.com/AdrianTworek/go-auth/commit/44caeb4473bee4d12c632d41ae4312a7bd5a2f69))
* user proper test .env file in ci ([0dae2c4](https://github.com/AdrianTworek/go-auth/commit/0dae2c4d95efbba538c8891aad26ef36c464b771))

## [1.1.0](https://github.com/AdrianTworek/go-auth/compare/v1.0.0...v1.1.0) (2025-03-20)


### Features

* trigger automated changelog generation ([9c904a9](https://github.com/AdrianTworek/go-auth/commit/9c904a9d5a979e18621df36ad472f06aacb0d7b2))

## 1.0.0 (2025-03-20)


### Features

* trigger automated changelog generation ([9c904a9](https://github.com/AdrianTworek/go-auth/commit/9c904a9d5a979e18621df36ad472f06aacb0d7b2))
