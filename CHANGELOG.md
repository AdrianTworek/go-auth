# Changelog

## [1.2.0](https://github.com/AdrianTworek/go-auth/compare/v1.1.0...v1.2.0) (2025-08-06)


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
* **fiber:** router adapter and example ([5c20a2f](https://github.com/AdrianTworek/go-auth/commit/5c20a2f2499d2cb5dfb00c1c943d1198884c7b02))
* **gin:** router adapter and example ([d983855](https://github.com/AdrianTworek/go-auth/commit/d98385514071a0c8fcf0111650deae77ed950207))
* login after registration option ina auth client conifg ([3c9ac85](https://github.com/AdrianTworek/go-auth/commit/3c9ac85b29352960c33fce16cb59bad6ca3f1033))
* setup and prepare app testing with testcontainers ([51b7fbb](https://github.com/AdrianTworek/go-auth/commit/51b7fbb1bcbd196a4a053c414d000ca0af6841dd))


### Bug Fixes

* **core:** add defered tx rollback after transaction is created ([74852ef](https://github.com/AdrianTworek/go-auth/commit/74852efa82421f714498f187ee9e06ff610e9d59))
* **core:** handle potential transaction error ([9667846](https://github.com/AdrianTworek/go-auth/commit/96678467f0dd2cd60e6abf470f7293e371697f1a))
* **core:** unhandled error ([3e7d7b2](https://github.com/AdrianTworek/go-auth/commit/3e7d7b23ad7ede4e1a59b32b4b935299432367b1))
* **core:** update all store methods to have tx as second arg ([4348011](https://github.com/AdrianTworek/go-auth/commit/4348011f90e4c2d6e97ffe64e18fa38818bcc0d5))
* **examples:** hook function in example did not return redirect ([44caeb4](https://github.com/AdrianTworek/go-auth/commit/44caeb4473bee4d12c632d41ae4312a7bd5a2f69))
* user proper test .env file in ci ([0dae2c4](https://github.com/AdrianTworek/go-auth/commit/0dae2c4d95efbba538c8891aad26ef36c464b771))

## [1.1.0](https://github.com/AdrianTworek/go-auth/compare/v1.0.0...v1.1.0) (2025-03-20)


### Features

* trigger automated changelog generation ([9c904a9](https://github.com/AdrianTworek/go-auth/commit/9c904a9d5a979e18621df36ad472f06aacb0d7b2))

## 1.0.0 (2025-03-20)


### Features

* trigger automated changelog generation ([9c904a9](https://github.com/AdrianTworek/go-auth/commit/9c904a9d5a979e18621df36ad472f06aacb0d7b2))
