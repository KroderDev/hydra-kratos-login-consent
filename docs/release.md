# Image Release And Verification

The container image is published to GitHub Container Registry at:

```text
ghcr.io/kroderdev/hydra-kratos-login-consent
```

The release workflow builds `linux/amd64` and `linux/arm64` images. Pull
requests build and scan both architectures without publishing. Version tags
publish a temporary candidate first; promotion occurs only after vulnerability
scanning, attestations, and signature verification succeed.

## Image References

Deployments must use the digest of the verified multi-architecture image:

```text
ghcr.io/kroderdev/hydra-kratos-login-consent@sha256:<digest>
```

The workflow also creates write-once `vX.Y.Z` and `sha-<commit>` aliases for
the same digest. It never publishes or requires a `latest` tag. A release rerun
must refuse to replace an existing alias with a different digest.

## Verification

The release workflow uses keyless Cosign signing through GitHub Actions OIDC.
The trusted certificate identity is the tag invocation of the container release
workflow, and the OIDC issuer is `https://token.actions.githubusercontent.com`.

Set the exact published digest and tag in the commands below:

```sh
IMAGE=ghcr.io/kroderdev/hydra-kratos-login-consent@sha256:<digest>
IDENTITY=https://github.com/KroderDev/hydra-kratos-login-consent/.github/workflows/container-release.yml@refs/tags/vX.Y.Z
ISSUER=https://token.actions.githubusercontent.com

cosign verify \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER" \
  "$IMAGE"

for ARCH in amd64 arm64; do
  PLATFORM_DIGEST="$(docker buildx imagetools inspect --raw "$IMAGE" | \
    jq -er --arg arch "$ARCH" '
      .manifests[]
      | select(.platform.os == "linux" and .platform.architecture == $arch)
      | .digest
    ')"
  cosign verify-attestation \
    --type https://spdx.dev/Document/v2.3 \
    --certificate-identity "$IDENTITY" \
    --certificate-oidc-issuer "$ISSUER" \
    "ghcr.io/kroderdev/hydra-kratos-login-consent@$PLATFORM_DIGEST"
done

cosign verify-attestation \
  --type https://slsa.dev/provenance/v1 \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER" \
  "$IMAGE"
```

The image must not be deployed when any verification command fails. Record the
verified digest and attestation results with the deployment so rollback returns
to the same artifact.

## Release Controls

The `container-publish` GitHub environment must be protected with required
reviewers and restricted to trusted `v*` tags. The workflow requires no Docker
Hub credentials, Cosign private key, or other signing secret. GHCR access uses
the workflow `GITHUB_TOKEN`; signing and attestations use short-lived OIDC
credentials.

The candidate is scanned for unfixed `HIGH` and `CRITICAL` vulnerabilities on
both platform-specific image digests before promotion. The workflow publishes
an SPDX SBOM attestation for each platform digest and SLSA provenance for the
exact multi-architecture digest. GoReleaser continues to publish the source and
binary release artifacts independently.
