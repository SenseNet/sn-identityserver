# Docker image workflow

The repository-owned `docker-image.yml` workflow builds the IdentityServer
image from `src/SenseNet.IdentityServer4.Web/Dockerfile` with `src` as the
Docker build context. It publishes `sensenetcsp/sn-identityserver` to Docker
Hub.

Pushes to `develop` and `main` build and publish automatically. Pull requests
targeting either branch perform build-only validation and never log in or push.
Manual runs use the branch selected in GitHub's **Run workflow** dialog and do
not publish unless `push_image` is enabled.

Published images receive the source branch tag, an immutable
`YYYYMMDD-shortSHA` tag, and the legacy TFS-compatible date tag:

- `develop.YYYY.MM.DD` on `develop`;
- `YYYY.MM.DD` on `main`.

Automatic `develop` publishes also update `preview`, while automatic `main`
publishes update `latest`. A manual publishing run may add a `custom_tag`.

The workflow requires these repository secrets for publishing:

- `DOCKERHUB_USERNAME`
- `DOCKERHUB_TOKEN`

TFS definition 348 downloads the `Sn-Deployment` artifact only for generic
Docker build, tag, login, push, logout, and runner-cleanup scripts. Its active
IdentityServer build is a plain Docker build with this repository's Dockerfile
and `src` context; it has no active private-feed preparation or generated build
asset that must be reproduced here.

The current Dockerfile's Node 14 installation was validated by a full pushless
build. The deleted `hotfix/node-version-in-dockerfile` remote branch contained
the same Node version and checksum already present on `develop`, so it is not
part of this migration.
