# PyGoat
<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
[![All Contributors](https://img.shields.io/badge/all_contributors-9-orange.svg?style=flat-square)](#contributors-)
<!-- ALL-CONTRIBUTORS-BADGE:END -->

intentionally vuln web Application Security in django.
our roadmap build intentionally vuln web Application in django. The Vulnerability can based on OWASP top ten
<br>

Table of Contents
=================

* [pygoat](#pygoat)
   * [Installation](#installation)
      * [From Sources](#from-sources)
      * [Docker Container](#docker-container)
      * [Installation Video](#installation-video)
   * [Uninstallation](#uninstallation)
   * [Solutions](/Solutions/solution.md)
   * [For Developers](/docs/dev_guide.md)

## Installation

### From Sources

To setup the project on your local machine:
<br>

First, Clone the repository using GitHub website or git in Terminal
```
  git clone https://github.com/adeyosemanputra/pygoat.git
  ### To Download a specific branch
  git clone -b <branch_name> https://github.com/adeyosemanputra/pygoat.git
```
### Windows Notes (PowerShell users)

- PyGoat is tested primarily on Linux/macOS. Windows users are recommended to use:
  - **Docker Desktop** (preferred), or
  - **WSL2 (Ubuntu)** for smoother setup.
- On some Windows environments, the `python3` command may not be available by default.
  - If `python3` is not recognized, try using `python` instead (ensure it points to Python 3.x).
- Ensure Python version is **3.10 or 3.11** for best compatibility.
- Some labs rely on Unix-style commands and may behave differently on native Windows shells.


#### Method 1

1. Install all app and python requirements using installer file - `bash installer.sh`
2. Apply the migrations `python3 manage.py migrate`.<br>
3. Finally, run the development server `python3 manage.py runserver`.<br>
4. The project will be available at <http://127.0.0.1:8000> 

#### Method 2

1. Install python3 requirements `pip install -r requirements.txt`.<br> 
2. Apply the migrations `python3 manage.py migrate`.<br>
3. Finally, run the development server `python3 manage.py runserver`.<br>
4. The project will be available at <http://127.0.0.1:8000> 

#### Method 3

1. Install all app and python requirements using `setup.py` file - `pip3 install .`
2. Apply the migrations `python3 manage.py migrate`.<br>
3. Finally, run the development server `python3 manage.py runserver`.<br>
4. The project will be available at <http://127.0.0.1:8000> 

### Docker Container
1. Install [Docker](https://www.docker.com)
2. Run `docker pull pygoat/pygoat` or `docker pull pygoat/pygoat:latest`
3. Run `docker run --rm -p 8000:8000 pygoat/pygoat:latest`
4. Browse to <http://127.0.0.1:8000> 
5. Remove existing image using `docker image rm pygoat/pygoat` and pull again incase of any error

### Publishing to ACR and GHCR

The `Publish containers to ACR and GHCR` workflow
(`.github/workflows/publish-containers.yml`) runs on pushes to `master` or
manually on `master`. It builds the root Dockerfile once for Linux/amd64 and
pushes the same image to both registries:

- `pygoat22283822.azurecr.io/pygoat`
- `ghcr.io/defendercloudv2/pygoat`

Each image receives a full source-commit SHA tag and a moving `latest` tag.
The workflow verifies both tags in both registries against the build digest
before reporting success. Registry pushes are not atomic: if a run fails after
one push, rerun it to finish publishing to both registries.

Azure uses GitHub OIDC with the `pygoat-github-publisher` managed identity,
trusted only for `repo:DefenderCloudV2/pygoat:ref:refs/heads/master`. It has
`AcrPush` scoped to this registry, not the subscription. The Basic-tier registry
and identity are in `rg-pygoat-containers` in East US. The registry incurs Azure
charges; its admin account is disabled and pulls require authentication.
GHCR publishing uses the workflow's `GITHUB_TOKEN` with `packages: write`;
no Azure client secret or personal access token is stored.

The repository has these Actions variables (identifiers, not secrets):

| Variable | Value |
| --- | --- |
| `CONTAINER_AZURE_CLIENT_ID` | `a9e13f92-93bb-47af-b9e9-e9605052df84` |
| `CONTAINER_AZURE_TENANT_ID` | `7070967c-b4ab-4835-84ac-9b51e0369f43` |
| `CONTAINER_AZURE_SUBSCRIPTION_ID` | `22283822-a9ef-446d-927c-08399daccd79` |
| `CONTAINER_ACR_NAME` | `pygoat22283822` |

To run manually:

```sh
gh workflow run publish-containers.yml --repo DefenderCloudV2/pygoat --ref master
gh run list --repo DefenderCloudV2/pygoat --workflow publish-containers.yml
gh run watch RUN_ID --repo DefenderCloudV2/pygoat --exit-status
```

For an authenticated ACR pull:

```sh
az acr login --name pygoat22283822 --subscription 22283822-a9ef-446d-927c-08399daccd79
docker pull pygoat22283822.azurecr.io/pygoat:latest
```

GHCR packages are private by default, even for a public source repository.
Authorized users can authenticate to `ghcr.io` and pull the GHCR image;
publishing does not change package visibility. Existing AKS deployment and
archive-attestation workflows are unchanged. This workflow only publishes
images; it does not deploy PyGoat.

**PyGoat is intentionally vulnerable. Use these images only in an isolated
learning environment, never in production.**

### From Docker-Compose 
1. Install [Docker](https://www.docker.com)
2. Run `docker-compose up` or `docker-compose up -d`

## Populate Challenge Data

PyGoat stores challenge definitions in `challenge/challenge.json`.
To populate the `Challenge` table in the database from this file, use the
built-in Django management command:

### Using Docker Compose

```bash
docker compose exec web python manage.py populate_challenges


### Build Docker Image and Run
1. Clone the repository  &ensp; `git clone https://github.com/adeyosemanputra/pygoat.git` 
2. Build the docker image from Dockerfile using &ensp; `docker build -f Dockerfile -t pygoat .`
3. Run the docker image &ensp;`docker run --rm -p 8000:8000 pygoat:latest`
4. Browse to <http://127.0.0.1:8000> or <http://0.0.0.0:8000> 

### Installation video 

1. From Source using `installer.sh`
 - [Installing PyGoat from Source](https://www.youtube.com/watch?v=7bYBJXG3FRQ)
2. Without using `installer.sh`
 - [![](http://img.youtube.com/vi/rfzQiMeiwso/0.jpg)](http://www.youtube.com/watch?v=rfzQiMeiwso "Installation Pygoat")
3. Install with Mac M1 (using Virtualenv)
 - [![](http://img.youtube.com/vi/rfzQiMeiwso/0.jpg)](https://youtu.be/a5UV7mUw580 "Install with Mac M1 - using Virtualenv")


## Uninstallation

### On Debian/Ubuntu Based Systems
- On Debian/Ubuntu based systems, you can use the `uninstaller.sh` script to uninstall `pygoat` along with all it's dependencies.
- To uninstall `pygoat`, simply run:
```bash
$ bash ./uninstaller.sh
```

### On Other Systems
- On other systems, you can use the `uninstaller.py` script to uninstall `pygoat` along with all it's dependencies
- To uninstall `pygoat`, simply run:
```bash
$ python3 uninstaller.py
```

## Solutions 
<a href="/Solutions/solution.md">Solutions to all challenges</a>

## Contributors ✨

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tr>
    <td align="center"><a href="https://github.com/pwned-17"><img src="https://avatars.githubusercontent.com/u/61360833?v=4?s=100" width="100px;" alt=""/><br /><sub><b>pwned-17</b></sub></a><br /><a href="https://github.com/adeyosemanputra/pygoat/commits?author=pwned-17" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/prince-7"><img src="https://avatars.githubusercontent.com/u/53997924?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Aman Singh</b></sub></a><br /><a href="https://github.com/adeyosemanputra/pygoat/commits?author=prince-7" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/adeyosemanputra"><img src="https://avatars.githubusercontent.com/u/24958168?v=4?s=100" width="100px;" alt=""/><br /><sub><b>adeyosemanputra</b></sub></a><br /><a href="https://github.com/adeyosemanputra/pygoat/commits?author=adeyosemanputra" title="Code">💻</a> <a href="https://github.com/adeyosemanputra/pygoat/commits?author=adeyosemanputra" title="Documentation">📖</a></td>
    <td align="center"><a href="https://github.com/gaurav618618"><img src="https://avatars.githubusercontent.com/u/29380890?v=4?s=100" width="100px;" alt=""/><br /><sub><b>gaurav618618</b></sub></a><br /><a href="https://github.com/adeyosemanputra/pygoat/commits?author=gaurav618618" title="Code">💻</a> <a href="https://github.com/adeyosemanputra/pygoat/commits?author=gaurav618618" title="Documentation">📖</a></td>
    <td align="center"><a href="https://github.com/kUSHAL0601"><img src="https://avatars.githubusercontent.com/u/29600964?v=4?s=100" width="100px;" alt=""/><br /><sub><b>MajAK</b></sub></a><br /><a href="https://github.com/adeyosemanputra/pygoat/commits?author=kUSHAL0601" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/JustinDPerkins"><img src="https://avatars.githubusercontent.com/u/60413733?v=4?s=100" width="100px;" alt=""/><br /><sub><b>JustinPerkins</b></sub></a><br /><a href="https://github.com/adeyosemanputra/pygoat/commits?author=JustinDPerkins" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/Hkakashi"><img src="https://avatars.githubusercontent.com/u/43193113?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Liu Peng</b></sub></a><br /><a href="https://github.com/adeyosemanputra/pygoat/commits?author=Hkakashi" title="Code">💻</a></td>
  </tr>
  <tr>
    <td align="center"><a href="https://github.com/RupakBiswas-2304"><img src="https://avatars.githubusercontent.com/u/75058161?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Metaphor</b></sub></a><br /><a href="https://github.com/adeyosemanputra/pygoat/commits?author=RupakBiswas-2304" title="Code">💻</a></td>
    <td align="center"><a href="https://whokilleddb.github.io"><img src="https://avatars.githubusercontent.com/u/56482137?v=4?s=100" width="100px;" alt=""/><br /><sub><b>whokilleddb</b></sub></a><br /><a href="https://github.com/adeyosemanputra/pygoat/commits?author=whokilleddb" title="Code">💻</a></td>
  </tr>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!
