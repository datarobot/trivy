## How to release our fork

It uses goreleaser: https://goreleaser.com/customization/release/#github

What you need to release?

`GITHUB_TOKEN` set to a GitHub API token that has release permissions

Logged into Docker Hub with a user that has permission to write images to datarobotdev/trivy

Make a tag that represents the version we are "forking".

I typically pick the latest release from the upstream, for example v0.48.3

I would do

```
git checkout v0.48.3
git checkout -b u/v0.48.3
git checkout main_datarobot
git rebase u/v0.48.3
git push -f
git tag v0.48.3-dr1
git push origin v0.48.3-dr1
```
then I'm ready to run the releaser that will build and push everything

To try out the release and make sure it should work:

https://goreleaser.com/quick-start/?h=dry+run#dry-run


```
goreleaser -f goreleaser-datarobot.yml build --clean
```

Make sure that works then:

```
goreleaser -f goreleaser-datarobot.yml release --clean

```

You probably will have some docker error:

```
docker context use default
```
should fix it, then run again


To update the drone-trivy plugin, just run the main branch build from the harness ui.
It is built from the latest tag of our forked trivy repo
