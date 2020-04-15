# Developer-local docs build

```bash
# Just run the make target
make build_docs
# or directly run the script:
./docs/build.sh
```

The output can be found in `generated/docs`.

# How the confidant website and docs are updated

1. The docs are published to [docs/confidant/latest](https://github.com/lyft/confidant.github.io/tree/master/docs/confidant/latest)
   on every commit to master. This process is handled by Travis with the
  [`publish.sh`](https://github.com/lyft/confidant/blob/master/docs/publish.sh) script.

2. The docs are published to [docs/confidant](https://github.com/lyft/confidant.github.io/tree/master/docs/confidant)
   in a directory named after every tagged commit in this repo. Thus, on every tagged release there
   are snapped docs.

// CRTODO: add documentation and CHANGELOG for group support
