Static confidant docs
=====================

## Updating the docs

Localized strings:

* locales/en.yml

Partials for nav, search and tracking:

* source/partials

Basic and advanced docs (in markdown):

* source/basic
* source/advanced

Landing page and footer:

* source/localizable

All images:

* source/images

### Running a local middleman test server to view changes

```
bundle exec middleman server
```

## Building the static site

```
bundle exec middleman build
```

## Publishing changes to github.io

```
bundle exec middleman deploy
```

## Copyright

Copyright (c) Lyft, Inc. [Creative Commons Attribution 3.0 Unported License](http://creativecommons.org/licenses/by/3.0/).
