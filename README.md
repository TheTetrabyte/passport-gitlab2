# passport-gitlub

Forked from [fh1ch/passport-gitlab2](https://github.com/fh1ch/passport-gitlub)
But modified to work with [Gitlub](https://gitlub.club)

[![npm version](https://badge.fury.io/js/passport-gitlub.svg)](http://badge.fury.io/js/passport-gitlub)
[![Build Status](https://travis-ci.org/thetetrabyte/passport-gitlub.svg?branch=master&style=flat)](https://travis-ci.org/thetetrabyte/passport-gitlub)
[![Coverage Status](https://coveralls.io/repos/thetetrabyte/passport-gitlub/badge.svg?branch=master)](https://coveralls.io/r/thetetrabyte/passport-gitlub?branch=master)
[![Code Climate](https://codeclimate.com/github/thetetrabyte/passport-gitlub/badges/gpa.svg)](https://codeclimate.com/github/thetetrabyte/passport-gitlub)
[![Dependency Status](https://david-dm.org/thetetrabyte/passport-gitlub.svg?theme=shields.io)](https://david-dm.org/thetetrabyte/passport-gitlub)

[Passport](http://passportjs.org/) strategy for authenticating with
[Gitlub](https://gitlub.club/) using the OAuth2 authentication provider service.

This module lets you authenticate using GitLab in your Node.js applications.
By plugging into Passport, GitLab authentication can be easily and
unobtrusively integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/).

## Install

```bash
$ npm install passport-gitlub
```

## Usage

Passport-Gitlub requires GitLab 7.7.0 or higher to work. Before using the OAuth2
authentication provider service, you have register a new application in your
[user profile](https://gitlab.com/profile/applications) or in the administrator
portal. GitLab will then issue an application ID and a secret, which need to be
provided to the strategy. You will also need to configure a redirect URI which
matches the route in your application.

#### Configure Strategy

The GitLab authentication strategy authenticates users using a GitLab
account and OAuth 2.0 tokens. The app ID and secret obtained when creating an
application are supplied as options when creating the strategy. The strategy
also requires a `verify` callback, which receives the access token and optional
refresh token, as well as `profile` which contains the authenticated user's
GitLab profile. The `verify` callback must call `cb` providing a user to
complete authentication.

```js
passport.use(new GitLubStrategy({
    clientID: GITLUB_APP_ID,
    clientSecret: GITLUB_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/gitlub/callback"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({gitlubId: profile.id}, function (err, user) {
      return cb(err, user);
    });
  }
));
```

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'gitlub'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

```js
app.get('/auth/gitlub', passport.authenticate('gitlub'));

app.get('/auth/gitlub/callback',
  passport.authenticate('gitlub', {
    failureRedirect: '/login'
  }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/');
  });
```

## FAQ

##### How do I change permissions / scope when obtaining a user profile?

GitLab supports two scopes at the moment which are `read_user` and `api`. By
default, the `read_user` scope is used which was introduced with **GitLab
version 8.15** and requires at least this version. If you have an older version
or you need full read/write access to all API resources, use the `api` scope
instead. Changing the OAuth2 scope to `api` works as following:

```js
app.get('/auth/gitlub',
  passport.authenticate('gitlub', {
    scope: ['api']
  }));
```

More information can be found in the [official GitLab documentation](https://docs.gitlab.com/ce/integration/oauth_provider.html#authorized-applications).

## Contributing

We appreciate contributions in several forms, e.g. documentation, testing,
coding, issues, etc. Please follow the best practice contribution guide as
mentioned below when submitting code changes:

#### Code style

This module uses the [Google JavaScript Code-Style](https://google.github.io/styleguide/javascriptguide.xml)
and enforces it using [JSCS](http://jscs.info/) as additional linter beneath
[JSHint](http://jshint.com/). These measures ensuring a high level of code
quality and easy maintainability of it. You can test if your changes comply
with the code style by executing:

```bash
$ make lint
```

#### Tests

The test suite is located in the `test/` directory. All new features are
expected to have corresponding test cases. Ensure that the complete test suite
passes by executing:

```bash
$ make test
```

#### Coverage

The test suite covers 100% of the code base. All new feature development is
expected to maintain that level. Coverage reports can be viewed by executing:

```bash
$ make coverage-view
```

## License

[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2016-2017 Fabio Huser <fabio@fh1.ch>

Copyright (c) 2011-2016 Jared Hanson <[http://jaredhanson.net/](http://jaredhanson.net/)>
