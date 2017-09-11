# oauth2orize-acdc

[OAuth2orize](https://github.com/jaredhanson/oauth2orize) extensions providing
support for [Authorization Cross Domain Code](https://openid.bitbucket.io/draft-acdc-01.html).

ACDC provides an authorization grant that decouples authorization from access
token issuance.  An authorization server is used to obtain authorization, which
is represented in the form of an authorization cross domain code.  This cross
domain code can be exchanged for an access token at an authorization server that
exists within a separate domain (provided appropriate level of trust has been
established).

This functionality allows for a form of federation in which access tokens are
issued by a single authoritative authorization server, while authorization (and
consent) can be obtained from an external authorization server.  Such a
deployment model is particularly relevant to SaaS providers that offer business
solutions.

## Install

    $ npm install oauth2orize-acdc

## Usage

#### Register Extensions

ACDC depends on audience indicators and PKCE.  These extensions must be
registered independently by requiring [oauth2orize-audience](https://github.com/jaredhanson/oauth2orize-audience)
and [oauth2orize-pkce](https://github.com/jaredhanson/oauth2orize-pkce):

```js
server.grant(require('oauth2orize-audience').extensions());
server.grant(require('oauth2orize-pkce').extensions());
```

#### Register ACDC Grant

A client will request an ACDC grant by setting `response_type` to `acdc` in an
authorization request.  In order to issue such a grant, register the grant with
a `Server` instance, and implement the `issue` callback:

```javascript
var acdc = require('oauth2orize-acdc');

server.grant(acdc.grant.acdc(function(client, user, audience, pkce, cb) {
  // TODO: Issue a ACDC code in JWT format.
  var code = generate(...);
  return cb(null, code);
}));
```

#### Register ACDC Exchange

Once a client has obtained an ACDC code, it can be exchanged for an access
token.  In order to issue the access token, register the exchange with a
`Server` instance and implement the `issue` callback:

```javascript
var acdc = require('oauth2orize-acdc');

server.exchange('urn:ietf:params:oauth:grant-type:jwt-acdc', acdc.exchange.jwtACDC(function(client, acdc, verifier, cb) {
  // TODO: Verify ACDC code and issue access token
  verify(acdc, verifier, function(err) {
    if (err) { return cb(err); }
    var token = generate(...);
    return cb(null, token);
  });
}));
```

## Contributing

#### Tests

The test suite is located in the `test/` directory.  All new features are
expected to have corresponding test cases.  Ensure that the complete test suite
passes by executing:

```bash
$ make test
```

#### Coverage

All new feature development is expected to have test coverage.  Patches that
increse test coverage are happily accepted.  Coverage reports can be viewed by
executing:

```bash
$ make test-cov
$ make view-cov
```

## Support

#### Funding

This software is provided to you as open source, free of charge.  The time and
effort to develop and maintain this project is volunteered by [@jaredhanson](https://github.com/jaredhanson).
If you (or your employer) benefit from this project, please consider a financial
contribution.  Your contribution helps continue the efforts that produce this
and other open source software.

Funds are accepted via [PayPal](https://paypal.me/jaredhanson), [Venmo](https://venmo.com/jaredhanson),
and [other](http://jaredhanson.net/pay) methods.  Any amount is appreciated.

## License

[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2016-2017 Jared Hanson <[http://jaredhanson.net/](http://jaredhanson.net/)>
