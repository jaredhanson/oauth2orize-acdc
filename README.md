# oauth2orize-acdc

[![Version](https://img.shields.io/npm/v/oauth2orize-acdc.svg?label=version)](https://www.npmjs.com/package/oauth2orize-acdc)
[![Build](https://img.shields.io/travis/jaredhanson/oauth2orize-acdc.svg)](https://travis-ci.org/jaredhanson/oauth2orize-acdc)
[![Quality](https://img.shields.io/codeclimate/github/jaredhanson/oauth2orize-acdc.svg?label=quality)](https://codeclimate.com/github/jaredhanson/oauth2orize-acdc)
[![Coverage](https://img.shields.io/coveralls/jaredhanson/oauth2orize-acdc.svg)](https://coveralls.io/r/jaredhanson/oauth2orize-acdc)
[![Dependencies](https://img.shields.io/david/jaredhanson/oauth2orize-acdc.svg)](https://david-dm.org/jaredhanson/oauth2orize-acdc)


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

```bash
$ npm install oauth2orize-acdc
```

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

```js
var acdc = require('oauth2orize-acdc');

server.grant(acdc.grant.acdc(function(client, user, audience, pkce, cb) {
  // TODO: Issue an ACDC code in JWT format.
  var code = issueACDCCode(...);
  return cb(null, code);
}));
```

#### Register ACDC Exchange

Once a client has obtained an ACDC code, it can be exchanged for an access
token.  In order to issue the access token, register the exchange with a
`Server` instance and implement the `issue` callback:

```js
var acdc = require('oauth2orize-acdc');

server.exchange('urn:ietf:params:oauth:grant-type:jwt-acdc', acdc.exchange.jwtACDC(function(client, code, verifier, cb) {
  // TODO:
  // 1. Verify the ACDC code, ensuring that it was issued by an authorization
  //    server with which a trust relationship has been established.
  // 2. Verify that the ACDC code is being exchanged by the client to which it
  //    was issued, by means of PKCE.
  // 3. Issue an access token with the scope granted during the authorization
  //    request.
  var token = issueAccessToken(...);
  return cb(null, token);
}));
```

## Considerations

#### Specification

This module is implemented based on a draft of [Authorization Cross Domain Code 1.0](https://openid.bitbucket.io/draft-acdc-01.html).
As a draft, the specification remains a work-in-progress and is *not* final.
The specification is under discussion within the [Native Applications](http://openid.net/wg/napps/)
working group of [OpenID Foundation](http://openid.net/).  Implementers are
encouraged to track the progress of this specification and update
implementations as necessary.  Furthermore, the implications of relying on
non-final specifications should be understood prior to deployment.

## License

[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2016-2017 Jared Hanson <[http://jaredhanson.net/](http://jaredhanson.net/)>


