var merge = require('utils-merge')
  , TokenError = require('../errors/tokenerror');


module.exports = function(options, issue) {
  if (typeof options == 'function') {
    issue = options;
    options = undefined;
  }
  options = options || {};
  
  if (!issue) { throw new TypeError('oauth2orize.acdc exchange requires an issue callback'); }
  
  var userProperty = options.userProperty || 'user';

  return function(req, res, next) {
    if (!req.body) { return next(new Error('OAuth2orize requires body parsing. Did you forget app.use(express.bodyParser())?')); }
    
    // The 'user' property of `req` holds the authenticated user.  In the case
    // of the token endpoint, the property will contain the OAuth 2.0 client.
    //
    // The ACDC authorization grant is a profile of JWT authorization grant, as
    // specified in [RFC 5723](https://tools.ietf.org/html/rfc7523).  In
    // accordance with that profile, the cross docmain code is conveyed in a
    // parameter named `assertion`.
    //
    // `code_verifyer` is accepted as an alternative to `code_verifier` to
    // accomodate a misspelling in the draft specifications, and any
    // implementations that may have fallen into that trap.
    var client = req[userProperty]
      , assertion = req.body.assertion
      , verifier = req.body.code_verifier || req.body.code_verifyer;
      
    if (!assertion) { return next(new TokenError('Missing required parameter: assertion', 'invalid_request')); }
    
    function issued(err, accessToken, refreshToken, params) {
      if (err) { return next(err); }
      if (!accessToken) { return next(new TokenError('Invalid authorization code', 'invalid_grant')); }
      if (refreshToken && typeof refreshToken == 'object') {
        params = refreshToken;
        refreshToken = null;
      }

      var tok = {};
      tok.access_token = accessToken;
      if (refreshToken) { tok.refresh_token = refreshToken; }
      if (params) { merge(tok, params); }
      tok.token_type = tok.token_type || 'Bearer';

      var json = JSON.stringify(tok);
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Pragma', 'no-cache');
      res.end(json);
    }
    
    try {
      var arity = issue.length;
      if (arity == 6) {
        issue(client, assertion, verifier, req.body, req.authInfo, issued);
      } else if (arity == 5) {
        issue(client, assertion, verifier, req.body, issued);
      } else if (arity == 4) {
        issue(client, assertion, verifier, issued);
      } else { // arity == 3
        issue(client, assertion, issued);
      }
    } catch (ex) {
      return next(ex);
    }
  };
};
