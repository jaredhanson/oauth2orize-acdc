module.exports = function(options, issue) {
  if (typeof options == 'function') {
    issue = options;
    options = undefined;
  }
  options = options || {};
  
  if (!issue) { throw new TypeError('oauth2orize.acdc grant requires an issue callback'); }
  
  var modes = options.modes || {};
  if (!modes.query) {
    modes.query = require('../modes/query');
  }
  
  
  // NOTE: combine with `oauth2orize-pkce` and `oauth2orize-audience`
  function request(req) {
    // TODO: Error if PKCE not present
    // TODO: Error if audience not present.
  }
  
  function response(txn, res, complete, next) {
    var mode = 'query'
      , respond;
    if (txn.req && txn.req.responseMode) {
      mode = txn.req.responseMode;
    }
    respond = modes[mode];
  
    if (!respond) {
      // http://lists.openid.net/pipermail/openid-specs-ab/Week-of-Mon-20140317/004680.html
      return next(new AuthorizationError('Unsupported response mode: ' + mode, 'unsupported_response_mode', null, 501));
    }
    if (respond && respond.validate) {
      try {
        respond.validate(txn);
      } catch(ex) {
        return next(ex);
      }
    }
  
    if (!txn.res.allow) {
      var params = { error: 'access_denied' };
      if (txn.req && txn.req.state) { params.state = txn.req.state; }
      return respond(txn, res, params);
    }
    
    
    function issued(err, crossDomainCode) {
      if (err) { return next(err); }
      if (!crossDomainCode) { return next(new AuthorizationError('Request denied by authorization server', 'access_denied')); }
      
      var params = { code: crossDomainCode };
      if (txn.req && txn.req.state) { params.state = txn.req.state; }
      complete(function(err) {
        if (err) { return next(err); }
        return respond(txn, res, params);
      });
    }
    
    var pkce = {
      challenge: txn.req.codeChallenge,
      method: txn.req.codeChallengeMethod
    }
    
    try {
      var arity = issue.length;
      if (arity == 8) {
        issue(txn.client, txn.user, txn.req.audience, pkce, txn.res, txn.req, txn.locals, issued);
      } else if (arity == 7) {
        issue(txn.client, txn.user, txn.req.audience, pkce, txn.res, txn.req, issued);
      } else if (arity == 6) {
        issue(txn.client, txn.user, txn.req.audience, pkce, txn.res, issued);
      } else { // arity == 5
        issue(txn.client, txn.user, txn.req.audience, pkce, issued);
      }
    } catch (ex) {
      return next(ex);
    }
  }
  
  /**
   * Return `acdc` grant module.
   */
  var mod = {};
  mod.name = 'acdc';
  mod.request = request;
  mod.response = response;
  return mod;
}
