module.exports = function(options, issue) {
  
  // NOTE: combine with `oauth2orize-pkce` and `oauth2orize-audience`
  function request(req) {
  }
  
  function response(txn, res, next) {
    try {
      var arity = issue.length;
      if (arity == 6) {
        issue(txn.client, txn.user, txn.res, txn.req, txn.locals, issued);
      } else { // arity == 5
        issue(txn.client, txn.user, txn.res, txn.req, issued);
      }
    } catch (ex) {
      return next(ex);
    }
  }
  
  /**
   * Return `id_token` grant module.
   */
  var mod = {};
  mod.name = 'acdc';
  mod.request = request;
  mod.response = response;
  return mod;
}
