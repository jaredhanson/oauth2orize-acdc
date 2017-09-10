var chai = require('chai')
  , expect = require('chai').expect
, acdc = require('../../lib/grant/acdc');


describe('grant.acdc', function() {
  
  describe('module', function() {
    var mod = acdc(function(){});
    
    it('should be named code', function() {
      expect(mod.name).to.equal('acdc');
    });
    
    it('should expose request and response functions', function() {
      expect(mod.request).to.be.a('function');
      expect(mod.response).to.be.a('function');
    });
  });
  
  
  describe('decision processing', function() {
    
    describe('issuing cross domain code', function() {
      var response;
      
      before(function(done) {
        function issue(client, user, audience, pkce, done) {
          if (client.id !== '1') { return done(new Error('incorrect client argument')); }
          if (user.id !== '501') { return done(new Error('incorrect user argument')); }
          if (audience !== 'https://server.partner.com') { return done(new Error('incorrect audience argument')); }
          if (pkce.challenge !== 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM') { return done(new Error('incorrect pkce argument')); }
          if (pkce.method !== 'S256') { return done(new Error('incorrect pkce argument')); }
          
          return done(null, 'eyJ');
        }
        
        chai.oauth2orize.grant(acdc(issue))
          .txn(function(txn) {
            txn.client = { id: '1', name: 'OAuth Client' };
            txn.redirectURI = 'http://www.example.com/auth/callback';
            txn.req = {
              audience: 'https://server.partner.com',
              codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
              codeChallengeMethod: 'S256'
            };
            txn.user = { id: '501', name: 'John Doe' };
            txn.res = { allow: true };
          })
          .end(function(res) {
            response = res;
            done();
          })
          .decide();
      });
      
      it('should respond', function() {
        expect(response.statusCode).to.equal(302);
        expect(response.getHeader('Location')).to.equal('http://www.example.com/auth/callback?code=eyJ');
      });
    }); // issuing cross domain code
    
  }); // decision processing
  
});
