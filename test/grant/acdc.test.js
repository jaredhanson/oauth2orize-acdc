var chai = require('chai')
  , expect = require('chai').expect
  , acdc = require('../../lib/grant/acdc');


describe('grant.acdc', function() {
  
  describe('module', function() {
    var mod = acdc(function(){});
    
    it('should be named acdc', function() {
      expect(mod.name).to.equal('acdc');
    });
    
    it('should expose request and response functions', function() {
      expect(mod.request).to.be.a('function');
      expect(mod.response).to.be.a('function');
      expect(mod.error).to.be.a('function');
    });
  });
  
  it('should throw if constructed without a issue callback', function() {
    expect(function() {
      acdc();
    }).to.throw(TypeError, 'oauth2orize.acdc grant requires an issue callback');
  });
  
  
  describe('request parsing', function() {
    
  }); // request parsing
  
  
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
    
    describe('issuing cross domain code along with state', function() {
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
              codeChallengeMethod: 'S256',
              state: 'f1o1o1'
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
        expect(response.getHeader('Location')).to.equal('http://www.example.com/auth/callback?code=eyJ&state=f1o1o1');
      });
    }); // issuing cross domain code along with state
    
    describe('authorization denied by user', function() {
      var response;
      
      before(function(done) {
        function issue(client, user, audience, pkce, done) {
          return done(null, '.ignore');
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
            txn.res = { allow: false };
          })
          .end(function(res) {
            response = res;
            done();
          })
          .decide();
      });
      
      it('should respond', function() {
        expect(response.statusCode).to.equal(302);
        expect(response.getHeader('Location')).to.equal('http://www.example.com/auth/callback?error=access_denied');
      });
    }); // authorization denied by user
    
    describe('authorization denied by user along with state', function() {
      var response;
      
      before(function(done) {
        function issue(client, user, audience, pkce, done) {
          return done(null, '.ignore');
        }
        
        chai.oauth2orize.grant(acdc(issue))
          .txn(function(txn) {
            txn.client = { id: '1', name: 'OAuth Client' };
            txn.redirectURI = 'http://www.example.com/auth/callback';
            txn.req = {
              audience: 'https://server.partner.com',
              codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
              codeChallengeMethod: 'S256',
              state: 'f1o1o1'
            };
            txn.user = { id: '501', name: 'John Doe' };
            txn.res = { allow: false };
          })
          .end(function(res) {
            response = res;
            done();
          })
          .decide();
      });
      
      it('should respond', function() {
        expect(response.statusCode).to.equal(302);
        expect(response.getHeader('Location')).to.equal('http://www.example.com/auth/callback?error=access_denied&state=f1o1o1');
      });
    }); // authorization denied by user along with state
    
    describe('authorization denied by server', function() {
      var response, err;
      
      before(function(done) {
        function issue(client, user, audience, pkce, done) {
          return done(null, false);
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
          .next(function(e) {
            err = e;
            done();
          })
          .decide();
      });
      
      it('should error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.constructor.name).to.equal('AuthorizationError');
        expect(err.message).to.equal('Request denied by authorization server');
        expect(err.code).to.equal('access_denied');
        expect(err.status).to.equal(403);
      });
    }); // authorization denied by server
    
    describe('encountering an error while issuing cross domain code', function() {
      var response, err;
      
      before(function(done) {
        function issue(client, user, audience, pkce, done) {
          return done(new Error('something went wrong'));
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
          .next(function(e) {
            err = e;
            done();
          })
          .decide();
      });
      
      it('should error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.message).to.equal('something went wrong');
      });
    }); // encountering an error while issuing cross domain code
    
    describe('encountering an exception while issuing cross domain code', function() {
      var response, err;
      
      before(function(done) {
        function issue(client, user, audience, pkce, done) {
          throw new Error('something went horribly wrong');
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
          .next(function(e) {
            err = e;
            done();
          })
          .decide();
      });
      
      it('should error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.message).to.equal('something went horribly wrong');
      });
    }); // encountering an exception while issuing cross domain code
    
  }); // decision processing
  
});
