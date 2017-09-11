var chai = require('chai')
  , expect = require('chai').expect
  , acdc = require('../../lib/grant/acdc')
  , AuthorizationError = require('../../lib/errors/authorizationerror');


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
    
    describe('issuing cross domain code based on response', function() {
      var response;
      
      before(function(done) {
        function issue(client, user, audience, pkce, ares, done) {
          if (client.id !== '1') { return done(new Error('incorrect client argument')); }
          if (user.id !== '501') { return done(new Error('incorrect user argument')); }
          if (audience !== 'https://server.partner.com') { return done(new Error('incorrect audience argument')); }
          if (pkce.challenge !== 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM') { return done(new Error('incorrect pkce argument')); }
          if (pkce.method !== 'S256') { return done(new Error('incorrect pkce argument')); }
          if (ares.scope !== 'foo') { return done(new Error('incorrect ares argument')); }
          
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
            txn.res = { allow: true, scope: 'foo' };
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
    }); // issuing cross domain code based on response
    
    describe('issuing cross domain code based on response and request', function() {
      var response;
      
      before(function(done) {
        function issue(client, user, audience, pkce, ares, areq, done) {
          if (client.id !== '1') { return done(new Error('incorrect client argument')); }
          if (user.id !== '501') { return done(new Error('incorrect user argument')); }
          if (audience !== 'https://server.partner.com') { return done(new Error('incorrect audience argument')); }
          if (pkce.challenge !== 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM') { return done(new Error('incorrect pkce argument')); }
          if (pkce.method !== 'S256') { return done(new Error('incorrect pkce argument')); }
          if (ares.scope !== 'foo') { return done(new Error('incorrect ares argument')); }
          if (areq.foo !== 'bar') { return done(new Error('incorrect areq argument')); }
          
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
              foo: 'bar'
            };
            txn.user = { id: '501', name: 'John Doe' };
            txn.res = { allow: true, scope: 'foo' };
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
    }); // issuing cross domain code based on response and request
    
    describe('issuing cross domain code based on response, request, and locals', function() {
      var response;
      
      before(function(done) {
        function issue(client, user, audience, pkce, ares, areq, locals, done) {
          if (client.id !== '1') { return done(new Error('incorrect client argument')); }
          if (user.id !== '501') { return done(new Error('incorrect user argument')); }
          if (audience !== 'https://server.partner.com') { return done(new Error('incorrect audience argument')); }
          if (pkce.challenge !== 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM') { return done(new Error('incorrect pkce argument')); }
          if (pkce.method !== 'S256') { return done(new Error('incorrect pkce argument')); }
          if (ares.scope !== 'foo') { return done(new Error('incorrect ares argument')); }
          if (areq.foo !== 'bar') { return done(new Error('incorrect areq argument')); }
          if (locals.bar !== 'baz') { return done(new Error('incorrect locals argument')); }
          
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
              foo: 'bar'
            };
            txn.user = { id: '501', name: 'John Doe' };
            txn.res = { allow: true, scope: 'foo' };
            txn.locals = { bar: 'baz' };
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
    }); // issuing cross domain code based on response, request, and locals
    
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
    
    describe('attempting to respond without redirect URL', function() {
      var response, err;
      
      before(function(done) {
        function issue(client, user, audience, pkce, done) {
          return done(null, 'eyJ');
        }
        
        chai.oauth2orize.grant(acdc(issue))
          .txn(function(txn) {
            txn.client = { id: '1', name: 'OAuth Client' };
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
        expect(err.message).to.equal('Unable to issue redirect for OAuth 2.0 transaction');
      });
    }); // attempting to respond without redirect URL
    
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
    
    describe('encountering an error while completing transaction', function() {
      var response, err;
      
      before(function(done) {
        function issue(client, user, audience, pkce, done) {
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
          .next(function(e) {
            err = e;
            done();
          })
          .decide(function(cb) {
            process.nextTick(function() { cb(new Error('failed to complete transaction')) });
          });
      });
      
      it('should error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.message).to.equal('failed to complete transaction');
      });
    }); // encountering an error while completing transaction
    
  }); // decision processing
  
});
