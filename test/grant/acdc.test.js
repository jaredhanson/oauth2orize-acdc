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
    
    describe('with response mode', function() {
      function issue(client, user, audience, pkce, done) {
        return done(null, 'eyJ');
      }
    
      var otherResponseMode = function(txn, res, params) {
        expect(txn.redirectURI).to.equal('http://www.example.com/auth/callback');
        expect(params.code).to.equal('eyJ');
        expect(params.state).to.equal('s1t2u3');
      
        res.redirect('/other_response_mode');
      }
      
      describe('issuing cross domain code using default response mode', function() {
        var response;
      
        before(function(done) {
        
          chai.oauth2orize.grant(acdc({ modes: { other: otherResponseMode } }, issue))
            .txn(function(txn) {
              txn.client = { id: '1', name: 'OAuth Client' };
              txn.redirectURI = 'http://www.example.com/auth/callback';
              txn.req = {
                audience: 'https://server.partner.com',
                codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
                codeChallengeMethod: 'S256',
                state: 's1t2u3'
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
          expect(response.getHeader('Location')).to.equal('http://www.example.com/auth/callback?code=eyJ&state=s1t2u3');
        });
      }); // issuing cross domain code using default response mode
      
      describe('issuing cross domain code using other response mode', function() {
        var response;
      
        before(function(done) {
          chai.oauth2orize.grant(acdc({ modes: { other: otherResponseMode } }, issue))
            .txn(function(txn) {
              txn.client = { id: '1', name: 'OAuth Client' };
              txn.redirectURI = 'http://www.example.com/auth/callback';
              txn.req = {
                responseMode: 'other',
                audience: 'https://server.partner.com',
                codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
                codeChallengeMethod: 'S256',
                state: 's1t2u3'
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
          expect(response.getHeader('Location')).to.equal('/other_response_mode');
        });
      }); // issuing cross domain code using other response mode
      
      describe('authorization denied by user using other response mode', function() {
        var response;
      
        before(function(done) {
          var otherResponseMode = function(txn, res, params) {
            expect(txn.redirectURI).to.equal('http://www.example.com/auth/callback');
            expect(params.error).to.equal('access_denied');
            expect(params.state).to.equal('s1t2u3');
      
            res.redirect('/other_response_mode');
          }
        
          chai.oauth2orize.grant(acdc({ modes: { other: otherResponseMode } }, issue))
            .txn(function(txn) {
              txn.client = { id: '1', name: 'OAuth Client' };
              txn.redirectURI = 'http://www.example.com/auth/callback';
              txn.req = {
                responseMode: 'other',
                audience: 'https://server.partner.com',
                codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
                codeChallengeMethod: 'S256',
                state: 's1t2u3'
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
          expect(response.getHeader('Location')).to.equal('/other_response_mode');
        });
      }); // authorization denied by user using other response mode
      
      describe('using unsupported response mode', function() {
        var err;
      
        before(function(done) {
          chai.oauth2orize.grant(acdc({ modes: { other: otherResponseMode } }, issue))
            .txn(function(txn) {
              txn.client = { id: '1', name: 'OAuth Client' };
              txn.redirectURI = 'http://www.example.com/auth/callback';
              txn.req = {
                responseMode: 'unsupported',
                audience: 'https://server.partner.com',
                codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
                codeChallengeMethod: 'S256',
                state: 's1t2u3'
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
          expect(err.message).to.equal('Unsupported response mode: unsupported');
          expect(err.code).to.equal('unsupported_response_mode');
          expect(err.uri).to.equal(null);
          expect(err.status).to.equal(501);
        });
      }); // using unsupported response mode
      
    }) // with response mode
    
  }); // decision processing
  
  
  describe('error handling', function() {
    
    describe('generic error', function() {
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
            txn.res = { allow: true };
          })
          .end(function(res) {
            response = res;
            done();
          })
          .error(new Error('something went wrong'));
      });
      
      it('should respond', function() {
        expect(response.statusCode).to.equal(302);
        expect(response.getHeader('Location')).to.equal('http://www.example.com/auth/callback?error=server_error&error_description=something%20went%20wrong');
        expect(response.getHeader('Content-Type')).to.be.undefined;
        expect(response.getHeader('WWW-Authenticate')).to.be.undefined;
      });
      
      it('should not set response body', function() {
        expect(response.body).to.be.undefined;
      });
    }); // generic error
    
    describe('generic error along with state', function() {
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
              state: 's1s2s3'
            };
            txn.user = { id: '501', name: 'John Doe' };
            txn.res = { allow: true };
          })
          .end(function(res) {
            response = res;
            done();
          })
          .error(new Error('something went wrong'));
      });
      
      it('should respond', function() {
        expect(response.statusCode).to.equal(302);
        expect(response.getHeader('Location')).to.equal('http://www.example.com/auth/callback?error=server_error&error_description=something%20went%20wrong&state=s1s2s3');
        expect(response.getHeader('Content-Type')).to.be.undefined;
        expect(response.getHeader('WWW-Authenticate')).to.be.undefined;
      });
      
      it('should not set response body', function() {
        expect(response.body).to.be.undefined;
      });
    }); // generic error along with state
    
    describe('authorization error', function() {
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
            txn.res = { allow: true };
          })
          .end(function(res) {
            response = res;
            done();
          })
          .error(new AuthorizationError('not authorized', 'unauthorized_client'));
      });
      
      it('should respond', function() {
        expect(response.statusCode).to.equal(302);
        expect(response.getHeader('Location')).to.equal('http://www.example.com/auth/callback?error=unauthorized_client&error_description=not%20authorized');
        expect(response.getHeader('Content-Type')).to.be.undefined;
        expect(response.getHeader('WWW-Authenticate')).to.be.undefined;
      });
      
      it('should not set response body', function() {
        expect(response.body).to.be.undefined;
      });
    }); // authorization error
    
    describe('authorization error with URI', function() {
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
            txn.res = { allow: true };
          })
          .end(function(res) {
            response = res;
            done();
          })
          .error(new AuthorizationError('not authorized', 'unauthorized_client', 'http://example.com/errors/2'));
      });
      
      it('should respond', function() {
        expect(response.statusCode).to.equal(302);
        expect(response.getHeader('Location')).to.equal('http://www.example.com/auth/callback?error=unauthorized_client&error_description=not%20authorized&error_uri=http%3A%2F%2Fexample.com%2Ferrors%2F2');
        expect(response.getHeader('Content-Type')).to.be.undefined;
        expect(response.getHeader('WWW-Authenticate')).to.be.undefined;
      });
      
      it('should not set response body', function() {
        expect(response.body).to.be.undefined;
      });
    }); // authorization error with URI
    
    describe('attempting to respond without redirect URL', function() {
      var response, err;
      
      before(function(done) {
        function issue(client, user, audience, pkce, done) {
          return done(null, '.ignore');
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
          .error(new Error('something went wrong'));
      });
      
      it('should error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.message).to.equal('something went wrong');
      });
    }); // attempting to respond without redirect URL
    
    describe('with response mode', function() {
      function issue(client, user, audience, pkce, done) {
        return done(null, '.ignore');
      }
      
      var otherResponseMode = function(txn, res, params) {
        expect(txn.redirectURI).to.equal('http://www.example.com/auth/callback');
        
        res.redirect('/other_response_mode');
      }
      
      
      describe('using default response mode', function() {
        var response;
      
        before(function(done) {
          chai.oauth2orize.grant(acdc({ modes: { other: otherResponseMode } }, issue))
            .txn(function(txn) {
              txn.client = { id: '1', name: 'OAuth Client' };
              txn.redirectURI = 'http://www.example.com/auth/callback';
              txn.req = {
                audience: 'https://server.partner.com',
                codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
                codeChallengeMethod: 'S256',
                state: 's1t2u3'
              };
              txn.user = { id: '501', name: 'John Doe' };
              txn.res = { allow: true };
            })
            .end(function(res) {
              response = res;
              done();
            })
            .error(new AuthorizationError('not authorized', 'unauthorized_client'));
        });
      
        it('should respond', function() {
          expect(response.statusCode).to.equal(302);
          expect(response.getHeader('Location')).to.equal('http://www.example.com/auth/callback?error=unauthorized_client&error_description=not%20authorized&state=s1t2u3');
          expect(response.getHeader('Content-Type')).to.be.undefined;
          expect(response.getHeader('WWW-Authenticate')).to.be.undefined;
        });
      
        it('should not set response body', function() {
          expect(response.body).to.be.undefined;
        });
      }); //using default response mode
      
      describe('using other response mode', function() {
        var response;
      
        before(function(done) {
          chai.oauth2orize.grant(acdc({ modes: { other: otherResponseMode } }, issue))
            .txn(function(txn) {
              txn.client = { id: '1', name: 'OAuth Client' };
              txn.redirectURI = 'http://www.example.com/auth/callback';
              txn.req = {
                responseMode: 'other',
                audience: 'https://server.partner.com',
                codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
                codeChallengeMethod: 'S256',
                state: 's1t2u3'
              };
              txn.user = { id: '501', name: 'John Doe' };
              txn.res = { allow: true };
            })
            .end(function(res) {
              response = res;
              done();
            })
            .error(new AuthorizationError('not authorized', 'unauthorized_client'));
        });
      
        it('should respond', function() {
          expect(response.statusCode).to.equal(302);
          expect(response.getHeader('Location')).to.equal('/other_response_mode');
          expect(response.getHeader('Content-Type')).to.be.undefined;
          expect(response.getHeader('WWW-Authenticate')).to.be.undefined;
        });
      
        it('should not set response body', function() {
          expect(response.body).to.be.undefined;
        });
      }); //using other response mode
      
      describe('using unsupported response mode', function() {
        var response, err;
      
        before(function(done) {
          chai.oauth2orize.grant(acdc({ modes: { other: otherResponseMode } }, issue))
            .txn(function(txn) {
              txn.client = { id: '1', name: 'OAuth Client' };
              txn.redirectURI = 'http://www.example.com/auth/callback';
              txn.req = {
                responseMode: 'unsupported',
                audience: 'https://server.partner.com',
                codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
                codeChallengeMethod: 'S256',
                state: 's1t2u3'
              };
              txn.user = { id: '501', name: 'John Doe' };
              txn.res = { allow: true };
            })
            .next(function(e) {
              err = e;
              done();
            })
            .error(new AuthorizationError('not authorized', 'unauthorized_client'));
        });
      
        it('should error', function() {
          expect(err).to.be.an.instanceOf(Error);
          expect(err.constructor.name).to.equal('AuthorizationError');
          expect(err.message).to.equal('not authorized');
          expect(err.code).to.equal('unauthorized_client');
          expect(err.status).to.equal(403);
        });
      }); //using unsupported response mode
      
    }); // with response mode
    
  }); // error handling
  
  
});
