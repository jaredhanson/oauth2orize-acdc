var chai = require('chai')
  , expect = require('chai').expect
  , acdc = require('../../lib/exchange/jwt-acdc');


describe('exchange.jwt-acdc', function() {
  
  it('should be unnamed', function() {
    expect(acdc(function(){}).name).to.equal('');
  });
  
  describe('issuing an access token', function() {
    var response, err;

    before(function(done) {
      function issue(client, assertion, done) {
        if (client.id !== '1') { return done(new Error('incorrect client argument')); }
        if (assertion !== 'eyJ') { return done(new Error('incorrect code argument')); }
        
        return done(null, 's3cr1t');
      }
      
      chai.connect.use(acdc(issue))
        .req(function(req) {
          req.user = { id: '1', name: 'OAuth Client' };
          req.body = { assertion: 'eyJ', code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk' };
        })
        .end(function(res) {
          response = res;
          done();
        })
        .dispatch();
    });
    
    it('should respond with headers', function() {
      expect(response.getHeader('Content-Type')).to.equal('application/json');
      expect(response.getHeader('Cache-Control')).to.equal('no-store');
      expect(response.getHeader('Pragma')).to.equal('no-cache');
    });
    
    it('should respond with body', function() {
      expect(response.body).to.equal('{"access_token":"s3cr1t","token_type":"Bearer"}');
    });
  });
  
});
