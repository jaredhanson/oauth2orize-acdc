/* global describe, it */

var pkg = require('..');
var expect = require('chai').expect;


describe('oauth2orize-acdc', function() {
  
  it('should export grants', function() {
    expect(pkg.grant).to.be.an('object');
    expect(pkg.grant.acdc).to.be.a('function');
  });
  
});
