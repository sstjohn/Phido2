/* Copyright (c) 2016 Saul St John */

var Phido2 = {	
	fidoAPI: window.fido || window.msCredentials,
	getAssertion: function (params, callback) 
  {
	var wrapper = r => callback(JSON.stringify(r));
	if (this.fidoAPI === undefined) {
		wrapper({error: {name: "NotSupportedError", message: "no fido 2.0 support in browser"}});
		return false;
	}
    if (params.existing === undefined 
            || (Array.isArray(params.existing) 
                && params.existing.length == 0)) {
        var filter = {accept: [{type: "FIDO_2_0"}]};
    } else {
	    var filter = {accept: params.existing};
    }
	return this.fidoAPI.getAssertion(params.challenge, filter)
		.then(function (assertion) {
			var response = {
			    id: assertion.id,
			    type: assertion.type,
			    signature: {
				authnrData: assertion.signature.authnrData,
				clientData: assertion.signature.clientData,
				signature: assertion.signature.signature
			    }
			};
			wrapper(response);
		}).catch(e => wrapper({error: {name: e.name, message: e.message}}));
  },
	makeCredential: function (params, callback) 
  {
	var wrapper = r => callback(JSON.stringify(r));
    if (this.fidoAPI === undefined) {
		wrapper({error: {name: "NotSupportedError", message: "no fido 2.0 support in browser"}});
		return false;
	}
	var cryptoParams = [
	  {
	    type: "FIDO_2_0",
	    algorithm: {
		name: "RSASSA-PKCS1-v1_5",
		hash: {
		    name: "SHA-256",
		},
	    },
	  },
	];
	var filter = {deny: params.existing || []};
	var user = {
		rpDisplayName: params.rpDisplayName,
		userDisplayName: params.userDisplayName,
		accountName: params.accountName,
		imageUri: params.imageUri
	};
	return this.fidoAPI.makeCredential(
			user, cryptoParams, params.challenge,
        		300, filter, params.extensions || {})
		.then(function (newCredentialInfo) {
			var response = {
				algorithm: newCredentialInfo.algorithm,
				attestation: newCredentialInfo.attestation,
				id: newCredentialInfo.id,
				publicKey: newCredentialInfo.publicKey,
				transportHints: newCredentialInfo.transportHints,
				type: newCredentialInfo.type
			};
			wrapper(response);
		}).catch(e => wrapper({error: {name:e.name, message:e.message}}));
  },
};
