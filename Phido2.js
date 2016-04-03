/* Copyright (c) 2016 Saul St John */

var Phido2 = {	
	fidoAPI: window.fido || window.msCredentials,
	getAssertion: function (params, callback) 
  {
	if (this.fidoAPI === undefined) {
		callback({error: "NotSupportedError"});
		return false;
	}
	var wrapper = r => callback(JSON.stringify(r));
	var filter = {accept: params.existing || []};
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
		}).catch(e => wrapper({error: e}));
  },
	makeCredential: function (params, callback) 
  {
	if (this.fidoAPI === undefined) {
		callback({error: "NotSupportedError"});
		return false;
	}

	var wrapper = r => callback(JSON.stringify(r));
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
		rpAccountName: params.rpAccountName,
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
		}).catch(e => wrapper({error: e}));
  },
};
