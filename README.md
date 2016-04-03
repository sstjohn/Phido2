Phido2
======

Phido2 is a library for authentication by Fast IDentity Online (FIDO) 2.0
credential, written in PHP and JavaScript.

Dependencies
------------

Server-side, the only dependencies are on PHP and its OpenSSL extension.

Client-side, the only known FIDO 2.0 implementation is the Windows Hello
authenticator in Microsoft Edge.

Usage
-----

Two workflows are defined: credential creation and assertion validation.

### Initialization ###

1. Instantiate an instance of the `Phido2\Phido2` class on the server. It
takes two arguments: the site's display and server names.

    ```php
    $phido2 = new Phido2\Phido2('My Home Page', 'example.com');
    ```
 
2. Generate request parameters using the `getParams` method of the Phido2
object. It takes two arguments: the user's account name, and an optional
list of existing credentials known to belong to the user; and returns a JSON
string.

    ```php
    $params = $phido2->getParams('user');
    ```

3. Cause the Phido2.js script to be loaded into the browser.

    ```php
    print('<script src="path/to/Phido2.js" />');
    ```

4. Provide the request parameters to the browser.

    ```php
    print('<script>'
    	. sprintf("var params = %s;", $params)
    	. '</script');
    ```

5. Construct a callback for returning the request's response to the server,
provide it to the browser.

    ```javascript
    function callback(response)
    {
    	document.getElementById('response-input').value = response;
    	document.getElementById('response-form').submit();
    }
    ```


### Credential Creation ###

1. In the browser, call the `makeCredential` method of the Phido2 object with the
request parameters and callback constructed previously. This will cause the
browser to authenticate its current user and provide the public authentication
credentials to the callback.

    ```javascript
    Phido2.makeCredential(params, callback);
    ```

2. On the server, JSON-decode the credentials and validate them using the
`validateCredential` method of the Phido2 object. This method is currently a
no-op, but attestation validation would take place therein were any 
authenticators presently returning attestation information, and invalid
credentials would be indicated by raising an exception.

    ```php
    $credential = json_decode($_POST['response-input']);
    if (isset($credential->error)) {
    	raise new Exception($credential->error);
    }
    $phido2->validateCredential($params, $credential);
    ```

3. Store the validated credential in a database.

  
### Assertion Validation ###

1. In the browser, call the `getAssertion` method of the Phido2 object with the
request parameters and callback constructed previously. This will cause the
browser to authenticate its current user and issue an assertion signed by
that user's credential's private key.

    ```javascript
    Phido2.getAssertion(params, callback);
    ```

2. On the server, JSON-decode the attestation, retrieve the identified
credential's public key from the database, and validate the assertion.
An exception is raised if the given credential's public key fails to
validate the assertion's signature.

    ```php
    $assertion = json_decode($_POST['response-input']);
    if (isset($assertion->error)) {
    	raise new Exception($assertion->error);
    }
    $pkey = get_credential_from_database($assertion->id)->publicKey;
    $phido2->validateAssertion($params, $assertion, $pkey);
    ```

License
-------

Copyright (C) 2016  Saul St John

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

