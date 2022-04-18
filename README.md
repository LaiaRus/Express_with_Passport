# Express_with_Passport

## Description

Two possible logins: 

- Exchanging a JWT using cookies 
- Through Oauth2 with GitHub.

## Getting Started

You need to create the file **config.js**. Its content should be the following:

```javascript
module.exports = {
    'GITHUB_ID': "your github client id",
    'GITHUB_SECRET': "your github secret"
}
```
Then you need to download the dependencies with npm:

```console
$ npm install
```

Run the application:

```console
$ sudo node index.js
```

You can get the following error when trying to send the client’s credentials by POST:

```console
UnhandledPromiseRejectionWarning: ReferenceError: TextEncoder is not defined
```

To solve it, you need to modify /node_modules/scrypt-pbkdf/dist/cjs/index.node.cjs:

```javascript
const { TextEncoder, TextDecoder } = require("util");
```



