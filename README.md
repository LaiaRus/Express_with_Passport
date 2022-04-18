# Express_with_Passport

## Description

Two possible logins: 

- Exchanging a JWT using cookies 
- Through Oauth2 with GitHub.

## Getting Started

You need to create the file **config.js**. Its content should be the following:

```javascript
module.exports = {
    'GITHUB_ID': "YOUR_GITHUB_CLIENT_ID",
    'GITHUB_SECRET': "YOUR_GITHUB_SECRET"
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

## Usage

You can either login with user and password or with a GitHub account.

### User and password login
You can use either

```console
User: alice
Password: alice123
```
or 

```console
User: bob
Password: bobob
```

### GitHub login

Using your GitHub account.

### Once beign logged in

You can read a different fortune sentence every time you access /. 

### Logging out

Go to /logout to log out.
