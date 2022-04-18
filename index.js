const session = require("express-session")
const bodyParser = require('body-parser')
const express = require('express')
const logger = require('morgan')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const jwt = require('jsonwebtoken')
const jwtSecret = require('crypto').randomBytes(16) // 16*8= 256 random bits // It's a random secret to check the HMAC-SHA256 signature of every JWT
const cookieParser = require('cookie-parser')
const fortune = require('fortune-teller')
const JwtStrategy = require('passport-jwt').Strategy;
const scryptPbkdf = require('scrypt-pbkdf')
const fs = require('fs')
const app = express()
const https = require('https');
const { config } = require("process")
const tlsServerKey = fs.readFileSync('./tls/webserver.key.pem');
const tlsServerCrt = fs.readFileSync('./tls/webserver.crt.pem');
const httpsOptions = {
  key: tlsServerKey,
  cert: tlsServerCrt
};
const server = https.createServer(httpsOptions, app);
const gitHubStrategy = require('passport-github2').Strategy

const secretConfig = require('./config')
const GITHUB_CLIENT_ID = secretConfig.GITHUB_ID
const GITHUB_CLIENT_SECRET = secretConfig.GITHUB_SECRET

const cookieExtractor = req => {
  let jwt = null
  if (req && req.cookies) {
    jwt = req.cookies['cookie_access_token']
  }
  return jwt
}

var passwordsJSON = {}
var jwtOptions = {}

jwtOptions.jwtFromRequest = cookieExtractor;
jwtOptions.secretOrKey = jwtSecret;
jwtOptions.issuer = 'localhost:3000';
jwtOptions.audience = 'localhost:3000';

app.use(bodyParser.urlencoded({ extended: true })) // needed to retrieve html form fields
app.use(bodyParser.json()) // github
app.use(cookieParser())
app.use(logger('dev'))
app.use(session({ secret: 'example secret', resave: false, saveUninitialized: false }))
app.use(passport.initialize()) // we load the passport auth middleware to our express application. It should be loaded before any route.
app.use(passport.session())

app.use(function (err, req, res, next) {
  console.error(err.stack)
  res.status(500).send('Something broke!')
})

/**
 * PASSPORT FOR JWT AUTH
 */

// Configure the local strategy for use by Passport.
// The local strategy requires a `verify` function which receives the credentials
// (`username` and `password`) submitted by the user.  The function must verify
// that the username and password are correct and then invoke `done` with a user
// object, which will be set at `req.user` in route handlers after authentication.
passport.use('local', new LocalStrategy(
  {
    usernameField: 'username', // it MUST match the name of the input field for the username in the login HTML formulary
    passwordField: 'password', // it MUST match the name of the input field for the password in the login HTML formulary
    session: false // we will store a JWT in the cookie with all the required session data. Our server does not need to keep a session, it's stateless
  },
  function (username, password, done) {
    validateUserPasswd(username, password).then(res => { // cridar una funció async
      if (res) {
        const user = {
          username: username,
          description: 'the only user that deserves to contact the fortune teller'
        }
        return done(null, user) // the first argument for done is the error, if any. In our case no error so that null. The object user will be added by the passport middleware to req.user and this will be available there for the next middleware and/or the route handler
      }
      return done(null, false) // in passport returning false as the user object means that the authentication process failed.
    })
  }
))

passport.use('jwt', new JwtStrategy(jwtOptions, (jwtPayload, done) => {
  const { expiration } = jwtPayload
  if (Date.now() > expiration) {
    done('Token expired', false) // en realitat aixo no cal
  }
  done(null, jwtPayload)
}))

/**
 * PASSPORT FOR GITHUB
 */

 passport.use(new gitHubStrategy({
  clientID: GITHUB_CLIENT_ID,
  clientSecret: GITHUB_CLIENT_SECRET,
  callbackURL: 'https://10.0.2.5/logingithub/callback'
},
  function (accessToken, refreshToken, profile, done) {
    process.nextTick(function () {
      return done(null, profile)
    })
  }))

// To avoid Error: Failed to serialize user into session
passport.serializeUser(function (user, done) {
  done(null, user);
});

passport.deserializeUser(function (user, done) {
  done(null, user);
});

/**
 * GENERAL AUTHENTICATION FUNCTIONS
 */

 function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated() || req.cookies['cookie_access_token']) { return next(); }
  res.redirect('/login')
}

/**
 * JWT AUTHENTICATION FUNCTIONS
 */

// Get hashed passwords from database (the passwords.json file)
fs.readFile('./passwords.json', 'utf8', (err, data) => {
  if (err) {
    console.error(err)
    return
  }
  passwordsJSON = JSON.parse(data)
})

function getHashedPasswd(_username) {
  var ret = null
  passwordsJSON.forEach(element => {
    if (element.username === _username) {
      ret = element.password
    }
  });
  return ret
}

function getSaltUser(_username) {
  const { salt } = passwordsJSON.find(pwd => pwd.username === _username); // find xq nomes necessito un element (salta el primer que retorna true). Si en necessités molt --> map
  return salt
}

async function validateUserPasswd(_username, _plainPasswd) {
  var hashedPasswd = getHashedPasswd(_username)
  if (hashedPasswd != null) {
    const salt = getSaltUser(_username)
    const derivedKeyLength = 32
    const recalculatedHash = await scryptPbkdf.scrypt(_plainPasswd, salt, derivedKeyLength)
    const recalculatedHash_hex = Buffer.from(recalculatedHash).toString('hex')
    // TO SAVE THE SALT AND THE HASH IN passwords.json
    //const salt = scryptPbkdf.salt()
    // console.log(`[salt]: ${salt}`)
    if (recalculatedHash_hex !== '') {
      if (hashedPasswd == recalculatedHash_hex) {
        return true
      } else {
        return false
      }
    } else { console.log("F") }
  }
}

/**
 * GET ENDPOINTS
 */

app.get('/', ensureAuthenticated, (req, res) => {
  res.send(fortune.fortune())
})

app.get('/login',
  (req, res) => {
    res.sendFile('login.html', { root: __dirname })
  }
)

app.get('/logout',
  (req, res) => {
    req.session.destroy(function (err) {
      res//.redirect('/login')
        .clearCookie('cookie_access_token')
        .json({
          message: 'You have logged out'
        })
    })
  }
)

app.get('/logingithub',
  passport.authenticate('github', { scope: ['user:email'] }),
  function (req, res) {
  }
);

app.get('/logingithub/callback',
  passport.authenticate('github', { failureRedirect: '/login' }),
  function (req, res) {
    res//.redirect('/')
      .json({ message: "Logged in successfully!" });
  }
);

/**
 * POST ENDPOINTS
 */

app.post('/login',
  passport.authenticate('local', { failureRedirect: '/login', session: false }),
  (req, res) => { //
    // we should create here the JWT for the fortune teller and send it to the user agent inside a cookie.
    // we'll do it later, right now we'll just say 'Hello ' and the name of the user that we get from the `req.user` object provided by passport
    //res.send(`Hello ${req.user.username}`)

    // This is what ends up in our JWT
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
      role: 'user' // just to show a private JWT field
    }

    // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
    const token = jwt.sign(jwtClaims, jwtSecret)

    // Just for testing, send the JWT directly to the browser. Later on we should send the token inside a cookie.
    //res.json(token)

    res
      .cookie("cookie_access_token", token) // cookie_access_token = name of the cookie
      .status(200)
      .json({ message: "Logged in successfully!" });

    // And let us log a link to the jwt.iot debugger, for easy checking/verifying:
    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('hex')}`)
  }
)

/**
 * Listen on provided port, on all network interfaces.
 */
server.listen(443);
server.on('listening', onListening);

/**
 * Event listener for HTTP server "listening" event.
 */
function onListening() {
  const addr = server.address();
  const bind = typeof addr === 'string'
    ? 'pipe ' + addr
    : 'port ' + addr.port;
  console.log('Listening on ' + bind);
  console.log('https://10.0.2.5/login')
}