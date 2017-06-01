import jwt from 'jsonwebtoken';
import NodeRSA from 'node-rsa';
import bodyParser from 'body-parser';

const expressFireAuth = (firebaseApp) => {
  // Get PEM encoded private key for RSA
  const key = new NodeRSA({ b: 1024 }, 'pkcs1-private-pem');
  const exported = key.exportKey('pkcs1-private-pem');
  const auth = firebaseApp.auth();

  // Generate token using user id and key
  const generateToken = (user) => {
    const privateClaim = { uid: user.uid };
    const options = {
      algorithm: 'RS256',
      issuer: 'expressFireAuth',
      subject: user.email,
      expiresIn: '30d'
    };
    const token = jwt.sign(privateClaim, exported, options);
    return token;
  };

  // Parse request body if request body has not been parsed
  const parseRequestBody = () => {
    return [
      bodyParser.json(),
      bodyParser.urlencoded({ extended: 'true' })
    ];
  };

  // For every request, Check request method and payload
  const validateRequest = () => {
    return (req, res, next) => {
      if (req.method !== 'POST') {
        throw new Error('POST request method expected');
      } else if (!req.body.email || !req.body.password) {
        throw new Error('non-empty email and password expected');
      } else {
        next();
      }
    };
  };

  /*
  Send response after user is logged in
  when setCookies, set the Set-Cookie header and return a 200 status
  else response is a json body
  */
  const afterLogIn = (setCookies, redirect, path) => {
    return (req, res) => {
      if (setCookies) {
        const date = new Date();
        date.setDate(date.getDate() + 30);
        res.cookie('token', req.token, { expires: date, httpOnly: true });
        return (redirect) ? res.redirect(path) : res.sendStatus(200);
      }
      return res.json(req.token);
    };
  };

  // Create a new user in your express-firebase app
  const signUp = ({
    setCookies = false,
    redirect = false,
    path = '/home'
  } = {}, ...middlewares) => {
    // Create user
    const createUser = (req, res, next) => {
      const { email, password } = req.body;
      auth.createUserWithEmailAndPassword(email, password)
      .then((user) => {
        const token = generateToken(user);
        req.token = token;
        next();
      })
      .catch((err) => {
        next(err);
      });
    };
    // Return an array of middleware that handles request
    return [
      ...parseRequestBody(),
      validateRequest(),
      createUser,
      ...middlewares,
      afterLogIn(setCookies, redirect, path)
    ];
  };

  // Log in an existing user
  const logIn = ({
    setCookies = false,
    redirect = false,
    path = '/home'
  } = {}, ...middlewares) => {
    // Log in user
    const logInUser = (req, res, next) => {
      const { email, password } = req.body;
      auth.signInWithEmailAndPassword(email, password)
      .then((user) => {
        const token = generateToken(user);
        req.token = token;
        next();
      })
      .catch((err) => {
        next(err);
      });
    };
    // Return an array of middleware that handles request
    return [
      ...parseRequestBody(),
      validateRequest(),
      logInUser,
      ...middlewares,
      afterLogIn(setCookies, redirect, path)
    ];
  };

  // Return api
  return {
    signUp,
    logIn
  };
};

export default expressFireAuth;
