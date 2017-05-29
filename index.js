import jwt from 'jsonwebtoken';
import NodeRSA from 'node-rsa';

const expressFireAuth = (firebaseApp) => {
  // Get PEM encoded private key for RSA
  const key = new NodeRSA({ b: 1024 }, 'pkcs1-private-pem');
  const exported = key.exportKey('pkcs1-private-pem');

  // Generate token
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

  // Create a new user in your express-firebase app
  const signUp = ({
    setCookies = false,
    redirect = false,
    path = '/home'
  } = {}, ...middlewares) => {
    // Check request method and payload
    const validateRequest = (req, res, next) => {
      if (req.method !== 'POST') {
        throw new Error('POST request method expected');
      } else if (!req.body.email || !req.body.password) {
        throw new Error('non-empty email and password expected');
      } else {
        next();
      }
    };
    // Create user
    const createUser = (req, res, next) => {
      const { email, password } = req.body;
      const auth = firebaseApp.auth();
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
    // Wrap up request after user sign up
    const response = (req, res) => {
      if (setCookies) {
        const date = new Date();
        date.setDate(date.getDate() + 30);
        res.cookie('token', req.token, { expires: date, httpOnly: true });
        return (redirect) ? res.redirect(path) : res.sendStatus(200);
      }
      return res.json(req.token);
    };
    return [validateRequest, createUser, ...middlewares, response];
  };
  // Return api
  return {
    signUp
  };
};

export default expressFireAuth;
