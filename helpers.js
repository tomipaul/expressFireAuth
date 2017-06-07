import NodeRSA from 'node-rsa';
import jwt from 'jsonwebtoken';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';

/**
 * Generate PEM encoded RSA key pair
 * function generateToken() uses key for token creation
 * @function generateRSAKeyPair
 * @returns {Object.<string>} PEM-encoded RSA public and private keys
 */
const generateRSAKeyPair = () => {
  const key = new NodeRSA({ b: 2048 });
  const publicKey = key.exportKey('pkcs1-public-pem');
  const privateKey = key.exportKey('pkcs1-private-pem');
  return { publicKey, privateKey };
};

/**
 * Generate json web token
 * @function generateToken
 * @param {Object} user - User object returned from firebase authentication
 * @param {String} rsaKey - PEM encoded RSA private key
 * @returns {String} - A json web token
 */
const generateToken = (user, rsaKey) => {
  const privateClaim = { uid: user.uid };
  const options = {
    algorithm: 'RS256',
    issuer: 'expressFireAuth',
    subject: user.email,
    expiresIn: '30d'
  };
  const token = jwt.sign(privateClaim, rsaKey, options);
  return token;
};

/**
 * Verify token's signature and get decoded payload
 * @param {String} token - JSON web token
 * @param {String} rsaKey - PEM encoded RSA public key
 * @returns {Promise.<Object>} - Decoded payload if
 * promise is fulfilled or an error if rejected.
 * Promise is fulfilled if token is valid.
 */
const verifyTokenGetPayload = (token, rsaKey) => {
  return new Promise((resolve, reject) => {
    const options = {
      algorithms: ['RS256'],
      issuer: 'expressFireAuth',
      maxAge: '30d'
    };
    jwt.verify(token, rsaKey, options, (err, decoded) => {
      return (err) ? reject(err) : resolve(decoded);
    });
  });
};

/**
 * Parse the body of requests and populate req.body with payload
 * See {@link https://expressjs.com/en/4x/api.html#req.body ExpressJS}
 * @function parseRequestBody
 * @returns {Array} - An array of two express middleware functions
 *  from body-parser.
 * See {@link https://www.npmjs.com/package/body-parser body-parser}
 */
const parseRequestBody = () => {
  return [
    bodyParser.json(),
    bodyParser.urlencoded({ extended: 'true' })
  ];
};

/**
 * Parse the request cookies header and populate req.cookies
 * See {@link https://expressjs.com/en/4x/api.html#req.cookies ExpressJS}
 * @function parseCookie
 * @returns {Function} - An express middleware function
 *  from cookie-parser.
 * See {@link https://www.npmjs.com/package/cookie-parser cookie-parser}
 */
const parseCookie = () => {
  return cookieParser();
};

export {
  parseCookie,
  generateToken,
  parseRequestBody,
  generateRSAKeyPair,
  verifyTokenGetPayload
};
