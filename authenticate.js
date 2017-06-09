import {
  generateToken,
  parseRequestBody
 } from './helpers';

/**
 * Handle Email-Paswword Authentication
 * @function emailPasswordAuth
 * @param {Object} auth - Auth service for the firebase app - firebase.auth()
 * @returns {Object.<function>} An object that contains
 * functions that implement authentication
 */
const emailPasswordAuth = function emailPasswordAuth(auth) {
  /**
   * Check if authentication request is valid
   * @function validateRequest
   * @returns {Function} An express middleware that checks
   * request method and payload for every authentication request
   */
  const validateRequest = () => {
    return (req, res, next) => {
      if (req.method !== 'POST') {
        res.status(400).json('POST request method expected');
      } else if (!req.body.email || !req.body.password) {
        res.status(400).json('non-empty email and password expected');
      } else {
        next();
      }
    };
  };

  /**
   * Send response after user authentication
   * @function userAuthenticationResponse
   * @param {Boolean} setCookie - Send a cookie in response to request
   * @param {Boolean|String} redirect -
   * Send an http redirect in response to request; false Or Path/URL
   * @returns {Function} A middleware that sends authentication response
   * If setCookies is true and redirect is false,
   * send a cookie that contains token and return a 200 status.
   * If setCookies is true and redirect is set,
   * send a cookie that contains token and
   * redirect to path/url specified by redirect
   * Else if setCookies is false, return a json response of token
   */
  const userAuthenticationResponse = (setCookie, redirect) => {
    return (req, res) => {
      if (setCookie) {
        const date = new Date();
        date.setDate(date.getDate() + 30);
        res.cookie('token', req.token, { expires: date, httpOnly: true });
        return (redirect) ? res.redirect(redirect) : res.sendStatus(200);
      }
      return res.json(req.token);
    };
  };

  /**
   * Authenticate a user to an express-firebase app
   * @function authenticateUserWithEmailAndPassword
   * @param {Object.boolean} newUser -
   * Create a new user or login an existing user
   * @param {Object.boolean} setCookie - Send a cookie in response to request
   * @param {Object.boolean|string} redirect -
   * Send an http redirect in response to request; false Or path/URL
   * @param {Function} middlewares - Custom middlewares if you desire to
   * implement additional logic before response is sent.
   * @returns {Array.<function>}
   * An array of middleware functions that handle request
   */
  const authenticateUserWithEmailAndPassword = ({
    newUser = false,
    setCookie = false,
    redirect = false
  } = {}, ...middlewares) => {
    const authenticateUser = (req, res, next) => {
      const { email, password } = req.body;
      const promise = (newUser) ?
      auth.createUserWithEmailAndPassword(email, password)
      : auth.signInWithEmailAndPassword(email, password);
      promise.then((user) => {
        const rsaKey = process.env.PRIVATE_KEY;
        const token = generateToken(user, rsaKey);
        req.user = user;
        req.token = token;
        next();
      })
      .catch((err) => {
        res.status(401).json(err);
      });
    };
    return [
      ...parseRequestBody(),
      validateRequest(),
      authenticateUser,
      ...middlewares,
      userAuthenticationResponse(setCookie, redirect)
    ];
  };

  return {
    authenticateUserWithEmailAndPassword
  };
};

export default emailPasswordAuth;
