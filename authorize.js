import {
  parseCookie,
  parseRequestBody,
  verifyTokenGetPayload
} from './helpers';

/**
 * Verify user identity and authorize user to assess requested route
 * or an alternate appropriate route.
 * @function authorizeUser
 * @param {Object.boolean} invokeNextOnFailure - Pass request to next
 * middleware function if authorization fails
 * @param {Object.boolean} invokeNextOnSuccess - Pass request to next
 * middleware function if authorization succeeds
 * @param {Object.boolean|string} redirectOnSuccess - URL to redirect to
 * if authorization succeeds else false
 * @param {Object.boolean|string} redirectOnFailure - URL to redirect to
 * if authorization fails else false
 * @returns {Array.<function>}
 * An array of middleware functions that handle request
 */
const authorizeUser = ({
  invokeNextOnFailure = false,
  invokeNextOnSuccess = false,
  redirectOnFailure = false,
  redirectOnSuccess = false
} = {}) => {
  /**
   * Get Token sent in client request
   * @function getClientAuthToken
   * @returns {Function} An express middleware that gets
   * authorization token from request body, query, header or cookies
   * and passes request to next middleware function.
   */
  const getClientAuthToken = () => {
    return (req, res, next) => {
      const token = req.get('Authorization') || req.body.token
      || req.cookies.token || req.query.token;
      const matched = /^Bearer (\S+)$/.exec(token);
      req.token = (matched) ? matched[1] : token;
      next();
    };
  };

  /**
   * Verify client token and get decoded payload
   * @function verifyClientAuthToken
   * @returns {Function} An express middleware that verifies the
   * authorization token sent by client, attaches error or decoded
   * payload to the request and passes request to the next
   * middleware function.
   */
  const verifyClientAuthToken = () => {
    return (req, res, next) => {
      if (req.token) {
        const rsaKey = process.env.PUBLIC_KEY;
        verifyTokenGetPayload(req.token, rsaKey)
        .then((decodedPayload) => {
          req.decodedPayload = decodedPayload;
          next();
        })
        .catch((err) => {
          req.err = err;
          next();
        });
      } else {
        next();
      }
    };
  };

  /**
   * Complete client authorization process
   * @function authorizationResponse
   * @returns {Function} An express middleware that sends response
   * to client Or passes request to the next middleware function.
   */
  const authorizationResponse = () => {
    return (req, res, next) => {
      if (req.err || !req.token) {
        if (redirectOnFailure) {
          return res.redirect(redirectOnFailure);
        }
        const message = (req.err) ? req.err.message
        : 'No Access token provided!';
        return (invokeNextOnFailure) ? next()
        : res.status(401).json(message);
      } else if (req.decodedPayload) {
        if (redirectOnSuccess) {
          return res.redirect(redirectOnSuccess);
        }
        return (invokeNextOnSuccess) ? next()
        : res.status(200).json(req.decodedPayload);
      }
    };
  };

  return [
    parseCookie(),
    ...parseRequestBody(),
    getClientAuthToken(),
    verifyClientAuthToken(),
    authorizationResponse()
  ];
};

export default authorizeUser;
