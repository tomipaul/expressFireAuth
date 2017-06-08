import {
  parseCookie,
  parseRequestBody,
  verifyTokenGetPayload
} from './helpers';

/**
 * Verify user identity and authorize user to assess requested route
 * or an alternate appropriate route.
 * @function authorizeUser
 * @param {Object.boolean|string} redirectOnSuccess - URL to redirect to
 * if authorization succeeds else false
 * @param {Object.boolean|string} redirectOnFailure - URL to redirect to
 * if authorization fails else false
 * @returns {Array.<function>}
 * An array of middleware functions that handle request
 */
const authorizeUser = ({
  redirectOnFailure = false,
  redirectOnSuccess = false
} = {}) => {
  /**
   * Get Token sent in client request
   * @function getToken
   * @returns {Function} An express middleware that gets
   * authorization token from request body, query, header or cookies.
   */
  const getToken = () => {
    return (req, res, next) => {
      const token = req.body.token || req.query.token
      || req.get('Authorization') || req.cookies.token;
      if (!token) {
        return (redirectOnFailure) ? res.redirect(redirectOnFailure)
        : res.status(401).send('No Access token provided!');
      }
      const matched = /^Bearer (\S+)$/.exec(token);
      req.token = (matched) ? matched[1] : token;
      next();
    };
  };

  /**
   * Verify client identity and send response
   * @function verifyUserIdentity
   * @returns {Function} An express middleware that verifies the
   * authorization token sent by client and then authorize client
   * to assess requested route or an alternate appropriate route.
   */
  const verifyUserIdentity = () => {
    return (req, res, next) => {
      const rsaKey = process.env.PUBLIC_KEY;
      verifyTokenGetPayload(req.token, rsaKey)
      .then((decodedPayload) => {
        req.userId = decodedPayload.uid;
        return (redirectOnSuccess) ? res.redirect(redirectOnSuccess)
        : next();
      })
      .catch((err) => {
        return (redirectOnFailure) ? res.redirect(redirectOnFailure)
        : res.status(401).send(err.message);
      });
    };
  };

  return [
    parseCookie(),
    ...parseRequestBody(),
    getToken(),
    verifyUserIdentity()
  ];
};

export default authorizeUser;
