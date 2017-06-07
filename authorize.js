import {
  parseCookie,
  parseRequestBody,
  verifyTokenGetPayload
} from './helpers';

/**
 * Verify user identity and authorize user to assess requested route
 * or an alternate appropriate route.
 * @function authorizeUser
 * @param {Object.boolean} redirectOnFailure - Redirect if user
 * authorization fails.
 * @param {Object.boolean} redirectOnSuccess - Redirect if user
 * authorization succeeds
 * @param {Object.string} successUrl - url to redirect to
 * if redirectOnSuccess
 * @param {Object.string} failureUrl - url to redirect to
 * if redirectOnFailure
 * @returns {Array.<function>}
 * An array of middleware functions that handle request
 */
const authorizeUser = ({
  redirectOnFailure = false,
  redirectOnSuccess = false,
  successUrl = '/',
  failureUrl = '/'
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
        return (redirectOnFailure) ? res.redirect(failureUrl)
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
        return (redirectOnSuccess) ? res.redirect(successUrl)
        : next();
      })
      .catch((err) => {
        return (redirectOnFailure) ? res.redirect(failureUrl)
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
