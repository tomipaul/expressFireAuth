import jwt from 'jsonwebtoken';
import NodeRSA from 'node-rsa';

const expressFireAuth = (firebaseApp) => {
  // Get PEM encoded private key for RSA
  const key = new NodeRSA({ b: 1026 }, 'pkcs1-private-pem');
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
};

export default expressFireAuth;
