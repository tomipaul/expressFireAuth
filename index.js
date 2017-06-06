import dotenv from 'dotenv';
import emailPasswordAuth from './authenticate';
import './script/CreateRsaKeyPair';

dotenv.config({ path: `${__dirname}/key/rsapair.pem` });

const expressFireAuth = (firebaseApp) => {
  const auth = firebaseApp.auth();
  const emailAuthProvider = emailPasswordAuth(auth);
  // Return api
  return {
    ...emailAuthProvider
  };
};

export default expressFireAuth;
