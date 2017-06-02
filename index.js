import emailPasswordAuth from './authenticate';

const expressFireAuth = (firebaseApp) => {
  const auth = firebaseApp.auth();
  const emailAuthProvider = emailPasswordAuth(auth);
  // Return api
  return {
    ...emailAuthProvider
  };
};

export default expressFireAuth;
