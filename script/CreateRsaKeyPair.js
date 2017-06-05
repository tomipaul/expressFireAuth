import fs from 'fs';
import { generateRSAKeyPair } from '../helpers';

const keyDirectory = `${__dirname}/../key`;

if (!process.env.PRIVATE_KEY && !process.env.PUBLIC_KEY
  && !fs.existsSync(`${keyDirectory}/rsapair.pem`)) {
  const rsaKeyPair = generateRSAKeyPair();
  const publicKey = JSON.stringify(rsaKeyPair.publicKey);
  const privateKey = JSON.stringify(rsaKeyPair.privateKey);
  const data = `PRIVATE_KEY = ${privateKey}\nPUBLIC_KEY = ${publicKey}`;
  fs.mkdirSync(keyDirectory);
  fs.writeFileSync(`${keyDirectory}/rsapair.pem`, data);
}
