const express = require("express");
const CryptoJS = require("crypto-js");
require('dotenv').config();
const cors = require('cors');
const app = express();

const admin = require("firebase-admin");
const { getFirestore } = require('firebase-admin/firestore');

const credentials = JSON.parse(process.env.FIREBASE_CONFIGURATION);


function generateKey(service) {
    let temp = "";
    let key = "";

    for (let i = 0; i < service.length; i++) {
        if (service[i].charCodeAt(0) >= 97)
            temp += service[i].charCodeAt(0).toString() + (service[i].charCodeAt(0) - 1).toString();
        else
            temp += service[i].charCodeAt(0).toString() + (service[i].charCodeAt(0) + 1).toString();

        key += temp[i] + service[i];
    }

    key += temp.slice(service.length);
    return key;
}

function encrypt(service, plaintext) {

    //Generate Key for encryption
    const key = generateKey(service);

    // Encrypt Password
    return CryptoJS.AES.encrypt(plaintext, key).toString();
}

function decrypt(service, ciphertext) {

    //Generate Key for encryption
    const key = generateKey(service);

    // Encrypt Password
    const bytes = CryptoJS.AES.decrypt(ciphertext, key);
    return bytes.toString(CryptoJS.enc.Utf8);
}

admin.initializeApp({
    credential: admin.credential.cert(credentials)
});

const db = getFirestore();

app.use(express.json());
app.use(cors());

app.use(express.urlencoded({ extended: true }));

app.post('/addPassword', async (req, res) => {
    if (!(req.body.uid && req.body.service && req.body.username && req.body.password && req.headers.authorization))
        return res.status(400).json({ message: 'Request should contain uid, service, username, password and authorization header.' });
    req.body.password = encrypt(req.body.service, req.body.password);
    req.body.username = encrypt(req.body.service, req.body.username);
    const passwords = db.collection('passwords');
    const authToken = req.headers.authorization.split(' ')[1];
    try {
        const decodeValue = await admin.auth().verifyIdToken(authToken);
        if (decodeValue && decodeValue.uid == req.body.uid && decodeValue.email_verified == true) {
            await passwords.add(req.body);
            return res.status(200).json({ message: "Password Added Successfully" });
        }
        return res.status(401).json({ message: 'Unauthorized Access' });
    } catch (e) {
        return res.status(500).json({ message: 'Internal Server Error' });
    }
});

app.post('/editPassword', async (req, res) => {
    if (!(req.body.id && req.body.uid && req.body.service && req.body.username && req.body.password && req.headers.authorization))
        return res.status(400).json({ message: 'Request should contain password id, user id, service, username, password and authorization header.' });

    req.body.password = encrypt(req.body.service, req.body.password);
    req.body.username = encrypt(req.body.service, req.body.username);

    const id = req.body.id;
    delete req.body.id;
    const passwords = db.collection('passwords');
    const authToken = req.headers.authorization.split(' ')[1];
    try {
        const decodeValue = await admin.auth().verifyIdToken(authToken);
        if (decodeValue && decodeValue.uid == req.body.uid && decodeValue.email_verified == true) {
            await passwords.doc(id).update(req.body);
            return res.status(200).json({ message: "Password Updated Successfully" });
        }
        return res.status(400).json({ message: 'Unauthorized Access' });
    } catch (e) {
        return res.status(500).json({ message: 'Internal Server Error' });
    }
});

app.post('/deletePassword', async (req, res) => {
    if (!(req.body.id && req.body.uid && req.headers.authorization))
        return res.status(400).json({ message: 'Request should contain password id, user id and authorization header.' });
    const id = req.body.id;
    const passwords = db.collection('passwords');
    const authToken = req.headers.authorization.split(' ')[1];
    try {
        const decodeValue = await admin.auth().verifyIdToken(authToken);
        if (decodeValue && decodeValue.uid == req.body.uid && decodeValue.email_verified == true) {
            await passwords.doc(id).delete();
            return res.status(200).json({ message: "Password Deleted Successfully" });
        }
        return res.status(400).json({ message: 'Unauthorized Access' });
    } catch (e) {
        return res.status(500).json({ message: 'Internal Server Error' });
    }
});

app.post('/decryptPasswords', async (req, res) => {
    if (!(req.body.passwords && req.headers.authorization))
        return res.status(400).json({ message: 'Request should contain passwords and authorization header.' });
    const authToken = req.headers.authorization.split(' ')[1];
    let passkeys = req.body.passwords;
    let valid = true;
    try {
        const decodeValue = await admin.auth().verifyIdToken(authToken);
        if (decodeValue && decodeValue.email_verified == true) {
            for (let i = 0; i < passkeys.length; i++) {
                if (decodeValue.uid != passkeys[i].uid){
                    valid = false;
                    break;
                }
                passkeys[i].username = decrypt(passkeys[i].service, passkeys[i].username);
                passkeys[i].password = decrypt(passkeys[i].service, passkeys[i].password);
            }
        }
        if (valid == true)
            res.status(200).json({ message: passkeys });
        else
            res.status(400).json({ message : 'Unauthorized access' })
    } catch (error) {
        res.status(500).json({ message: "Internal server error" });
    }
});


app.get('/test', (req, res) => {
    res.status(200).json({ message: 'Server is running.' });
})

const PORT = process.env.PORT || 9000;

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}.`);
})
