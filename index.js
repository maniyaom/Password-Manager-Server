const express = require("express");
require('dotenv').config();
const cors = require('cors');
const app = express();

const admin = require("firebase-admin");
const { getFirestore } = require('firebase-admin/firestore');

const credentials = JSON.parse(process.env.FIREBASE_CONFIGURATION);

admin.initializeApp({
    credential: admin.credential.cert(credentials)
});

const db = getFirestore();

app.use(express.json());
app.use(cors());

app.use(express.urlencoded({ extended: true }));

app.post('/addPassword', async (req, res) => {
    const passwords = db.collection('passwords');
    const authToken = req.headers.authorization.split(' ')[1];
    try {
        const decodeValue = await admin.auth().verifyIdToken(authToken);
        if (decodeValue && decodeValue.uid == req.body.uid && decodeValue.email_verified == true) {
            await passwords.add(req.body);
            return res.status(200).json({ message : "Password Added Successfully"});
        }
        return res.status(400).json({ message: 'Unauthorized Access' });
    } catch (e) {
        return res.status(500).json({ message: 'Internal Server Error' });
    }
});

app.post('/editPassword', async (req, res) => {
    const id = req.body.id;
    delete req.body.id;
    const passwords = db.collection('passwords');
    const authToken = req.headers.authorization.split(' ')[1];
    try {
        const decodeValue = await admin.auth().verifyIdToken(authToken);
        if (decodeValue && decodeValue.uid == req.body.uid && decodeValue.email_verified == true) {
            await passwords.doc(id).update(req.body);
            return res.status(200).json({ message : "Password Updated Successfully"});
        }
        return res.status(400).json({ message: 'Unauthorized Access' });
    } catch (e) {
        return res.status(500).json({ message: 'Internal Server Error' });
    }
});

app.post('/deletePassword', async (req, res) => {
    const id = req.body.id;
    const passwords = db.collection('passwords');
    const authToken = req.headers.authorization.split(' ')[1];
    try {
        const decodeValue = await admin.auth().verifyIdToken(authToken);
        if (decodeValue && decodeValue.uid == req.body.uid && decodeValue.email_verified == true) {
            await passwords.doc(id).delete();
            return res.status(200).json({ message : "Password Deleted Successfully"});
        }
        return res.status(400).json({ message: 'Unauthorized Access' });
    } catch (e) {
        return res.status(500).json({ message: 'Internal Server Error' });
    }
});

app.post('/getPassword', async (req, res) => {
    const passwords = db.collection('passwords');
    const authToken = req.headers.authorization.split(' ')[1];

    try{
        const decodeValue = await admin.auth().verifyIdToken(authToken);
        if (decodeValue && decodeValue.uid == req.body.uid && decodeValue.email_verified == true) {
            const snapshot = await passwords.where('uid', '==', req.body.uid).get();
            
            let foundPassword = null;
            snapshot.forEach((doc) => {
                if (doc.id == req.body.id)
                    foundPassword = doc.data();
            })
            if (foundPassword)
                return res.status(200).json(foundPassword);
            return res.status(400).json({ message: 'Unauthorized Access' });
        }
    }
    catch (e) {
        return res.status(500).json({ message: 'Internal Server Error' });
    }
});

app.get('/test', (req,res) => {
    res.status(200).json({ message: 'Server is running.' });
})

const PORT = process.env.PORT || 9000;

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}.`);
})
