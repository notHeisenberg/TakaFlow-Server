const express = require('express');
const app = express();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();
const { MongoClient, ServerApiVersion } = require('mongodb');

const port = process.env.PORT || 3000;

app.use(cors());

app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.pgsiu4c.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        await client.connect();

        const usersCollection = client.db("takaflow").collection("users");

        // Middleware to Verify Tokens
        const verifyToken = (req, res, next) => {
            if (!req.headers.authorization) {
                return res.status(401).send({ message: 'unauthorized access' });
            }
            const token = req.headers.authorization.split(' ')[1];
            jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
                if (err) {
                    return res.status(401).send({ message: 'unauthorized access' });
                }
                req.decoded = decoded;
                next();
            });
        };

        // Login Endpoint
        app.post('/login', async (req, res) => {
            const { emailOrPhone, pin } = req.body;

            try {
                const user = await usersCollection.findOne({
                    $or: [
                        { email: emailOrPhone },
                        { phoneNum: emailOrPhone }
                    ]
                });
                console.log(user)

                if (!user) {
                    return res.status(401).json({ status: 'error', message: 'Invalid credentials' });
                }

                const isMatch = await bcrypt.compare(pin.toString(), user.pin);
                if (!isMatch) {
                    return res.status(401).json({ status: 'error', message: 'Invalid credentials' });
                }

                const token = jwt.sign({ id: user._id, role: user.role }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });

                res.json({
                    status: 'success',
                    token,
                    user
                });
            } catch (error) {
                res.status(500).json({ status: 'error', message: 'Server error', error });
            }
        });


        // Register User
        app.post('/register', async (req, res) => {

            const { email, userName, phoneNum, role, pin, photoUrl, createdAt, approvedBy } = req.body;

            try {
                const userExists = await usersCollection.findOne({
                    $or: [{ phoneNum }, { email }]
                });

                if (userExists) {
                    return res.status(400).send({ message: 'User already exists' });
                }

                const hashedPin = await bcrypt.hash(pin, 10);

                const newUser = {
                    name: userName,
                    email: email,
                    phoneNum: phoneNum,
                    role: role,
                    pin: hashedPin,
                    photoUrl: photoUrl,
                    createdAt: createdAt,
                    approvedBy: approvedBy,
                    status: 'pending', // initial status pending
                    balance: 0, // initial balance
                };

                const result = await usersCollection.insertOne(newUser);

                res.status(201).send(result);
            } catch (error) {
                res.status(500).send({ message: 'Server error', error });
            }
        });

        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);

app.get('/', (req, res) => {
    res.send('taka is flowing')
})

app.listen(port, () => {
    console.log(`Taka is flowing on port ${port}`);
})