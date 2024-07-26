const express = require('express');
const app = express();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

const port = process.env.PORT || 4000;

app.use(cors(
    {
        origin: [
            "http://localhost:5173",
            "https://easytaka-mfs.netlify.app"

        ]
    }
));

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
        const transactionsCollection = client.db("takaflow").collection("transactions");

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

        const verifyAdmin = (req, res, next) => {
            if (!req.headers.authorization) {
                return res.status(401).send({ message: 'unauthorized access' });
            }
            const token = req.headers.authorization.split(' ')[1];
            jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
                if (err) {
                    return res.status(401).send({ message: 'unauthorized access' });
                }
                if (decoded.role !== 'admin') {
                    return res.status(403).send({ message: 'Forbidden access' });
                }
                req.decoded = decoded;

                next();
            });
        }

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


                if (!user) {
                    return res.status(401).json({ status: 'error', message: 'Invalid Email/PhoneNum' });
                }

                const isMatch = await bcrypt.compare(pin.toString(), user.pin);
                if (!isMatch) {
                    return res.status(401).json({ status: 'error', message: 'Invalid Pin' });
                }

                const token = jwt.sign({ id: user._id, role: user.role, email: user.email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });

                res.status(200).json({
                    status: 'success',
                    token,
                    user: {
                        id: user._id,
                        name: user.name,
                        email: user.email,
                        phoneNum: user.phoneNum,
                        role: user.role,
                        photoUrl: user.photoUrl,
                        status: user.status,
                        balance: user.balance
                    },
                    message: 'Login successful'
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

        app.patch('/update-profile', verifyToken, async (req, res) => {
            const { name, phoneNum, photoUrl, pin } = req.body;
            const { id } = req.decoded;

            try {
                const user = await usersCollection.findOne({ _id: new ObjectId(id) });

                const isMatch = await bcrypt.compare(pin.toString(), user.pin);
                if (!isMatch) {
                    return res.status(400).json({ status: 'error', message: 'Invalid Pin' });
                }

                const result = await usersCollection.updateOne(
                    { _id: new ObjectId(id) },
                    {
                        $set: {
                            name,
                            phoneNum,
                            photoUrl
                        }
                    }
                );

                res.status(200).send(result);
            } catch (error) {
                res.status(500).send({ message: 'Server error', error });
            }
        });

        // Done - Update Status
        app.patch('/users/:id', verifyAdmin, async (req, res) => {
            const { status } = req.body;
            const { id } = req.params;

            try {
                if (status === 'active') {
                    const result = await usersCollection.updateOne(
                        { _id: new ObjectId(id) },
                        {
                            $set: {
                                status,
                                balance: 40
                            }
                        }
                    );

                    res.status(200).send(result);
                } else if (status === 'blocked') {
                    const result = await usersCollection.updateOne(
                        { _id: new ObjectId(id) },
                        {
                            $set: {
                                status
                            }
                        }
                    );

                    res.status(200).send(result);
                }
            } catch (error) {
                res.status(500).send({ message: 'Server error', error });
            }
        });

        // TO-DO - Update Pin
        app.patch('/update-pin', verifyToken, async (req, res) => {
            const { oldPin, newPin } = req.body;
            const { id } = req.decoded;

            try {
                const user = await usersCollection.findOne({ _id: new ObjectId(id) });

                const isMatch = await bcrypt.compare(oldPin.toString(), user.pin);
                if (!isMatch) {
                    return res.status(400).json({ status: 'error', message: 'Invalid Pin' });
                }

                const hashedPin = await bcrypt.hash(newPin, 10);

                const result = await usersCollection.updateOne(
                    { _id: new ObjectId(id) },
                    {
                        $set: {
                            pin: hashedPin
                        }
                    }
                );

                res.status(200).send(result);
            } catch (error) {
                res.status(500).send({ message: 'Server error', error });
            }
        });

        // Get All Users
        app.get('/users', verifyAdmin, async (req, res) => {
            try {
                const users = await usersCollection.find({ role: { $ne: 'admin' } }).toArray();

                res.status(200).send(users);
            } catch (error) {
                res.status(500).send({ message: 'Server error', error });
            }
        });

        // Get User ballance By email
        app.get('/users/:email', verifyToken, async (req, res) => {
            const { email } = req.params; 


            try {
                const user = await usersCollection.findOne({ email });

                res.status(200).send({
                    user: {
                        id: user._id,
                        name: user.name,
                        email: user.email,
                        phoneNum: user.phoneNum,
                        role: user.role,
                        photoUrl: user.photoUrl,
                        status: user.status,
                        balance: user.balance
                    }
                });
            } catch (error) {
                res.status(500).send({ message: 'Server error', error });
            }
        });

        // Send Money
        app.post('/send-money', verifyToken, async (req, res) => {
            const { amount, receiverEmail, pin } = req.body;
            const { id } = req.decoded;

            try {
                const sender = await usersCollection.findOne({ _id: new ObjectId(id) });
                const receiver = await usersCollection.findOne({ email: receiverEmail });

                if (!receiver || receiver.status === 'pending' || receiver.role === 'admin' || receiver.role === 'agent') {
                    return res.status(404).send({ message: 'User not found' });
                }

                const isMatch = await bcrypt.compare(pin.toString(), sender.pin);
                if (!isMatch) {
                    return res.status(400).json({ status: 'error', message: 'Invalid Pin' });
                }

                if (sender.balance < amount) {
                    return res.status(406).send({ message: 'Insufficient balance' });
                }

                const session = client.startSession();
                session.startTransaction();

                try {
                    if (sender._id.toString() === receiver._id.toString()) {
                        return res.status(405).send({ message: 'You cannot send money to yourself' });
                    }

                    const senderBalance = amount > 100 ? sender.balance - amount - 5 : sender.balance - amount;
                    const receiverBalance = receiver.balance + amount;

                    const updateSender = usersCollection.updateOne(
                        { _id: new ObjectId(id) },
                        { $set: { balance: senderBalance } },
                        { session }
                    );

                    const updateReceiver = usersCollection.updateOne(
                        { email: receiverEmail },
                        { $set: { balance: receiverBalance } },
                        { session }
                    );

                    const generateTransactionId = () => {
                        const chars = '0123456789';
                        let transId = '';
                        for (let i = 0; i < 10; i++) {
                            transId += chars.charAt(Math.floor(Math.random() * chars.length));
                        }
                        return transId;
                    }

                    const transactionID = generateTransactionId();

                    const transaction = {
                        senderInfo: {
                            name: sender.name,
                            email: sender.email,
                            phoneNum: sender.phoneNum,
                        },
                        receiverInfo: {
                            name: receiver.name,
                            email: receiver.email,
                            phoneNum: receiver.phoneNum,
                        },
                        amount,
                        transactionType: 'send-money',
                        transactionId: transactionID,
                        status: 'success',
                        createdAt: new Date()
                    };

                    const createTransaction = transactionsCollection.insertOne(transaction, { session });

                    await Promise.all([updateSender, updateReceiver, createTransaction]);

                    await session.commitTransaction();
                    session.endSession();

                    res.status(200).send({ message: 'Transaction successful', transaction });
                } catch (error) {
                    await session.abortTransaction();
                    session.endSession();
                    res.status(500).send({ message: 'Transaction failed', error });
                }
            } catch (error) {
                res.status(500).send({ message: 'Server error', error });
            }
        });

        // Get All Transactions
        app.get('/transactions', verifyAdmin, async (req, res) => {
            try {
                const transactions = await transactionsCollection.find().toArray();

                res.status(200).send(transactions);
            } catch (error) {
                res.status(500).send({ message: 'Server error', error });
            }
        });

        // Get User Transactions
        app.get('/user-transactions', verifyToken, async (req, res) => {
            const { id,role } = req.decoded;

            try {
                if (role === 'agent') {
                    const userTransactions = await transactionsCollection.find({
                        $or: [
                            { 'senderInfo.email': req.decoded.email },
                            { 'receiverInfo.email': req.decoded.email }
                        ]
                    }).sort({ createdAt: -1 }).toArray();
                    return res.status(200).limit(10).send(userTransactions);
                }
                else {
                    const userTransactions = await transactionsCollection.find({
                        $or: [
                            { 'senderInfo.email': req.decoded.email },
                            { 'receiverInfo.email': req.decoded.email }
                        ]
                    }).sort({ createdAt: -1 }).limit(20).toArray();
                    return res.status(200).send(userTransactions);
                }
                
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