    const express = require('express');
    const mongoose = require('mongoose');
    const bcrypt = require('bcrypt');
    const jwt = require('jsonwebtoken');

    const { authenticateUser, authorizeUser } = require('./middleware');

    const app = express();

    const PORT = 5000;

    app.use(express.json());

    app.listen(PORT, () => console.log(`Auth app listening on port ${PORT}`));

    // connect to database
    mongoose.connect('mongodb+srv://asuift458:asu1234@cluster0.qopgnyc.mongodb.net/auth', {useNewUrlParser: true})
        .then(() => console.log('MongoDB connection successful'))
        .catch((err) => console.error(err));

    // define the 'user' schema -----
    const userSchema = new mongoose.Schema({
        email: {
            type: String,
            required: true,
            unique: true,
        },
        password: {
            type: String,
            required: true,
        },
        role: {
            type: String,
            enum: ['user', 'admin'],
            default: 'user',
        },
    });

    userSchema.pre('save', async function (next) {
        const user = this;

        if (!user.isModified('password')) {
            return next();
        }

        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(user.password, salt);

        user.password = hash;

        next();
    });

    const User = mongoose.model('User', userSchema);

    // user registration endpoint -----
    app.post('/register', async (req, res) => {
        try {
            const { email, password } = req.body;
            const user = new User({ email, password });

            User.create({
                email: email,
                password: password,
            });

            res.json({
                success: true,
                data: user,
                message: 'User registered sucessfully',
            });
        } catch (error) {
            console.error(error);
            res.status(500).json({
                success: false,
                message: 'An error has occured',
            });
        }
    });

    // user login endpoint -----
    app.post('/login', async (req, res) => {
        try {
            const { email, password } = req.body;
            
            const user = await User.findOne({ email });
            // invalid email
            if (!user) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid email',
                });  
            }
            // compare password
            const isMatch = await bcrypt.compare(password, user.password);
            // invalid password
            if (!isMatch) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid password'
                });
            }

            const token = jwt.sign({ userId: user._id, role: user.role }, 'secret');

            res.json ({
                success: true,
                token,
            });
        
        } catch (error) {
            console.error(error);
            res.status(500).json({
                success: false,
                message: 'An error has occured',
            });
        }
    });

    // protected resource endpoint -----
    app.get('/protected', authenticateUser, authorizeUser(['admin']), (req, res) => {
        res.json({
            success: true,
            message: 'You have accessed a protected resource',
        });
    })