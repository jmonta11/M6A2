    const jwt = require('jsonwebtoken');
    const { decode } = require('punycode');

    // verify authentication using token
    const authenticateUser = (req, res, next) => {
        const token = req.headers.authorization;

        if (!token) {
            return res.status(401).json({
                success: false,
                message: 'Unauthorized',
            });
        }

        try {
            const decodedToken = jwt.verify(token, 'secret');
            req.user = decodedToken;
            next();
        } catch (error) {
            console.error(error);
            res.status(401).json({
                success: false,
                message: 'Invalid token'
            })
        };
    };

    // verify resource authorization according to role
    const authorizeUser = (roles) => {
        return (req, res, next) => {
            const { role } = req.user;

            if (!roles.includes(role)) {
                return res.status(403).json({
                    success: false,
                    message: 'Forbidden'
                });
            }

            next();
        };
    };

    module.exports = { authenticateUser, authorizeUser };