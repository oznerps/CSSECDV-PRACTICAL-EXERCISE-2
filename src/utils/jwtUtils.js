import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-change-in-production-min-32-chars';
const JWT_EXPIRES_IN = '24h';

export const generateToken = (user) => {
    const payload = {
        userId: user.id,
        username: user.username,
        email: user.email,
        roles: user.roles?.map(r => r.name) || []
    };
    
    return jwt.sign(payload, JWT_SECRET, { 
        expiresIn: JWT_EXPIRES_IN,
        issuer: 'cssecdv-pe3'
    });
};

export const verifyToken = (token) => {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            throw new Error('Token expired');
        } else if (error.name === 'JsonWebTokenError') {
            throw new Error('Invalid token');
        } else {
            throw new Error('Token verification failed');
        }
    }
};

export const refreshToken = (oldToken) => {
    try {
        // Verify the old token ignoring expiration
        const decoded = jwt.verify(oldToken, JWT_SECRET, { ignoreExpiration: true });
        
        // Remove JWT-specific fields and create new token
        const { iat, exp, ...payload } = decoded;
        
        return jwt.sign(payload, JWT_SECRET, { 
            expiresIn: JWT_EXPIRES_IN,
            issuer: 'cssecdv-pe3'
        });
    } catch (error) {
        throw new Error('Cannot refresh token');
    }
};

export const decodeToken = (token) => {
    try {
        // Decode without verification (for getting payload info)
        return jwt.decode(token);
    } catch (error) {
        return null;
    }
};

export const isTokenExpired = (token) => {
    try {
        const decoded = jwt.decode(token);
        if (!decoded || !decoded.exp) {
            return true;
        }
        
        const currentTime = Math.floor(Date.now() / 1000);
        return decoded.exp < currentTime;
    } catch (error) {
        return true;
    }
};