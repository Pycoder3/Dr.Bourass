const crypto = require('crypto');

// Store credentials in environment variables for security
const ALLOWED_USERNAME = process.env.ALLOWED_USERNAME || 'nour';
const ALLOWED_PASSWORD = process.env.ALLOWED_PASSWORD || 'nounou358';
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-here';

// Simple JWT-like token generation
function generateToken(username) {
    const header = {
        alg: 'HS256',
        typ: 'JWT'
    };
    
    const payload = {
        username: username,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) // 24 hours
    };
    
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    
    const signature = crypto
        .createHmac('sha256', JWT_SECRET)
        .update(`${encodedHeader}.${encodedPayload}`)
        .digest('base64url');
    
    return `${encodedHeader}.${encodedPayload}.${signature}`;
}

// Verify token
function verifyToken(token) {
    try {
        const [header, payload, signature] = token.split('.');
        
        const expectedSignature = crypto
            .createHmac('sha256', JWT_SECRET)
            .update(`${header}.${payload}`)
            .digest('base64url');
        
        if (signature !== expectedSignature) {
            return null;
        }
        
        const decodedPayload = JSON.parse(Buffer.from(payload, 'base64url').toString());
        
        // Check if token is expired
        if (decodedPayload.exp < Math.floor(Date.now() / 1000)) {
            return null;
        }
        
        return decodedPayload;
    } catch (error) {
        return null;
    }
}

exports.handler = async (event, context) => {
    // Only allow POST requests
    if (event.httpMethod !== 'POST') {
        return {
            statusCode: 405,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type, Authorization',
                'Access-Control-Allow-Methods': 'POST, OPTIONS'
            },
            body: JSON.stringify({ error: 'Method not allowed' })
        };
    }
    
    // Handle preflight requests
    if (event.httpMethod === 'OPTIONS') {
        return {
            statusCode: 200,
            headers: {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type, Authorization',
                'Access-Control-Allow-Methods': 'POST, OPTIONS'
            }
        };
    }
    
    try {
        const { username, password } = JSON.parse(event.body);
        
        // Validate credentials
        if (username === ALLOWED_USERNAME && password === ALLOWED_PASSWORD) {
            const token = generateToken(username);
            
            return {
                statusCode: 200,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
                },
                body: JSON.stringify({
                    success: true,
                    message: 'Login successful',
                    token: token,
                    user: {
                        username: username
                    }
                })
            };
        } else {
            return {
                statusCode: 401,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
                },
                body: JSON.stringify({
                    success: false,
                    message: 'Invalid username or password'
                })
            };
        }
    } catch (error) {
        return {
            statusCode: 500,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            body: JSON.stringify({
                success: false,
                message: 'Internal server error'
            })
        };
    }
};