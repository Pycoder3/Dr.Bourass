const crypto = require('crypto');

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-here';

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
                'Access-Control-Allow-Headers': 'Content-Type, Authorization'
            },
            body: JSON.stringify({ error: 'Method not allowed' })
        };
    }
    
    try {
        const { token } = JSON.parse(event.body);
        
        if (!token) {
            return {
                statusCode: 401,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                body: JSON.stringify({
                    authenticated: false,
                    message: 'No token provided'
                })
            };
        }
        
        const decoded = verifyToken(token);
        
        if (decoded) {
            return {
                statusCode: 200,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                body: JSON.stringify({
                    authenticated: true,
                    user: {
                        username: decoded.username
                    }
                })
            };
        } else {
            return {
                statusCode: 401,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                body: JSON.stringify({
                    authenticated: false,
                    message: 'Invalid or expired token'
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
                authenticated: false,
                message: 'Internal server error'
            })
        };
    }
};