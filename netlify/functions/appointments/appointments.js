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

// Get appointments from Netlify Function (you can integrate with a database here)
async function getAppointments() {
    // This is a placeholder - in production, you'd fetch from a database
    return [];
}

// Save appointment
async function saveAppointment(appointment) {
    // This is a placeholder - in production, you'd save to a database
    console.log('Saving appointment:', appointment);
    return { success: true };
}

exports.handler = async (event, context) => {
    // Handle preflight requests
    if (event.httpMethod === 'OPTIONS') {
        return {
            statusCode: 200,
            headers: {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type, Authorization',
                'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS'
            }
        };
    }
    
    // Check authentication for protected routes
    const authHeader = event.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return {
            statusCode: 401,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            body: JSON.stringify({ error: 'No token provided' })
        };
    }
    
    const token = authHeader.substring(7);
    const decoded = verifyToken(token);
    
    if (!decoded) {
        return {
            statusCode: 401,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            body: JSON.stringify({ error: 'Invalid or expired token' })
        };
    }
    
    try {
        switch (event.httpMethod) {
            case 'GET':
                const appointments = await getAppointments();
                return {
                    statusCode: 200,
                    headers: {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    },
                    body: JSON.stringify(appointments)
                };
                
            case 'POST':
                const appointment = JSON.parse(event.body);
                const result = await saveAppointment(appointment);
                return {
                    statusCode: 201,
                    headers: {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    },
                    body: JSON.stringify(result)
                };
                
            default:
                return {
                    statusCode: 405,
                    headers: {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    },
                    body: JSON.stringify({ error: 'Method not allowed' })
                };
        }
    } catch (error) {
        return {
            statusCode: 500,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            body: JSON.stringify({ error: 'Internal server error' })
        };
    }
};