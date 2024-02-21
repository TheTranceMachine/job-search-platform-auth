const express = require('express');
const session = require('express-session');
const fs = require('fs')
const https = require('https')
const http = require('http')
const cors = require('cors')
const axios = require('axios');
const log4js = require('log4js');
const jwt = require('jsonwebtoken');
const logger = log4js.getLogger("using-management-api");
logger.level = "DEBUG";

logger.info("Starting");

const CLOUD_IAM_URL = process.env.CLOUD_IAM_URL
const CLOUD_IAM_API_KEY = process.env.IAM_API_KEY;
const APPID_MANAGEMENT_URL = process.env.MANAGEMENT_URL;

const app = express()
// Enable CORS
app.use(
    cors({
        origin: 'http://localhost:5173',
    })
)

// Middleware for parsing JSON and URL-encoded bodies
app.use(express.json())
app.use(express.urlencoded({ extended: false }))

// Use express-session middleware
app.use(session({
    secret: 'your-secret-key',
    resave: true,
    saveUninitialized: true
}));

const AuthenticateUserMiddleware = async (req, res, next) => {
    const { username, password } = req.body;
    const data = {
        'grant_type': 'password',
        'username': username,
        'password': password
    };

    try {
        logger.info(`Retrieving user ${username}`);
        const response = await axios({
            method: "POST",
            url: `${process.env.OAUTH_SERVER_URL}/token`,
            headers: {
                'accept': 'application/json',
                'authorization': `Basic ${btoa(`${process.env.CLIENT_ID}:${process.env.SECRET}`)}`,
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            data
        });
        logger.info(response.data);
        req.session.accessToken = response.data.access_token;
        req.session.idToken = response.data.id_token;
        // req.session.tokenExpirationTime = expirationTime;
        next()
    } catch (err) {
        logger.info(err.response.data);
        res.status(400).json({ message: err.response.data })
    }
}

const decodeToken = (token) => {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(atob(base64).split('').map(function (c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));

    return jsonPayload;
}

// Login route
app.post('/login', AuthenticateUserMiddleware, async (req, res) => {
    // logger.info(req.session.accessToken);
    if (req.session.accessToken && req.session.idToken) {
        // decode idToken and send json response with user data
        const user = decodeToken(req.session.idToken);
        const parsed = JSON.parse(user);
        const { email, name, email_verified, preferred_username } = parsed;
        // ToDo: Before you respond, check if the user email was verified
        if (!email_verified) {
            res.status(401).json({ message: 'Email is not verified!' });
        }
        res.status(200).json({ message: { email, name, email_verified, preferred_username } });
    } else {
        res.status(401).json({ message: 'Unauthorized!' });
    }
})

function verifyTokenForAllRoutes(req, res, next) {
    // Get the token, decode it and compare exp time with current time
    const accessToken = req.session.accessToken; // Assuming the token is passed in the Authorization header

    if (!accessToken) {
        return res.status(401).json({ error: 'Unauthorized!' });
    }

    const decodedToken = decodeToken(req.session.accessToken);
    const parsedAccessToken = JSON.parse(decodedToken);
    logger.info(parsedAccessToken);
    const now = Date.now() / 1000;
    if (now < parsedAccessToken.exp) {
        // Token is still valid, proceed with using it
        logger.info('Access token is still valid');
        next();
    } else {
        // Token has expired, handle accordingly (e.g., request a new token)
        return res.status(403).json({ error: 'Invalid access token' });
    }
}

// Apply the middleware to all routes
app.use(verifyTokenForAllRoutes);

app.get('/protected', (req, res) => {
    // Check if access token exists in the session
    logger.info('IM PROTECTED!');
    res.status(200).json({ message: 'Authorized!' });
});

async function getCloudIamAccessToken() {
    logger.info("Retrieving Cloud IAM access token with API key", CLOUD_IAM_API_KEY);
    let response = await request({
        method: "POST",
        url: CLOUD_IAM_URL,
        json: true,
        form: {
            "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
            "apikey": CLOUD_IAM_API_KEY
        }
    });
    const accessToken = response["access_token"];
    logger.info("Retrieved Cloud IAM access token", accessToken);
    return accessToken;
}

async function getUserById(id) {
    try {
        logger.info(`Retrieving user id ${id}`);
        const cloudIamAccessToken = await getCloudIamAccessToken();
        return await axios({
            method: "GET",
            url: APPID_MANAGEMENT_URL + `/cloud_directory/Users/${id}`,
            headers: {
                "Authorization": "Bearer " + cloudIamAccessToken
            }
        });
    } catch (err) {
        return err;
    }
}

async function getUsers() {
    const cloudIamAccessToken = await getCloudIamAccessToken();
    logger.info("Retrieving all users");
    let response = await request({
        method: "GET",
        url: APPID_MANAGEMENT_URL + "/cloud_directory/Users",
        json: true,
        headers: {
            "Authorization": "Bearer " + cloudIamAccessToken
        }
    });
    logger.info("Response:", response);
}

async function createUser() {
    const cloudIamAccessToken = await getCloudIamAccessToken();
    logger.info("Creating a new user");
    let response = await request({
        method: "POST",
        url: APPID_MANAGEMENT_URL + "/cloud_directory/sign_up?shouldCreateProfile=true",
        json: true,
        headers: {
            "Authorization": "Bearer " + cloudIamAccessToken
        },
        body: {
            status: "PENDING",
            userName: "***REMOVED***",
            password: "***REMOVED***",
            name: {
                givenName: "Greg",
                familyName: "Smolin",
                formatted: "Greg Smolin"
            },
            emails: [{
                value: "***REMOVED***",
                primary: true
            }]
        }
    });
    logger.info("Response:", response);
}

async function deleteUser() {
    const cloudIamAccessToken = await getCloudIamAccessToken();
    const userId = process.argv[3];
    logger.info("Deleting a user with ID", userId);
    let response = await request({
        method: "DELETE",
        url: APPID_MANAGEMENT_URL + "/cloud_directory/Users/" + userId,
        json: true,
        headers: {
            "Authorization": "Bearer " + cloudIamAccessToken
        }
    });
    logger.info("Done!");
}

// Start server
const HTTP_PORT = process.env.PORT || 8080
const HTTPS_PORT = 443

// Run HTTP server
http.createServer(app).listen(HTTP_PORT, () => {
    console.log(`HTTP listening on port ${HTTP_PORT}`)
})

// HTTPS configuration
// this is only local signed cert, for production it will need certbot or paid SSL cert
const privateKey = fs.readFileSync('server.key', 'utf8')
const certificate = fs.readFileSync('server.cert', 'utf8')
const credentials = { key: privateKey, cert: certificate }

const httpsServer = https.createServer(credentials, app)

// Run HTTPS server
httpsServer.listen(HTTPS_PORT, () => {
    console.log(`HTTPS listening on port ${HTTPS_PORT}`)
})