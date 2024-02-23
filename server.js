const express = require('express');
const session = require('express-session');
// const fs = require('fs')
// const https = require('https')
const http = require('http')
const cors = require('cors')
const axios = require('axios');
const log4js = require('log4js');
const logger = log4js.getLogger("using-management-api");
logger.level = "DEBUG";

logger.info("Starting");

const CLOUD_IAM_URL = process.env.CLOUD_IAM_URL
const CLOUD_IAM_API_KEY = process.env.IAM_API_KEY;
const APPID_MANAGEMENT_URL = process.env.MANAGEMENT_URL;
const CLIENT_ID = process.env.CLIENT_ID;
const SECRET = process.env.SECRET;
const OAUTH_SERVER_URL = process.env.OAUTH_SERVER_URL;
const SESSION_SECRET = process.env.SESSION_SECRET;
const PORT = process.env.PORT;
const S_PORT = process.env.S_PORT;

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
    secret: SESSION_SECRET,
    resave: true,
    saveUninitialized: true
}));

////////////////////////////////////////////////// Login

const AuthenticateUserMiddleware = async (req, res, next) => {
    const { username, password } = req.body;
    const data = {
        'grant_type': 'password',
        'username': username,
        'password': password
    };

    const config = {
        method: "POST",
        url: `${OAUTH_SERVER_URL}/token`,
        headers: {
            'accept': 'application/json',
            'authorization': `Basic ${btoa(`${CLIENT_ID}:${SECRET}`)}`,
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        data
    }

    try {
        logger.info(`Retrieving user ${username}`);
        const response = await axios(config);

        req.session.accessToken = response.data.access_token;
        req.session.idToken = response.data.id_token;
        req.session.refreshToken = response.data.refresh_token;

        next()
    } catch (err) {
        logger.info(err.response.data);
        res.status(400).json({ message: err.response.data.error_description })
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
    if (req.session.accessToken && req.session.idToken && req.session.refreshToken) {
        // decode idToken and send json response with user data
        const user = decodeToken(req.session.idToken);
        const parsed = JSON.parse(user);
        const { email, name, email_verified, preferred_username } = parsed;
        // ToDo: Before you respond, check if the user email was verified
        if (!email_verified) {
            res.status(401).json({ message: 'Email is not verified!' });
        }
        res.status(200).json({ message: 'User logged in!', body: { email, name, email_verified, preferred_username } });
    } else {
        res.status(401).json({ message: 'Unauthorized!' });
    }
})

////////////////////////////////////////////////// Registration

const getCloudIamAccessToken = async () => {
    try {
        logger.info("Retrieving Cloud IAM access token with API key");
        const config = {
            method: "POST",
            url: CLOUD_IAM_URL,
            headers: {
                'accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            data: {
                "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
                "apikey": CLOUD_IAM_API_KEY
            }
        }
        const response = await axios(config);
        logger.info(response)
        const accessToken = response.data.access_token;
        logger.info("Retrieved Cloud IAM access token");
        return accessToken;
    } catch (err) {
        logger.info(err)
        return err;
    }

}

const createUser = async ({ userName, password, email }) => {
    const cloudIamAccessToken = await getCloudIamAccessToken();
    try {
        logger.info("Creating a new user");
        const data = {
            status: "PENDING",
            userName,
            password,
            emails: [{
                value: email,
                primary: true
            }]
        };
        const config = {
            method: "POST",
            url: APPID_MANAGEMENT_URL + "/cloud_directory/sign_up?shouldCreateProfile=true",
            headers: {
                "Authorization": "Bearer " + cloudIamAccessToken
            },
            data
        }
        return await axios(config);
    } catch (err) {
        return err;
    }
}

app.post('/register', async (req, res) => {
    const { userName, password, email } = req.body;
    const response = await createUser({ userName, password, email });
    if (response.status > 201) {
        res.status(response.data.status).json({ message: response.data.detail })
    } else {
        res.status(200).json({ message: 'User registered!', body: response.data })
    }
})

////////////////////////////////////////////////// Authenticated Routes

const validateToken = (token) => {
    const decodedToken = decodeToken(token);
    const parsedAccessToken = JSON.parse(decodedToken);
    logger.info(parsedAccessToken);
    const now = Date.now() / 1000;
    if (now < parsedAccessToken.exp) {
        // Token is still valid, proceed with using it
        logger.info('Access token is still valid');
        return true;
    } else {
        logger.info('Access token is invalid');
        // Token has expired, handle accordingly (e.g., request a new token)
        return false;
    }
}

const verifyTokenForAllRoutes = async (req, res, next) => {
    // Get the token, decode it and compare exp time with current time
    const accessToken = req.session.accessToken; // Assuming the token is passed in the Authorization header
    const refreshToken = req.session.refreshToken; // Assuming the token is passed in the Authorization header

    console.log(accessToken);
    console.log(refreshToken);
    console.log(req.session);
    if (!accessToken) {
        return res.status(401).json({ error: 'Unauthorized!' });
    }

    if (validateToken(accessToken)) {
        next();
    } else {
        const data = {
            'grant_type': 'refresh_token',
            'refresh_token': refreshToken
        };
        const config = {
            method: 'POST',
            maxBodyLength: Infinity,
            url: `${OAUTH_SERVER_URL}/token`,
            headers: {
                'accept': 'application/json',
                'authorization': `Basic ${btoa(`${CLIENT_ID}:${SECRET}`)}`,
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            data
        };
        try {
            const response = await axios(config);

            console.log(response);

            req.session.accessToken = response.data.access_token;
            req.session.idToken = response.data.id_token;
            req.session.refreshToken = response.data.refresh_token;

            next()
        } catch (err) {
            logger.info(err.response.data);
            res.status(400).json({ message: err.response.data.error_description })
        }
    }
}

// Apply the middleware to all routes
app.use(verifyTokenForAllRoutes);

app.get('/todos', (req, res) => {
    // Check if access token exists in the session
    logger.info('IM PROTECTED!');
    res.status(200).json({ message: 'Authorized!', body: [{ text: 'first' }] });
});



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
const HTTP_PORT = PORT || 8080

// Run HTTP server
http.createServer(app).listen(HTTP_PORT, () => {
    console.log(`HTTP listening on port ${HTTP_PORT}`)
})

// HTTPS configuration
const HTTPS_PORT = S_PORT
// this is only local signed cert, for production it will need certbot or paid SSL cert
// const privateKey = fs.readFileSync('server.key', 'utf8')
// const certificate = fs.readFileSync('server.cert', 'utf8')
// const credentials = { key: privateKey, cert: certificate }

// const httpsServer = https.createServer(credentials, app)

// Run HTTPS server
// httpsServer.listen(HTTPS_PORT, () => {
//     console.log(`HTTPS listening on port ${HTTPS_PORT}`)
// })