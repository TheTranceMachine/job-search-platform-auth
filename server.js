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

const CLOUD_IAM_URL = process.env.CLOUD_IAM_URL;
const CLOUD_IAM_API_KEY = process.env.IAM_API_KEY;
const APPID_MANAGEMENT_URL = process.env.MANAGEMENT_URL;
const CLIENT_ID = process.env.CLIENT_ID;
const SECRET = process.env.SECRET;
const OAUTH_SERVER_URL = process.env.OAUTH_SERVER_URL;
const SESSION_SECRET = process.env.SESSION_SECRET;
const PORT = process.env.PORT;

const app = express()
// Enable CORS
app.use(
    cors({
        origin: 'http://localhost:5173',
        credentials: true
    })
)

// Middleware for parsing JSON and URL-encoded bodies
app.use(express.json())
app.use(express.urlencoded({ extended: false }))

// Use express-session middleware
app.use(session({
    secret: SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
    cookie: { sameSite: 'lax' }
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
        logger.warn(`Creating accessToken for user ${username}`);
        const response = await axios(config);

        req.session.accessToken = response.data.access_token;
        req.session.idToken = response.data.id_token;
        req.session.refreshToken = response.data.refresh_token;

        logger.info(`Created accessToken and RefreshToken for ${username}`);

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

const sendForgottenPasswordEmail = async (userName) => {
    const cloudIamAccessToken = await getCloudIamAccessToken();
    logger.info(userName)
    const config = {
        method: "POST",
        url: APPID_MANAGEMENT_URL + "/cloud_directory/forgot_password",
        headers: {
            "Authorization": "Bearer " + cloudIamAccessToken
        },
        data: {
            user: userName
        }
    }
    return await axios(config);
}

// Login route
app.post('/login', AuthenticateUserMiddleware, async (req, res) => {
    // logger.info(req.session.accessToken);
    if (req.session.accessToken && req.session.idToken && req.session.refreshToken) {
        // decode idToken and send json response with user data
        const user = decodeToken(req.session.idToken);
        const parsed = JSON.parse(user);
        console.log(parsed);
        const { email, name, email_verified, preferred_username } = parsed;
        // ToDo: Before you respond, check if the user email was verified
        if (!email_verified) {
            logger.error('Email is not verified!');
            res.status(401).json({ message: 'Email is not verified!' });
        }
        res.status(200).json({ message: 'User logged in!', body: { email, name, email_verified, preferred_username } });
    } else {
        logger.error('Unauthenticated');
        res.status(401).json({ message: 'Unauthenticated!' });
    }
})

app.post('/forgot_password', (req, res) => {
    const { username } = req.body;
    logger.info(`User ${username} forgot password`);
    try {
        const user = sendForgottenPasswordEmail(username);
        res.status(200).json({ message: 'Reset Password Email was Sent.' });
    } catch (err) {
        res.status(500).json({ message: 'Something went wrong. Check if your username is correct.' });
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
        const accessToken = response.data.access_token;
        logger.info("Retrieved Cloud IAM access token");
        return accessToken;
    } catch (err) {
        logger.info(err)
        return err;
    }

}

const resendUserVerification = async (uuid) => {
    const cloudIamAccessToken = await getCloudIamAccessToken();
    const config = {
        method: "POST",
        url: APPID_MANAGEMENT_URL + "/cloud_directory/resend/USER_VERIFICATION",
        headers: {
            "Authorization": "Bearer " + cloudIamAccessToken
        },
        data: { uuid }
    }
    return await axios(config);
}

const createUser = async ({ userName, password, email }) => {
    const cloudIamAccessToken = await getCloudIamAccessToken();
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
}

app.post('/register', async (req, res) => {
    const { userName, password, email } = req.body;
    if (email === '' || password === '' || userName === '') {
        logger.error('No username, password and email');
        res.status(400).json({ message: 'Please provide username, password and email' });
    } else {
        try {
            const user = await createUser({ userName, password, email });
            console.log(user);
            logger.info('Created a new user!');
            res.status(200).json({ message: 'User registered!', body: user.data })
        } catch (err) {
            logger.error(err.response.data);
            res.status(err.response.status).json({ message: err.response.data.detail })
        }
    }
})

app.post('/register/resend', async (req, res) => {
    const { id } = req.body;
    console.log(id);
    try {
        logger.info(`Resending verification email for user id ${id}`);
        resendUserVerification(id);
        logger.info("Email sent");
        res.status(200).json({ message: 'Verification email sent' })
    } catch (err) {
        logger.error(err.response.data);
        res.status(500).json({ message: 'Email was not send' })
    }
})

////////////////////////////////////////////////// Logout

app.get('/logout', (req, res) => {
    logger.info('Logging user out');
    if (req.session) {
        req.session.destroy(err => {
            if (err) {
                res.status(400).json({ message: 'Unable to log out' });
            } else {
                res.status(200).json({ message: 'Logout successful' });
            }
        });
    } else {
        res.end()
    }
})

////////////////////////////////////////////////// Authenticated Routes

const validateToken = (token) => {
    const decodedToken = decodeToken(token);
    const parsedAccessToken = JSON.parse(decodedToken);
    const now = Date.now() / 1000;
    if (now < parsedAccessToken.exp) {
        // Token is still valid, proceed with using it
        return true;
    } else {
        // Token has expired, handle accordingly (e.g., request a new token)
        return false;
    }
}

const verifyTokenForAllRoutes = async (req, res, next) => {
    console.log(req.body);
    // Get the token, decode it and compare exp time with current time
    const accessToken = req.session.accessToken; // Assuming the token is passed in the Authorization header
    const refreshToken = req.session.refreshToken; // Assuming the token is passed in the Authorization header

    if (!accessToken) {
        logger.error('accessToken Not Found!');
        return res.status(401).json({ error: 'Unauthenticated!' });
    }

    if (validateToken(accessToken)) {
        logger.info('accessToken Valid!');
        next();
    } else {
        logger.error('Access token is invalid');
        logger.info('Trying to refresh accessToken...');
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

            req.session.accessToken = response.data.access_token;
            req.session.idToken = response.data.id_token;
            req.session.refreshToken = response.data.refresh_token;
            logger.info('accessToken refreshed!');
            next()
        } catch (err) {
            logger.error('Failed to refresh accessToken');
            res.status(400).json({ message: err.response.data.error_description })
        }
    }
}

// Apply the middleware to all routes
app.use(verifyTokenForAllRoutes);

app.get('/todos', (req, res) => {
    // Check if access token exists in the session
    logger.info('IM PROTECTED!');
    res.status(200).json({ message: 'Authenticated!', body: [{ id: 1, title: 'first' }] });
});

app.post('/job', async (req, res) => {
    const job = req.body;

    const data = {
        db: 'portfolio-website-saved-jobs',
        document: job
    }

    const config = {
        method: "POST",
        url: 'https://cloudant-post-document.1cm56t43oohi.us-south.codeengine.appdomain.cloud',
        data
    };

    try {
        await axios(config);
        res.status(200).json({ message: 'All Saved jobs fetched', body: job });
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: err });

    }
});

app.post('/jobs', async (req, res) => {
    const { username } = req.body;

    const data = {
        db: 'portfolio-website-saved-jobs',
        options: {
            selector: {
                username: {
                    $eq: username
                }
            },
            fields: ['_id', 'name', '_rev', 'description', 'title', 'id', 'by', 'time', 'url', 'username']
        }
    };

    const config = {
        method: "POST",
        url: 'https://cloudant-get-find.1cm56t43oohi.us-south.codeengine.appdomain.cloud',
        data
    };
    try {
        const jobs = await axios(config);
        res.status(200).json({ message: 'All Saved jobs fetched', body: jobs.data.docs });
    } catch (err) {
        res.status(500).json({ message: err });

    }
});

// Start server
const HTTP_PORT = PORT || 8080

// Run HTTP server
http.createServer(app).listen(HTTP_PORT, () => {
    console.log(`HTTP listening on port ${HTTP_PORT}`)
})