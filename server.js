const express = require('express');
const app = express();

const json2html = require('json-to-html');

const {Datastore} = require('@google-cloud/datastore');

const bodyParser = require('body-parser');
const request = require('request');

const datastore = new Datastore();

const jwt = require('express-jwt');
const jwksRsa = require('jwks-rsa');

const BOAT = "Boat";

const router = express.Router();
const login = express.Router();

const CLIENT_ID = 'yeh7BIE4f1NswASHSlesTaH3DljuOerY';
const CLIENT_SECRET = 'CY86-Crs9yn_uGzeS-jrrLJIsYAptFpslV7oWoOD-xkEcL8Ja8MgYbKHJIdaY8NT';
const DOMAIN = 'dev-1oqfmwvdsaovxclo.us.auth0.com';

const { auth } = require('express-openid-connect');
const { requiresAuth } = require('express-openid-connect');


const config = {
  authRequired: false,
  auth0Logout: true,
  baseURL: 'http://localhost:3000',
  clientID: `${CLIENT_ID}`,
  issuerBaseURL: `https://${DOMAIN}`,
  secret: `${CLIENT_SECRET}`,
};

// auth router attaches /login, /logout, and /callback routes to the baseURL
app.use(auth(config));


app.get('/', (req, res) => {
    if (req.oidc.isAuthenticated()) {
      // User is logged in, send the JWT Token
      res.send(`
        <h1>Logged in</h1>
        <p>Your JWT Token:</p>
        <p>${req.oidc.idToken}</p>
      `);
    } else {
      // User is no longer logged in, show the logged-out message
      res.send('<h1>Logged out</h1><p><a href="/login">Log in</a></p>');
    }
  });

app.use(bodyParser.json());

function fromDatastore(item){
    item.id = item[Datastore.KEY].id;
    return item;
}
  
const checkJwt = jwt({
    secret: jwksRsa.expressJwtSecret({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
      jwksUri: `https://${DOMAIN}/.well-known/jwks.json`
    }),
  
    // Validate the audience and the issuer.
    issuer: `https://${DOMAIN}/`,
    algorithms: ['RS256']
  });

const optionalAuth = (req, res, next) => {
    if (req.headers.authorization) {
        return checkJwt(req, res, next);
    } else {
        next();
    }
};

/* ------------- Begin Boat Model Functions ------------- */

//  Post new boat with attributes
function post_boat(name, type, length, owner, public){
    var key = datastore.key(BOAT);
	const new_boat = {
        "name": name, 
        "type": type, 
        "length": length, 
        "owner":owner,
        "public": public
    };
	return datastore.save({"key":key, "data":new_boat}).then(() => {return key});
}

//  Get boats of an owner && Get all boats that are public
function get_boats(owner){
	const q = datastore.createQuery(BOAT);
	return datastore.runQuery(q).then( (entities) => {
			return entities[0].map(fromDatastore).filter( item => item.owner === owner );
		});
}
function get_boats_unprotected(){
    const q = datastore.createQuery(BOAT);
    return datastore.runQuery(q).then( (entities) => {
            // Filter to return only public boats
            return entities[0].map(fromDatastore).filter(item => item.public === true);
    });
}

// Get public boats of a particular owner
function get_public_boats_for_owner(owner_id) {
    const q = datastore.createQuery(BOAT).filter('owner', '=', owner_id).filter('public', '=', true);
    return datastore.runQuery(q).then((entities) => {
        return entities[0].map(fromDatastore);
    });
}

// Delete a boat with valid JWT & owner
function delete_boat(boat_id, owner) {
    const key = datastore.key([BOAT, parseInt(boat_id, 10)]);
    return datastore.get(key)
        .then(([boat]) => {
            if (!boat) {
                return 'Not Found'; // If boat with ID is not valid
            } 
            else if (boat.owner !== owner) {
                return 'Forbidden'; // If boat owner does not match with JWT
            } else {
                return datastore.delete(key).then(() => 'Deleted'); // Proceed to delete
            }
        });
}

/* ------------- End Model Functions ------------- */

/* ------------- Begin Controller Functions ------------- */


router.get('/', optionalAuth, (req, res) => {
    // Check if req.user exists and has a sub property
    if (req.user && req.user.sub) {
        // JWT is valid, get boats for the specific owner
        get_boats(req.user.sub)
        .then(boats => {
            res.status(200).json(boats);
        })
    } else {
        // No JWT or JWT is invalid, get all boats
        get_boats_unprotected()
        .then(boats => {
            res.status(200).json(boats);
        })
    }
});


router.get('/owners/:owner_id/boats', function(req, res){
    get_public_boats_for_owner(req.params.owner_id)
    .then(boats => {
        res.status(200).json(boats);
    });
});


router.delete('/:boat_id', checkJwt, function(req, res){
    if(!req.user || !req.user.sub){
        return res.status(401).send('Unauthorized');    // If JWT missing/invalid, send 401
    }
    delete_boat(req.params.id, req.user.sub)
    .then(result => {
        if(result === 'Forbidden'){ // Boat does not belong to owner
            res.status(403).send('Forbidden');  
        } else if(result === 'Not Found'){  // Boat with boat_id not found
            res.status(403).send('Not Found');  
        } else if(result === 'Deleted'){        //Proceed to delete
            res.status(204).send();
        }
    });
});


router.post('/', checkJwt, function(req, res){
    if(!req.user || !req.user.sub){
        return res.status(401).send('Unauthorized');    // Send 401 if JWT invalid/missing
    }
    if(req.get('content-type') !== 'application/json'){
        res.status(415).send('Server only accepts application/json data.')
    }

    const { name, type, length, public } = req.body;
    const owner = req.user.sub;

    // Create the boat
    post_boat(name, type, length, owner, public)    // Call function to create boat
    .then(key => {
        // Set the location header
        res.location(`${req.protocol}://${req.get('host')}/boats/${key.id}`);
        res.status(201).send({ id: key.id });   // Send 201 status 
})
    
});

//  Login for auth0
login.post('/', function(req, res){
    const username = req.body.username;
    const password = req.body.password;
    var options = { method: 'POST',
            url: `https://${DOMAIN}/oauth/token`,
            headers: { 'content-type': 'application/json' },
            body:
             { grant_type: 'password',
               username: username,
               password: password,
               client_id: CLIENT_ID,
               client_secret: CLIENT_SECRET },
            json: true };
    request(options, (error, response, body) => {
        if (error){
            res.status(500).send(error);
        } else {
            res.send(body);
        }
    });

});


/* ------------- End Controller Functions ------------- */

app.use('/boats', router);
app.use('/login', login);

// Listen to the App Engine-specified port, or 8080 otherwise
const PORT = process.env.PORT || 3000; 
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}...`);
});