const express = require('express');
const app = express();

const json2html = require('json-to-html');

const {Datastore} = require('@google-cloud/datastore');

const bodyParser = require('body-parser');
const request = require('request');

const datastore = new Datastore();

const jwt = require('express-jwt');
const jwksRsa = require('jwks-rsa');

const GAME = "Game";
const GENRE = "Genre";

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
  baseURL: 'https://final-alejanjo.uw.r.appspot.com',
  clientID: `${CLIENT_ID}`,
  issuerBaseURL: `https://${DOMAIN}`,
  secret: `${CLIENT_SECRET}`,
};

// auth router attaches /login, /logout, and /callback routes to the baseURL
app.use(auth(config));

app.get('/users', (req, res) => {
    get_all_users()
        .then(users => {
            res.status(200).json(users);
        })
});

app.get('/', (req, res) => {
    if (req.oidc.isAuthenticated()) {
      // User is logged in, send the JWT Token
      res.send(`
        <h1>Logged in</h1>
        <p>Your unique User ID:</p>
        <p>${req.oidc.user.sub}</p>
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

/* ------------- Begin Game & Genre Functions ------------- */

//  POST FUNCTIONS //
function post_game(name, developer, length_time, owner, req) {
    // Return error if missing attributes
    if (!name || !developer || !length_time) {
        const error = new Error('Missing attributes');
        error.status = 400;
        return Promise.reject(error);
    }
    // Set entity with properties
    var key = datastore.key(GAME);
    const new_game = {
        "name": name,
        "developer": developer,
        "length_time": length_time,
        "assigned_genre": null,
        "owner": owner,
        "self": `${req.protocol}://${req.get('host')}${req.baseUrl}/games/${key.id}`
    };
    return datastore.save({ "key": key, "data": new_game }).then(() => {
        return { ...new_game, id: key.id };
    });
}

function post_genre(name, sub_genre, description, req) {
    // Return error if missing attributes
    if (!name || !sub_genre || !description ) {
        const error = new Error('Missing attributes')
        error.status = 400;
        return Promise.reject(error);
    }
    // Set entity with properties
    var key = datastore.key(GENRE);
    const new_genre = {
        "name": name,
        "sub_genre": sub_genre,
        "description": description,
        "self": `${req.protocol}://${req.get('host')}${req.baseUrl}/games/${key.id}`
    };
    return datastore.save({ "key": key, "data": new_genre }).then(() => {
        return { ...new_genre, id: key.id };
    });s
}

// UPDATE FUNCTIONS (PUT & PATCH) //
function put_game(id, name, developer, length_time) {
    // Return error if not all properties are changed
    if (!name || !developer || !length_time) {
        const error = new Error('Missing attributes');
        error.status = 400;
        return Promise.reject(error);
    }

    const key = datastore.key([GAME, parseInt(id, 10)]);

    return datastore.get(key)
        .then(([existingGameData]) => {
            if (!existingGameData) {
                const error = new Error('Not Found');
                error.status = 404;
                return Promise.reject(error);   // Return error if not found
            }
            // Update with new properties
            const updatedGame = {
                ...existingGameData,
                "name": name,
                "developer": developer,
                "length_time": length_time
            };
            return datastore.save({ "key": key, "data": updatedGame });
        });
}

function put_genre(id, name, sub_genre, description) {
    // Return error if not all properties are changed
    if (!name || !sub_genre || !description) {
        const error = new Error('Missing attributes');
        error.status = 400;
        return Promise.reject(error);
    }

    const key = datastore.key([GENRE, parseInt(id, 10)]);

    return datastore.get(key)
        .then(([existingGenreData]) => {
            if (!existingGenreData) {
                const error = new Error('Not Found');
                error.status = 404;
                return Promise.reject(error);   // Return error if not found
            }
            // Update with new properties
            const updatedGenre = {
                ...existingGenreData,
                "name": name,
                "sub_genre": sub_genre,
                "description": description
            };
            return datastore.save({ "key": key, "data": updatedGenre });
        });
}

function patch_game(id, updatedData) {
    const key = datastore.key([GAME, parseInt(id, 10)]);

    return datastore.get(key)
        .then(([game]) => {
            if (!game) {
                const error = new Error('Game not found');
                error.status = 404;
                return Promise.reject(error);   // Return error if not found
            }

            // Merge existing data with the new data
            const updated_game = { ...game, ...updatedData };
            return datastore.save({ "key": key, "data": updated_game });
        });
}

function patch_genre(id, updatedData) {
    const key = datastore.key([GENRE, parseInt(id, 10)]);

    return datastore.get(key)
        .then(([genre]) => {
            if (!genre) {
                const error = new Error('Genre not found');
                error.status = 404;
                return Promise.reject(error);   // Return error if not found
            }

            // Merge existing data with new data
            const updated_genre = { ...genre, ...updatedData };
            return datastore.save({ "key": key, "data": updated_genre });
        });
}


//  GET FUNCTIONS //
function get_games(owner){
	const q = datastore.createQuery(GAME);
	return datastore.runQuery(q).then( (entities) => {
            // Filter for entities by the given owner token
			return entities[0].map(fromDatastore).filter( item => item.owner === owner );
		});
}

function get_games_unprotected(){
    const q = datastore.createQuery(GAME);
    return datastore.runQuery(q).then( (entities) => {
            // Filter to return only public games
            return entities[0].map(fromDatastore).filter(item => item.public === true);
    });
}

function get_genres() {
    const q = datastore.createQuery(GENRE);
    return datastore.runQuery(q).then((entities) => {
        return entities[0].map(fromDatastore);
    });
}


// DELETE FUNCTIONS
function delete_game(game_id) {
    const key = datastore.key([GAME, parseInt(game_id, 10)]);
    return datastore.get(key)
        .then(([game]) => {
            if (!game) {
                const error = new Error('Not Found');
                error.status = 404;
                return Promise.reject(error);   // Return 404 if not found
            } 
             else {
                return datastore.delete(key).then(() => 'Deleted');
            }
        });
}

function delete_genre(genre_id) {
    const key = datastore.key([GENRE, parseInt(genre_id, 10)]);
    return datastore.get(key)
        .then(([genre]) => {
            if (!genre) {
                return 'Not Found'; // If genre with ID is not valid
            } else {
                return datastore.delete(key).then(() => 'Deleted'); // Proceed to delete
            }
        });
}

// ASSIGN/REMOVE FUNCTIONS //
function assign_game(game_id, genre_id) {
    const gameKey = datastore.key([GAME, parseInt(game_id, 10)]);
    return datastore.get(gameKey).then(gameData => {
        if (!gameData[0]) {
            const error = new Error("Game not found");
            error.status = 404;
            return Promise.reject(error); // Return error if game not found
        }
        const game = fromDatastore(gameData[0]);
        game.assigned_genre = genre_id; // Assign the given genre ID to the property within the game

        return datastore.save({ "key": gameKey, "data": game });
    });
}


function remove_genre_from_game(game_id) {
    const gameKey = datastore.key([GAME, parseInt(game_id, 10)]);
    return datastore.get(gameKey).then(gameData => {
        if (!gameData[0]) {
            const error = new Error("Game not found");
            error.status = 404;
            return Promise.reject(error);   // Return error if game not found
        }
        const game = fromDatastore(gameData[0]);
        game.assigned_genre = null; // Remove the relationship and make it null again

        return datastore.save({ "key": gameKey, "data": game });
    });
}

function get_all_users() {
    const query = datastore.createQuery(GAME);
    return datastore.runQuery(query).then(([games]) => {
        // Get owner IDs from games and depulicate
        const ownerIds = games.map(game => game.owner).filter((value, index, self) => self.indexOf(value) === index);
        return ownerIds.map(owner => {
            return { userId: owner }; // Return userID
        });
    });
}



/* ------------- End Model Functions ------------- */

/* ------------- Begin Controller Functions ------------- */

// POST ROUTERS //
router.post('/games', checkJwt, function(req, res){
    // Error Check
    if(!req.user || !req.user.sub){
        return res.status(401).send('Error: Unauthorized');    // Send 401 if JWT invalid/missing
    }
    if (!req.accepts('application/json')) {
        return res.status(406).send('Error: Server only sends application/json data'); // Send 406 if accepts is not JSON
    }

    // Use post function passing in parameters
    post_game(req.body.name, req.body.developer, req.body.length_time, req.user.sub, req)
        .then(key => {
            const responseBody = {
                "id": key.id,
                "name": req.body.name,
                "developer": req.body.developer,
                "length_time": req.body.length_time,
                "owner": req.user.sub,
                "self": req.protocol + '://' + req.get('host') + req.baseUrl + '/games/' + key.id
            }
            res.status(201).json(responseBody);
        })
        .catch(error => {
            if (error.status === 400) {
                res.status(400).json({ 'Error': 'The request object is missing at least one of the required attributes' });
            } 
        });
});

router.post('/genres', checkJwt, function(req,res){
    // Error Check
    if(!req.user || !req.user.sub){
        return res.status(401).send('Error: Unauthorized');    // Send 401 if JWT invalid/missing
    }
    if (!req.accepts('application/json')) {
        return res.status(406).send('Error: Server only sends application/json data'); // Send 406 if accepts is not JSON
    }

    // Use post function passing in parameters
    post_genre(req.body.name, req.body.sub_genre, req.body.description, req)
        .then(key => {
            const responseBody = { 
                "id": key.id, 
                "name": req.body.name, 
                "sub_genre": req.body.sub_genre,
                "description": req.body.description,
                "self": req.protocol + '://' + req.get('host') + req.baseUrl + '/genres/' + key.id
            };
            res.status(201).json(responseBody); 
        })
        .catch(error => {
            if (error.status === 400) {
                res.status(400).json({ 'Error': 'The request object is missing at least one of the required attributes' });
            } 
        });
})

// PUTS AND PATCHES ROUTERS //
router.put('/games/:game_id', checkJwt, (req, res) => {
    // Error Check
    if(!req.user || !req.user.sub){
        return res.status(401).send('Error: Unauthorized');    // Send 401 if JWT invalid/missing
    }
    if (!req.accepts('application/json')) {
        return res.status(406).send('Error: Server only sends application/json data'); // Send 406 if accepts is not JSON
    }

    const { name, developer, length_time } = req.body;
    const gameId = req.params.game_id;

    // Use put function passing in parameters
    put_game(gameId, name, developer, length_time)
        .then(() => {
            res.status(200).json({ message: 'Game updated successfully' });
        })
        .catch(error => {
            res.status(error.status).json({ error: error.message });
        });
});

router.put('/genres/:genre_id', checkJwt, (req, res) => {
    // Error Check
    if(!req.user || !req.user.sub){
        return res.status(401).send('Error: Unauthorized');    // Send 401 if JWT invalid/missing
    }
    if (!req.accepts('application/json')) {
        return res.status(406).send('Error: Server only sends application/json data'); // Send 406 if accepts is not JSON
    }

    const { name, sub_genre, description } = req.body;
    const genreId = req.params.genre_id;

    // Use put function passing in parameters
    put_genre(genreId, name, sub_genre, description)
        .then(() => {
            res.status(200).json({ message: 'Genre updated successfully' }); 
        })
        .catch(error => {
            res.status(error.status).json({ error: error.message });
        });
});

router.patch('/games/:game_id', checkJwt, (req, res) => {
    // Error Check
    if(req.method !== "PATCH") {
        return res.status(405).send("Error: Invalid method");  // Send 405 if invalid method
    }
    if(!req.user || !req.user.sub){
        return res.status(401).send('Error: Unauthorized');    // Send 401 if JWT invalid/missing
    }
    if(req.get('content-type') !== 'application/json'){
        res.status(406).send('Error: Server only accepts application/json data.') // Send 406 if accepts is not JSON
    }

    const gameId = req.params.game_id;
    const updatedData = req.body; 

    // Use patch function passing in paramters
    patch_game(gameId, updatedData)
        .then(() => {
            res.status(200).json({ message: 'Game updated successfully' }); 
        })
        .catch(error => {
            res.status(error.status).json({ error: error.message }); 
        });
});

router.patch('/genres/:genre_id', checkJwt, (req, res) => {
    // Error Check
    if(req.method !== "PATCH") {
        return res.status(405).send("Error: Invalid method");  // Send 405 if invalid method
    }
    if(!req.user || !req.user.sub){
        return res.status(401).send('Error: Unauthorized');    // Send 401 if JWT invalid/missing
    }
    if(req.get('content-type') !== 'application/json'){
        res.status(406).send('Error: Server only accepts application/json data.') // Send 406 if accepts is not JSON
    }

    const genreId = req.params.genre_id;
    const updatedData = req.body;
    
    // Use patch function passing in paramters
    patch_genre(genreId, updatedData)
        .then(() => {
            res.status(200).json({ message: 'Genre updated successfully' }); 
        })
        .catch(error => {
            res.status(error.status).json({ error: error.message });
        });
});

// GET ROUTERS //
router.get('/games', optionalAuth, (req, res) => {
    // Check if req.user exists and has a sub property
    if (req.user && req.user.sub) {
        // JWT is valid, get games for the specific owner
        get_games(req.user.sub)
        .then(games => {
            res.status(200).json(games);
        })
    } else {
        // No JWT or JWT is invalid, get all games
        get_games_unprotected()
        .then(games => {
            res.status(200).json(games);
        })
    }
});

router.get('/genres', (req, res) => {
    get_genres()
        .then(genres => {
            res.status(200).json(genres);
        })
});

// DELETE ROUTERS //
router.delete('/games/:game_id', checkJwt, function(req, res){
    if(!req.user || !req.user.sub){
        return res.status(401).send('Error: Unauthorized'); // Send 401 is JWT missing/invalid
    }

    delete_game(req.params.game_id, req.user.sub)
    .then(result => {
        if(result === 'Forbidden'){
            res.status(403).send('Error: Forbidden'); // Not owner
        } else if(result === 'Not Found'){
            res.status(404).send('Error: Not Found'); // Not found
        } else if(result === 'Deleted'){
            res.status(204).send(); // Proceed to delete
        }
    }).catch(error => {
        res.status(error.status).send(error.message);
    });
});


router.delete('/genres/:genre_id', checkJwt, function(req, res){
    // Error Check
    if(!req.user || !req.user.sub){
        return res.status(401).send('Unauthorized');    // If JWT missing/invalid, send 401
    }

    delete_genre(req.params.genre_id)
        .then(result => {
            if (result === 'Not Found') {   // Genre with genre_id not found
                res.status(404).json({ 'Error': 'Genre not found' });
            } else if (result === 'Deleted') {  // Proceed to delete
                res.status(204).end();
            }
        })
});

// ASSIGN/REMOVE RELATIONSHIP //
router.put('/games/:game_id/genres/:genre_id', function(req, res) {
    const game_id = req.params.game_id;
    const genre_id = req.params.genre_id;

    // Use assign function passing in game and genre IDs
    assign_game(game_id, genre_id)
        .then(() => {
            res.status(200).json({ message: 'Genre assigned to game successfully' });
        })
        .catch(error => {
            res.status(error.status).json({ error: error.message });
        });
});

router.delete('/games/:game_id/genres', function(req, res) {
    const game_id = req.params.game_id;

    // Use remove function passing in game ID
    remove_genre_from_game(game_id)
        .then(() => {
            res.status(200).json({ message: 'Genre removed from game successfully' });
        })
        .catch(error => {
            res.status(error.status).json({ error: error.message });
        });
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

app.use('/', router);
app.use('/login', login);

// Listen to the App Engine-specified port, or 8080 otherwise
const PORT = process.env.PORT || 3000; 
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}...`);
});