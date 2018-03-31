<?php
//header('Content-Type: text/html');
header("access-control-allow-origin: *");
require_once '../include/DbHandler.php';
require_once '../include/PassHash.php';
require_once '../include/config.php';
require '.././libs/Slim/Slim.php';
 
\Slim\Slim::registerAutoloader();
 
$app = new \Slim\Slim();
 
// User id from db - Global Variable
$user_id = NULL;
 
/**
 * Verifying required params posted or not
 */
function verifyRequiredParams($required_fields) {
    $error = false;
    $error_fields = "";
    $request_params = array();
    $request_params = $_REQUEST;
    // Handling PUT request params
    if ($_SERVER['REQUEST_METHOD'] == 'PUT') {
        $app = \Slim\Slim::getInstance();
        parse_str($app->request()->getBody(), $request_params);
    }
    foreach ($required_fields as $field) {
        if (!isset($request_params[$field]) || strlen(trim($request_params[$field])) <= 0) {
            $error = true;
            $error_fields .= $field . ', ';
        }
    }
 
    if ($error) {
        // Required field(s) are missing or empty
        // echo error json and stop the app
        $response = array();
        $app = \Slim\Slim::getInstance();
        $response["error"] = true;
        $response["message"] = 'Required field(s) ' . substr($error_fields, 0, -2) . ' is missing or empty';
        echoRespnse(400, $response);
        $app->stop();
    }
}
 
/**
 * Validating email address
 */
function validateEmail($email) {
    $app = \Slim\Slim::getInstance();
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $response["error"] = true;
        $response["message"] = 'Email address is not valid';
        echoRespnse(400, $response);
        $app->stop();
    }
}
 
/**
 * Echoing json response to client
 * @param String $status_code Http response code
 * @param Int $response Json response
 */
function echoRespnse($status_code, $response) {
    $app = \Slim\Slim::getInstance();
    // Http response code
    $app->status($status_code);
 
    // setting response content type to json
    $app->contentType('application/json');
 
    echo json_encode($response);
}

/**
 * Adding Middle Layer to authenticate every request
 * Checking if the request has valid api key in the 'Authorization' header
 */
function authenticate(\Slim\Route $route) {
    // Getting request headers
    $headers = apache_request_headers();
    $response = array();
    $app = \Slim\Slim::getInstance();
 
    // Verifying Authorization Header
    if (isset($headers['Authorization'])) {
        $db = new DbHandler();
 
        // get the api key
        $api_key = $headers['Authorization'];
        // validating api key
        if (!$db->isValidApiKey($api_key)) {
            // api key is not present in users table
            $response["error"] = true;
            $response["message"] = "Accès refusé. Clé API non valide.";
            echoRespnse(401, $response);
            $app->stop();
        } else {
            global $user_id;  //ATTENTION ICI  (Cyril)
            // get user primary key id
            $user = $db->getUserId($api_key);
            if ($user != NULL)
                $user_id = $user["utilisateur_id"];
            //pas de gestion du cas on trouve la clé mais pas l'utilisateur_id. 
            //ne devrait pas arriver avec constraint en db
        }
    } else {
        // api key is missing in header
        $response["error"] = true;
        $response["message"] = "Clé API manquante";
        echoRespnse(400, $response);
        $app->stop();
    }
}

/**
 * User Registration
 * url - /register
 * method - POST
 * params - name, email, password
 */
$app->post('/register',function() use ($app) {
            // check for required params
            verifyRequiredParams(array('pseudo', 'email', 'password'));
 
            $response = array();
            

            // reading post params
            $pseudo = $app->request->post('pseudo');
            $email = $app->request->post('email');
            $password = $app->request->post('password');
            $nom = $app->request->post('nom');
            $prenom = $app->request->post('prenom');

            // validating email address
            validateEmail($email);
            
            $db = new DbHandler();

            $res = $db->createUser($pseudo, $email, $password, $nom, $prenom);

            if ($res == USER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "Inscription réussie";
                echoRespnse(201, $response);
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oups! Une erreur a eu lieu pendant l'inscription";
                echoRespnse(200, $response);
            } else if ($res == USER_EMAIL_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Désolé, cet email est déjà utilisé.";
                echoRespnse(200, $response);
            } else if ($res == USER_PSEUDO_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Désolé, ce pseudo est déjà utilisé.";
                echoRespnse(200, $response);
            }
        });
        
/**
 * User Login
 * url - /login
 * method - POST
 * params - email, password
 */
$app->post('/login', function() use ($app) {
            // check for required params
            //mettre la valeur du champ unique en front dans les valeurs d'email ET de pseudo
            verifyRequiredParams(array('email','password','pseudo')); 
 
            // reading post params
            $email = $app->request()->post('email');
            $password = $app->request()->post('password');
            $pseudo = $app->request()->post('pseudo');
            $response = array();
 
            $db = new DbHandler();
            // check for correct email and password
            if ($db->checkLogin($email, $password)) {
                // get the user by email
                $user = $db->getUserByEmail($email);
 
                if ($user != NULL) {
                    $response["error"] = false;
                    $response['utilisateur_pseudo'] = $user['utilisateur_pseudo'];
                    $response['utilisateur_email'] = $user['utilisateur_email'];
                    $response['utilisateur_cleapi'] = $user['utilisateur_cleapi'];
                    $response['utilisateur_datecree'] = $user['utilisateur_datecree'];
                    $response['utilisateur_prenom'] = $user['utilisateur_prenom'];
                    $response['utilisateur_nom'] = $user['utilisateur_nom'];
                } else {
                    // unknown error occurred
                    $response['error'] = true;
                    $response['message'] = "Une erreur est survenue. Veuillez réessayer dans quelques minutes";
                }
            } elseif($db->checkLoginPseudo($pseudo, $password)) {
                // get the user by pseudo (Cyril)
                $user = $db->getUserByPseudo($pseudo);
 
                if ($user != NULL) {
                    $response["error"] = false;
                    $response['utilisateur_pseudo'] = $user['utilisateur_pseudo'];
                    $response['utilisateur_email'] = $user['utilisateur_email'];
                    $response['utilisateur_cleapi'] = $user['utilisateur_cleapi'];
                    $response['utilisateur_datecree'] = $user['utilisateur_datecree'];
                    $response['utilisateur_prenom'] = $user['utilisateur_prenom'];
                    $response['utilisateur_nom'] = $user['utilisateur_nom'];
                } else {
                    // unknown error occurred
                    $response['error'] = true;
                    $response['message'] = "Une erreur est survenue. Veuillez réessayer dans quelques minutes";
                }
            } else {
                // user credentials are wrong
                $response['error'] = true;
                $response['message'] = 'Echec de connexion. Identifiants erronés';
            }
 
            echoRespnse(200, $response);
        });

 /**
 * Creation d'un nouveau marqueur
 * La fonction est plutot dégeu, avec le recul je me dit que j'aurai du faire des catch d'erreur plutot que des if
 * Mais pour ça il aurait fallu connaitre un minimum php ce qui n'était pas mon cas.
 * method POST
 * params - name
 * url - /marqueur
 */
 
     
$app->post('/marqueur', 'authenticate', function() use ($app) {
            //on recupere le user_id global de la methode authenticate
            global $user_id;
            
            // check for required params
            verifyRequiredParams(array('adresse_longitude','adresse_latitude','adresse_ville','adresse_pays','localisation_latitude','localisation_longitude'));
 
            $response = array();

            // reading post params
            //TODO : il y en aura plus après
            //on prend les param pour l'adresse
            $adresse_numero = $app->request->post('adresse_numero');
            $adresse_nom = $app->request->post('adresse_nom');
            $adresse_rue = $app->request->post('adresse_rue');
            $adresse_ville = $app->request->post('adresse_ville');
            $adresse_codepostal = $app->request->post('adresse_codepostal');
            $adresse_pays = $app->request->post('adresse_pays');
            $adresse_complement = $app->request->post('adresse_complement');
            $adresse_latitude = $app->request->post('adresse_latitude');
            $adresse_longitude = $app->request->post('adresse_longitude');
            $adresse_geom = $app->request->post('adresse_geom');
            
            $db = new DbHandler();
            //on crée l'adresse
            $adresse_id = $db->createAddress($adresse_numero,$adresse_nom,$adresse_rue,$adresse_ville,$adresse_codepostal,$adresse_pays,$adresse_complement,$adresse_latitude, $adresse_longitude,$adresse_geom);

            if ($adresse_id == ADDRESS_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oups! Une erreur a eu lieu pendant la création de l'adresse";
                echoRespnse(200, $response);  
            } else {
                //pas d'erreur --> l'adresse a été créée  
                //on prend les param pour la localisation
                $localisation_latitude = $app->request->post('localisation_latitude');
                $localisation_longitude = $app->request->post('localisation_longitude');
                
                //on crée la localisation
                $localisation_id = $db->createLocalisation($adresse_id, $localisation_latitude, $localisation_longitude);
                
                if ($localisation_id == LOCALISATION_CREATE_FAILED) {
                    $response["error"] = true;
                    $response["message"] = "Oups! Une erreur a eu lieu pendant la création de la localisation du marqueur";
                    echoRespnse(200, $response);                
                } else {
                    //pas d'erreur --> la localisation a été crée
                    
                    //on prend les param pour la localisation
                    //user_id est connu grâce au authenticate voir premiere ligne de la méthode
                    $marqueur_comment = $app->request->post('marqueur_comment');
                    
                    //on crée le marqueur
                    $marqueur_id = $db->createMarqueur($localisation_id, $user_id, $marqueur_comment);
                    
                    if ($marqueur_id == MARQUEUR_CREATE_FAILED) {
                        $response["error"] = true;
                        $response["message"] = "Oups! Une erreur a eu lieu pendant la création du marqueur";
                        echoRespnse(200, $response);  
                    } else {
                        //pas d'erreur --> le marqueur a été créé
                        //on prend les param pour la Rose
                        $rose_o= $app->request->post('rose_o');
                        $rose_t= $app->request->post('rose_t');
                        $rose_v= $app->request->post('rose_v');
                        $rose_a= $app->request->post('rose_a');        
                        
                        //on crée la rose
                        $res = $db->createRose($marqueur_id, $rose_o, $rose_t, $rose_v, $rose_a);
                        
                        if ($res == ROSE_CREATE_FAILED) {
                            $response["error"] = true;
                            $response["message"] = "Oups! Une erreur a eu lieu pendant la création de la Rose";
                            echoRespnse(200, $response);
                        } else {
                            //on crée la rose
                            $response["error"] = false;
                            $response["marqueur_id"] = $marqueur_id;
                            $response["message"] = "Le marqueur a bien été créé. Reste à ajouter notes et photo"; //mettre test id
                            echoRespnse(201, $response);
                        }
                    }
                }
            }    
        });  

/**
 * Liste de tous les marqueurs en base
 * method GET
 * url /marqueur/all          
 */   

$app->get('/marqueur/all', 'authenticate', function() {
            //on recupere le user_id global de la methode authenticate
            global $user_id;
            $response = array();
            $db = new DbHandler();
 
            // fetching all user marqueurs
            $result = $db->getAllMarqueur();
 
            $response["error"] = false;
            $response["marqueurs"] = array();
 
            // looping through result and preparing marqueurs array
            while ($marqueur = $result->fetch_assoc()) {
                $tmp = array();
                $tmp["marqueur_id"] = $marqueur["marqueur_id"];
                $tmp["localisation_id"] = $marqueur["localisation_id"];
                $tmp["utilisateur_id"] = $marqueur["utilisateur_id"];
                $tmp["marqueur_date"] = $marqueur["marqueur_date"];
                $tmp["marqueur_comment"] = $marqueur["marqueur_comment"];
                $tmp["localisation_latitude"] = $marqueur["localisation_latitude"];
                $tmp["localisation_longitude"] = $marqueur["localisation_longitude"];
                $tmp["adresse_id"] = $marqueur["adresse_id"];
                $tmp["adresse_numero"] = $marqueur["adresse_numero"];
                $tmp["adresse_nom"] = $marqueur["adresse_nom"];
                $tmp["adresse_rue"] = $marqueur["adresse_rue"];
                $tmp["adresse_ville"] = $marqueur["adresse_ville"];
                $tmp["adresse_codepostal"] = $marqueur["adresse_codepostal"];
                $tmp["adresse_pays"] = $marqueur["adresse_pays"];
                $tmp["adresse_complement"] = $marqueur["adresse_complement"];
                $tmp["adresse_latitude"] = $marqueur["adresse_latitude"];
                $tmp["adresse_longitude"] = $marqueur["adresse_longitude"];
                $tmp["adresse_geom"] = $marqueur["adresse_geom"];
                $tmp["rose_id"] = $marqueur["rose_id"];
                $tmp["rose_o"] = $marqueur["rose_o"];
                $tmp["rose_t"] = $marqueur["rose_t"];
                $tmp["rose_v"] = $marqueur["rose_v"];
                $tmp["rose_a"] = $marqueur["rose_a"];
                $tmp["photo_id"] = $marqueur["photo_id"];
                $tmp["photo_chemin"] = $marqueur["photo_chemin"];
                array_push($response["marqueurs"], $tmp);
            }
 
            echoRespnse(200, $response);
        });         
        
/**
 * Liste de tous les marqueurs de l'utilisateur
 * method GET
 * url /marqueur          
 */   

$app->get('/marqueur', 'authenticate', function() {
            //on recupere le user_id global de la methode authenticate
            global $user_id;
            $response = array();
            $db = new DbHandler();
 
            // fetching all user marqueurs
            $result = $db->getAllUsrMarqueur($user_id);
 
            $response["error"] = false;
            $response["marqueurs"] = array();
 
            // looping through result and preparing marqueurs array
            while ($marqueur = $result->fetch_assoc()) {
                $tmp = array();
                $tmp["marqueur_id"] = $marqueur["marqueur_id"];
                $tmp["localisation_id"] = $marqueur["localisation_id"];
                $tmp["utilisateur_id"] = $marqueur["utilisateur_id"];
                $tmp["marqueur_date"] = $marqueur["marqueur_date"];
                $tmp["marqueur_comment"] = $marqueur["marqueur_comment"];
                $tmp["localisation_latitude"] = $marqueur["localisation_latitude"];
                $tmp["localisation_longitude"] = $marqueur["localisation_longitude"];
                $tmp["adresse_id"] = $marqueur["adresse_id"];
                $tmp["adresse_numero"] = $marqueur["adresse_numero"];
                $tmp["adresse_nom"] = $marqueur["adresse_nom"];
                $tmp["adresse_rue"] = $marqueur["adresse_rue"];
                $tmp["adresse_ville"] = $marqueur["adresse_ville"];
                $tmp["adresse_codepostal"] = $marqueur["adresse_codepostal"];
                $tmp["adresse_pays"] = $marqueur["adresse_pays"];
                $tmp["adresse_complement"] = $marqueur["adresse_complement"];
                $tmp["adresse_latitude"] = $marqueur["adresse_latitude"];
                $tmp["adresse_longitude"] = $marqueur["adresse_longitude"];
                $tmp["adresse_geom"] = $marqueur["adresse_geom"];
                $tmp["rose_id"] = $marqueur["rose_id"];
                $tmp["rose_o"] = $marqueur["rose_o"];
                $tmp["rose_t"] = $marqueur["rose_t"];
                $tmp["rose_v"] = $marqueur["rose_v"];
                $tmp["rose_a"] = $marqueur["rose_a"];
                $tmp["photo_id"] = $marqueur["photo_id"];
                $tmp["photo_chemin"] = $marqueur["photo_chemin"];
                array_push($response["marqueurs"], $tmp);
            }
 
            echoRespnse(200, $response);
        });        
 
/**
 * Fetch d'un marqueur de l'utilisateur avec un id donné
 * method GET
 * url /tasks/:id
 * Retourne 404 si le marqueur n'appartient pas à l'utilisateur
 */
$app->get('/marqueur/:id', 'authenticate', function($marqueur_id) {
            global $user_id;
            $response = array();
            $db = new DbHandler();
 
            // fetch du marqueur
            $result = $db->getMarqueur($user_id, $marqueur_id);
 
            if ($result != NULL) {
                $response["error"] = false;
                $response["marqueur_id"] = $result["marqueur_id"];
                $response["localisation_id"] = $result["localisation_id"];
                $response["utilisateur_id"] = $result["utilisateur_id"];
                $response["marqueur_date"] = $result["marqueur_date"];
                $response["marqueur_comment"] = $result["marqueur_comment"];
                $response["localisation_latitude"] = $result["localisation_latitude"];
                $response["localisation_longitude"] = $result["localisation_longitude"];
                $response["adresse_id"] = $result["adresse_id"];
                $response["adresse_numero"] = $result["adresse_numero"];
                $response["adresse_nom"] = $result["adresse_nom"];
                $response["adresse_rue"] = $result["adresse_rue"];
                $response["adresse_ville"] = $result["adresse_ville"];
                $response["adresse_codepostal"] = $result["adresse_codepostal"];
                $response["adresse_pays"] = $result["adresse_pays"];
                $response["adresse_complement"] = $result["adresse_complement"];
                $response["adresse_latitude"] = $result["adresse_latitude"];
                $response["adresse_longitude"] = $result["adresse_longitude"];
                $response["adresse_geom"] = $result["adresse_geom"];
                $response["rose_id"] = $result["rose_id"];
                $response["rose_o"] = $result["rose_o"];
                $response["rose_t"] = $result["rose_t"];
                $response["rose_v"] = $result["rose_v"];
                $response["rose_a"] = $result["rose_a"];
                $response["photo_id"] = $result["photo_id"];
                $response["photo_chemin"] = $result["photo_chemin"];
                echoRespnse(200, $response);
            } else {
                $response["error"] = true;
                $response["message"] = "The requested resource doesn't exists";
                echoRespnse(404, $response);
            }
        });        
/**
 * Creation d'une nouvelle note
 * method POST
 * params - name
 * url - /marqueur/
 */        
$app->post('/note','authenticate', function() use ($app) {
            //WARNING : on devrait vérifier que le marqueur appartient bien au user qui fait le post de note
            // check for required params
            verifyRequiredParams(array('marqueur_id', 'mot_libelle', 'note_value'));
 
            $response = array();
            

            // reading post params
            $marqueur_id = $app->request->post('marqueur_id');
            $libelle = $app->request->post('mot_libelle');
            $note_value = $app->request->post('note_value');
            
            $db = new DbHandler();

            $mot_id = $db->getMotIdByLib($libelle);
            
            if ($mot_id == NULL){
                $response["error"] = true;
                $response["message"] = "Oups! Le mot à noter n'existe pas";
                echoRespnse(200, $response); 
            } else{
                $res = $db->createNote($marqueur_id, $mot_id, $note_value);
                if ($res == NOTE_SUCCESSFULLY_CREATED) {
                    $response["error"] = false;
                    $response["message"] = "Note créée avec succès";
                    echoRespnse(201, $response);
                } else {
                    $response["error"] = true;
                    $response["message"] = "Oups! Une erreur a eu lieu pendant la création de la note";
                    echoRespnse(200, $response);
                }
            }
        });

/**
 * Fetch des notes d'un marqueur de l'utilisateur avec un id donné
 * method GET
 * url /note/:id
 * Retourne liste vide si le marqueur n'appartient pas
 */        
$app->get('/note/:id', 'authenticate', function($marqueur_id) {
            global $user_id;
            $response = array();
            $db = new DbHandler();
 
            // fetch du marqueur
            $result = $db->getNoteSu($marqueur_id);
            
            $response["error"] = false;
            $response["notes"] = array();
 
            // looping through result and preparing tasks array
            while ($note = $result->fetch_assoc()) {
                $tmp = array();
                $tmp["marqueur_id"] = $note["marqueur_id"];  //for checking purpose
                // $tmp["localisation_id"] = $note["localisation_id"];
                $tmp["utilisateur_id"] = $note["utilisateur_id"]; //for checking purpose
                $tmp["marqueur_date"] = $note["marqueur_date"]; //for checking purpose
                //$tmp["marqueur_comment"] = $note["marqueur_comment"];
                $tmp["mot_id"] = $note["mot_id"];
                $tmp["mot_libelle"] = $note["mot_libelle"];
                $tmp["mot_actif"] = $note["mot_actif"];
                $tmp["note_id"] = $note["note_value"];
                $tmp["note_value"] = $note["note_value"];
                array_push($response["notes"], $tmp);
            }
 
            echoRespnse(200, $response);
        });                
        
/**
 * Upload d'une nouvelle image.
 * Partie difficile
 * method POST
 * params - name
 * url - /marqueur/
 */ 
$app->post('/photo', 'authenticate', function() use ($app) {
    verifyRequiredParams(array('marqueur_id'));
    //reading post params
    $marqueur_id = $app->request->post('marqueur_id');
    
    if (!isset($_FILES['upload'])) {
        $response["error"] = true;
        $response["message"] = "Oups! Une erreur a eu lieu pendant l'upload de fichier";
        echoRespnse(400, $response);
    } else {
        $file = $_FILES['upload'];
        if ($file['error']=== 0) {
            //TODO : mettre un switchcase sur le MIME type pour avoir .png/.jpeg/etc à la fin plutot que rien
            $name = uniqid('img-'.date('Ymd').'-');
            if (move_uploaded_file($file['tmp_name'], 'uploads/' . $name) === true) {
                //reecrire
                $chemin = '/uploads/' . $name;
                $db = new DbHandler();
                $res = $db->createPhoto($marqueur_id, $chemin);
                if ($res == PHOTO_SUCCESSFULLY_CREATED) {
                    $response["error"] = false;
                    $response["path"] = $chemin;
                    $response["message"] = "Le fichier a bien été uploadé";
                    echoRespnse(201, $response);
                } else {
                    $response["error"] = true;
                    $response["message"] = "Oups! Une erreur a eu lieu pendant l'enregistrement de la photo en base";
                    echoRespnse(200, $response);
                }
                
            }
        } else {
            $response["error"] = true;
            $response["message"] = "Oups! Une erreur a eu lieu pendant l'enregistrement du fichier";
            echoRespnse(400, $response);
        }
    }
});

/**
 * Liste de tous les mots disponibles, avec leur ID
 * method GET
 * url /mots          
 */   

$app->get('/mots', 'authenticate', function() {
            //on recupere le user_id global de la methode authenticate
            global $user_id;
            $response = array();
            $db = new DbHandler();
 
            // fetching all user marqueurs
            $result = $db->getMots();
 
            $response["error"] = false;
            $response["mots"] = array();
 
            // looping through result and preparing mots array
            while ($mot = $result->fetch_assoc()) {
                $tmp = array();
                $tmp["mot_id"] = $mot["mot_id"];
                $tmp["mot_libelle"] = $mot["mot_libelle"];
                array_push($response["mots"], $tmp);
            }
 
            echoRespnse(200, $response);
        });

        
$app->run();

?>