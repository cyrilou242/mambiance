<?php
 
/**
 * Class to handle all db operations
 * This class will have CRUD methods for database tables
 *
 * @author Ravi Tamada
 */
require_once '../include/config.php';

//WARNING : pas de test sur les types car l'API n'est pas sensé être publique
//néanmoins cela devrait être fait pour une vraie appli

class DbHandler {
 
    private $conn;
 
    function __construct() {
        require_once dirname(__FILE__) . '/DbConnect.php';
        // opening db connection
        $db = new DbConnect();
        $this->conn = $db->connect();
    }
 
    /* ------------- `users` table method ------------------ */
 
    /**
     * Creating new user
     * @param String $name User full name
     * @param String $email User login email id
     * @param String $password User login password
     * @param String $nom Nom de l'utilisateur, pas obligatoire
     * * @param String $prenom Prenom de l'utilisateur, pas obligatoire
     */
    // j'ai pas rajouté nom et prenom
    public function createUser($pseudo, $email, $password, $nom, $prenom){//,$nom,$prenom) {
        require_once 'PassHash.php';
        $response = array();
        $mailexists=$this->isUserExists($email);
        $pseudoexists=$this->isUserExistsPseudo($pseudo);
        // First check if user already existed in db
        if ((!$mailexists) && (!$pseudoexists)) {
            // Generating password hash
            $password_hash = PassHash::hash($password);
            // Generating API key
            $api_key = $this->generateApiKey();
            // insert query
            $stmt = $this->conn->prepare("INSERT INTO Utilisateur (utilisateur_pseudo, utilisateur_email, utilisateur_motdepasse, utilisateur_cleapi, utilisateur_statut, utilisateur_nom, utilisateur_prenom) values(?, ?, ?, ?, 1,?,?)");
            $stmt->bind_param("ssssss", $pseudo, $email, $password_hash, $api_key,$nom,$prenom);
            $result = $stmt->execute();
            $stmt->close();
 
            // Check for successful insertion
            if ($result) {
                // User successfully inserted
                return USER_CREATED_SUCCESSFULLY;
            } else {
                // Failed to create user
                return USER_CREATE_FAILED;
            }
        } else if($mailexists) {
            // User with same email already existed in the db
            return USER_EMAIL_ALREADY_EXISTED;
        } else if ($pseudoexists) {
            // User with same pseudo already existed in the db. Cyril
            return USER_PSEUDO_ALREADY_EXISTED;
        }
 
        return $response;
    }
 
    /**
     * Checking user login
     * @param String $email User login email id
     * @param String $password User login password
     * @return boolean User login status success/fail
     */
    public function checkLogin($email, $password) {
        // fetching user by email
        $stmt = $this->conn->prepare("SELECT utilisateur_motdepasse FROM Utilisateur WHERE utilisateur_email = ?");
 
        $stmt->bind_param("s", $email);
 
        $stmt->execute();
 
        $stmt->bind_result($password_hash);
 
        $stmt->store_result();
 
        if ($stmt->num_rows > 0) {
            // Found user with the email
            // Now verify the password
 
            $stmt->fetch();
 
            $stmt->close();
 
            if (PassHash::check_password($password_hash, $password)) {
                // User password is correct
                return TRUE;
            } else {
                // user password is incorrect
                return FALSE;
            }
        } else {
            $stmt->close();
 
            // user not existed with the email
            return FALSE;
        }
    }
    
    /**
     * Checking user login by pseudo
     * @param String $pseudo User login pseudo
     * @param String $password User login password
     * @return boolean User login status success/fail
     */
    public function checkLoginPseudo($pseudo, $password){ //Cyril
        // fetching user by pseudo
        $stmt = $this->conn->prepare("SELECT utilisateur_motdepasse FROM Utilisateur WHERE utilisateur_pseudo = ?");
 
        $stmt->bind_param("s", $pseudo);
 
        $stmt->execute();
 
        $stmt->bind_result($password_hash);
 
        $stmt->store_result();
 
        if ($stmt->num_rows > 0) {
            // Found user with the pseudo
            // Now verify the password
 
            $stmt->fetch();
 
            $stmt->close();
 
            if (PassHash::check_password($password_hash, $password)) {
                // User password is correct
                return TRUE;
            } else {
                // user password is incorrect
                return FALSE;
            }
        } else {
            $stmt->close();
 
            // user not existed with the email
            return FALSE;
        }
    }
 
    /**
     * Checking for duplicate user by pseudo.
     * Par Cyril
     * @param String $email email to check in db
     * @return boolean
     */
    public function isUserExists($email) {
        $stmt = $this->conn->prepare("SELECT utilisateur_id from Utilisateur WHERE utilisateur_email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }
    
    /**
     * Checking for duplicate user by pseudo.
     * Par Cyril
     * @param String $pseudo email to check in db
     * @return boolean
     */
    public function isUserExistsPseudo($pseudo) {
        $stmt = $this->conn->prepare("SELECT utilisateur_id from Utilisateur WHERE utilisateur_pseudo = ?");
        $stmt->bind_param("s", $pseudo);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }
 
    /**
     * Fetching user by email
     * @param String $email User email id
     */
    public function getUserByEmail($email) {
        $stmt = $this->conn->prepare("SELECT utilisateur_pseudo, utilisateur_email, utilisateur_cleapi, utilisateur_statut, utilisateur_datecree, utilisateur_prenom, utilisateur_nom FROM Utilisateur WHERE utilisateur_email = ?");
        $stmt->bind_param("s", $email);
        if ($stmt->execute()) {
            $user = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            return $user;
        } else {
            return NULL;
        }
    }
    
    /**
     * Fetching user by email
     * Par Cyril
     * @param String $pseudo User email id
     */
    public function getUserByPseudo($pseudo) {
        $stmt = $this->conn->prepare("SELECT utilisateur_pseudo, utilisateur_email, utilisateur_cleapi, utilisateur_statut, utilisateur_datecree, utilisateur_prenom, utilisateur_nom FROM Utilisateur WHERE utilisateur_pseudo = ?");
        $stmt->bind_param("s", $pseudo);
        if ($stmt->execute()) {
            $user = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            return $user;
        } else {
            return NULL;
        }
    }
    
 
    /**
     * Fetching user api key
     * @param String $user_id user id primary key in user table
     */
    public function getApiKeyById($user_id) {
        $stmt = $this->conn->prepare("SELECT utilisateur_cleapi FROM Utilisateur WHERE utilisateur_id = ?");
        $stmt->bind_param("i", $user_id);
        if ($stmt->execute()) {
            $api_key = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            return $api_key;
        } else {
            return NULL;
        }
    }
 
    /**
     * Fetching user id by api key
     * @param String $api_key user api key
     */
    public function getUserId($api_key) {
        $stmt = $this->conn->prepare("SELECT utilisateur_id FROM Utilisateur WHERE utilisateur_cleapi = ?");
        $stmt->bind_param("s", $api_key);
        if ($stmt->execute()) {
            $user_id = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            return $user_id;
        } else {
            return NULL;
        }
    }
 
    /**
     * Validating user api key
     * If the api key is there in db, it is a valid key
     * @param String $api_key user api key
     * @return boolean
     */
    public function isValidApiKey($api_key) {
        $stmt = $this->conn->prepare("SELECT utilisateur_id from Utilisateur WHERE utilisateur_cleapi = ?");
        $stmt->bind_param("s", $api_key);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }
 
    /**
     * Generating random Unique MD5 String for user Api key
     */
    private function generateApiKey() {
        return md5(uniqid(rand(), true));
    }
    
    /* ------------- Methode de la table `Adresse`------------------ */
    
     /**
     * Fonction qui renvoie un booléen d'existence d'une adresse
     */ 
    public function isAddressExists($latitude, $longitude) {
        $precision=0.00001;
        $stmt = $this->conn->prepare("SELECT adresse_id from Adresse WHERE (ABS(adresse_latitude - ?)<=?) and (ABS(adresse_longitude - ?)<=?)");
        $stmt->bind_param("dddd", $latitude, $precision, $longitude, $precision);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }
    
    /**
     * TODO
     * Fonction qui renvoie les informations d'une adresse à partir de l'id de l'adresse
     */ 
    public function getAddressIdByPos($latitude, $longitude) {
        //on défini ici la précision sur l'égalité de floats de longitude et latitude
        $precision=0.00001;
        $stmt = $this->conn->prepare("SELECT adresse_id from Adresse WHERE (ABS(adresse_latitude - ?)<=?) and (ABS(adresse_longitude - ?)<=?)");
        $stmt->bind_param("dddd", $latitude, $precision, $longitude, $precision);
        if ($stmt->execute()) {
            $address_id = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            return $address_id;
        } else {
            return NULL;
        }
    }
 
    /**
     * Création d'une nouvelle adresse
     */   
    
    public function createAddress($numero,$nom, $rue, $ville,$codepostal, $pays, $complement, $latitude, $longitude, $geom){
        //WARNING: geom est un string je ne sais pas ce que c'est
        $response = array();
        $addressexists=$this->isAddressExists($latitude,$longitude);
 
        // First check si l'adresse existe déjà dans la base
        if (!$addressexists) {
            // insert query
            $query="INSERT INTO Adresse (adresse_numero, adresse_nom, adresse_rue, adresse_ville, adresse_codepostal, adresse_pays, adresse_complement, adresse_latitude, adresse_longitude, adresse_geom) VALUES (?,?,?,?,?,?,?,?,?,?)";
            $stmt = $this->conn->prepare($query);
            $stmt->bind_param("sssssssdds", $numero, $nom, $rue, $ville, $codepostal, $pays, $complement, $latitude, $longitude, $geom);
            $result = $stmt->execute();
            $lastId = $stmt->insert_id;
            $stmt->close();
            // Check for successful insertion
            if ($result) {
                // User successfully inserted
                return ($lastId);
            } else {
                // Failed to create user
                return ADDRESS_CREATE_FAILED;
            }
        } else{
            // Adresse avec même latitude et longitude existait, on renvoie l'ID
            //a aucun moment on ne fera remonter plus haut que l'on n'a pas créé de nouvelle adresse
            $existingId = $this->getAddressIdByPos($latitude, $longitude);
            return $existingId['adresse_id'];
        } 
        return $response;
    }
    
/* ------------- Methode de la table `Localisation`------------------ */
    /**
     * Creating new Localisation
     */
    public function createLocalisation($adresse_id, $latitude, $longitude) {
        $query="INSERT INTO Localisation (adresse_id, localisation_latitude, localisation_longitude) VALUES(?,?,?)";
        $stmt = $this->conn->prepare($query);
        $stmt->bind_param("idd", $adresse_id, $latitude, $longitude);
        $result = $stmt->execute();
        $lastId = $stmt->insert_id;
        $stmt->close();
 
        if ($result) {
                // Localisation successfully created
                return ($lastId);
            } else {
                // Failed to create loclaisation
                return LOCALISATION_CREATE_FAILED;
            }
        }
        
/* ------------- Methode de la table `Marqueur`------------------ */
    /**
     * Creating new Marqueur
     */
    public function createMarqueur($localisation_id, $user_id, $marqueur_comment) {
        //WARNING: on autorise que 2 marqueurs ait la même personne et la même localisation
        $query="INSERT INTO Marqueur (localisation_id, utilisateur_id, marqueur_comment) VALUES(?,?,?)";
        $stmt = $this->conn->prepare($query);
        $stmt->bind_param("iis", $localisation_id,$user_id,$marqueur_comment);
        $result = $stmt->execute();
        $lastId = $stmt->insert_id;
        $stmt->close();
 
        if ($result) {
                // Marqueur successfully created
                return ($lastId);
            } else {
                // Failed to create Marqueur
                return MARQUEUR_CREATE_FAILED;
            }
        }
    
       
    /**
     * Fetching all marqueurs in table
     * Shouldn't be used for the moment
     * Does NOT fetch notes
     */ 
    public function getAllMarqueur() {
        $request = "SELECT * FROM Marqueur NATURAL JOIN Localisation NATURAL JOIN Adresse NATURAL JOIN Rose NATURAL LEFT JOIN Photo";
        $stmt = $this->conn->prepare($request);
        $stmt->execute();
        $marqueurs = $stmt->get_result();
        $stmt->close();
        return $marqueurs;
    }  
        
    /**
     * Fetching all user Marqueurs
     * @param String $user_id id of the user
     * Does NOT fetch notes
     */
    public function getAllUsrMarqueur($user_id) {
        $request = "SELECT * FROM Marqueur NATURAL JOIN Localisation NATURAL JOIN Adresse NATURAL JOIN Rose NATURAL LEFT JOIN Photo WHERE utilisateur_id=?";
        $stmt = $this->conn->prepare($request);
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $marqueurs = $stmt->get_result();
        $stmt->close();
        return $marqueurs;
    }    
    

    /**
     * Fetching single Marqueur by ID
     * @param String $user_id id of the user
     * Does NOT fetch notes
     * Shouldn't be really usefull
     */    
    public function getMarqueur($user_id, $marqueur_id) {
        $request = "SELECT * FROM Marqueur NATURAL JOIN Localisation NATURAL JOIN Adresse NATURAL JOIN Rose NATURAL LEFT JOIN Photo WHERE utilisateur_id=? and marqueur_id=?";
        $stmt = $this->conn->prepare("$request");
        $stmt->bind_param("ii",$user_id,  $marqueur_id);
        if ($stmt->execute()) {
            $marqueur = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            return $marqueur;
        } else {
            return NULL;
        }
    }
     
/* ------------- Methode de la table `Rose`------------------ */
    /**
     * Creating new Rose
     */
    public function createRose($marqueur_id, $rose_o, $rose_t, $rose_v, $rose_a) {
        //TODO: marqueur_id est unique dans la bdd 
        $query="INSERT INTO Rose (marqueur_id, rose_o, rose_t, rose_v, rose_a) VALUES(?,?,?,?,?)";
        $stmt = $this->conn->prepare($query);
        $stmt->bind_param("idddd", $marqueur_id,$rose_o, $rose_t, $rose_v, $rose_a);
        $result = $stmt->execute();
        $stmt->close();
        if ($result) {
                // Rose successfully created
                return ROSE_SUCCESSFULLY_CREATED;
            } else {
                // Failed to create Rose
                return ROSE_CREATE_FAILED;
            }
        }
    
/* ------------- Methode de la table `Mot`------------------ */
    /**
     * Creating new Mot
     */
    public function createMot($libelle, $actif) {
        //valeur 1 pour actif: mot actif
        //valeur 0 pour actif: mot inactif
        //choix d'un entier si dans le futur on veut mettre des probas sur l'apparition de mot
        $query="INSERT INTO Mot (mot_libelle, mot_actif) VALUES(?,?)";
        $stmt = $this->conn->prepare($query);
        $stmt->bind_param("si", $libelle,$actif);
        $result = $stmt->execute();
        $stmt->close();
        if ($result) {
                // Rose successfully created
                return MOT_SUCCESSFULLY_CREATED;
            } else {
                // Failed to create Rose
                return MOT_CREATE_FAILED;
            }
        }
    /**
     * Getting a mot_id by the mot_libelle
     */
    public function getMotIdByLib($libelle) {
        $stmt = $this->conn->prepare("SELECT mot_id FROM Mot WHERE mot_libelle = ?");
        $stmt->bind_param("s", $libelle);
        if ($stmt->execute()) {
            $mot_id = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            return $mot_id['mot_id'];
        } else {
            return NULL;
        }
    }
    
    /**
     * Getting a mot_id by the mot_libelle
     */
    public function getMots() {
        $request = "SELECT mot_id,mot_libelle FROM Mot WHERE mot_actif=1";
        $stmt = $this->conn->prepare($request);
        $stmt->execute();
        $mots = $stmt->get_result();
        $stmt->close();
        return $mots;
    }
   
/* ------------- Methode de la table `PossedeNote`------------------ */
    /**
     * Creating new Note
     */
    public function createNote($marqueur_id, $mot_id,$note_value) {
        //pas de test d'unicité, il y a une contrainte en base sur le couple (marqueur,mot)
        $query="INSERT INTO PossedeNote (marqueur_id, mot_id,note_value) VALUES(?,?,?)";
        $stmt = $this->conn->prepare($query);
        $stmt->bind_param("iii", $marqueur_id,$mot_id, $note_value);
        $result = $stmt->execute();
        $stmt->close();
        if ($result) {
                // Note successfully created
                return NOTE_SUCCESSFULLY_CREATED;
            } else {
                // Failed to create Note
                return NOTE_CREATE_FAILED;
            }
    }
    
        /**
     * Fetching notes for single marqueur ID
     * @param String $user_id id of the user
     * User checking : won't get note of a marqueur not own by the user
     * WARNING : not used but may be if we want to make notes private for the owner of the marqueur 
     */    
    public function getNote($user_id, $marqueur_id) {
        $request = "SELECT * FROM Mot Natural JOIN PossedeNote Natural RIGHT JOIN Marqueur WHERE utilisateur_id=? and marqueur_id=?";
        $stmt = $this->conn->prepare("$request");
        $stmt->bind_param("ii",$user_id,  $marqueur_id);
        if ($stmt->execute()) {
            $marqueur = $stmt->get_result();
            $stmt->close();
            return $marqueur;
        } else {
            return NULL;
        }
    }
    
            /**
     * Fetching notes for single marqueur ID
     * @param String $user_id id of the user
     * NO user checking: will get note even if the user doesn't own the marqueur
     */    
    public function getNoteSu($marqueur_id) {
        $request = "SELECT * FROM Mot Natural JOIN PossedeNote Natural RIGHT JOIN Marqueur WHERE marqueur_id=?";
        $stmt = $this->conn->prepare("$request");
        $stmt->bind_param("i",$marqueur_id);
        if ($stmt->execute()) {
            $marqueur = $stmt->get_result();
            $stmt->close();
            return $marqueur;
        } else {
            return NULL;
        }
    }
    
/* ------------- Methode de la table `Photo`------------------ */
    /**
     * Creating new Photo
     */
    public function createPhoto($marqueur_id, $chemin) {
        //pas de test d'unicité, il y a une contrainte en base sur le couple (marqueur,mot)
        $query="INSERT INTO Photo (marqueur_id, photo_chemin) VALUES(?,?)";
        $stmt = $this->conn->prepare($query);
        $stmt->bind_param("is", $marqueur_id,$chemin);
        $result = $stmt->execute();
        $stmt->close();
        if ($result) {
                // Note successfully created
                return PHOTO_SUCCESSFULLY_CREATED;
            } else {
                // Failed to create Note
                return PHOTO_CREATE_FAILED;
            }
    }

    
    
    
    
    //EXEMPLE SUR UN AUTRE MODELE DE BDD
    //LES METHODES POUR CREER LES MARQUEURS SONT A FAIRE
//    /* ------------- `tasks` table method ------------------ */
// 
//    /**
//     * Creating new task
//     * @param String $user_id user id to whom task belongs to
//     * @param String $task task text
//     */
//    public function createTask($user_id, $task) {        
//        $stmt = $this->conn->prepare("INSERT INTO tasks(task) VALUES(?)");
//        $stmt->bind_param("s", $task);
//        $result = $stmt->execute();
//        $stmt->close();
// 
//        if ($result) {
//            // task row created
//            // now assign the task to user
//            $new_task_id = $this->conn->insert_id;
//            $res = $this->createUserTask($user_id, $new_task_id);
//            if ($res) {
//                // task created successfully
//                return $new_task_id;
//            } else {
//                // task failed to create
//                return NULL;
//            }
//        } else {
//            // task failed to create
//            return NULL;
//        }
//    }
// 
//    /**
//     * Fetching single task
//     * @param String $task_id id of the task
//     */
//    public function getTask($task_id, $user_id) {
//        $stmt = $this->conn->prepare("SELECT t.id, t.task, t.status, t.created_at from tasks t, user_tasks ut WHERE t.id = ? AND ut.task_id = t.id AND ut.user_id = ?");
//        $stmt->bind_param("ii", $task_id, $user_id);
//        if ($stmt->execute()) {
//            $task = $stmt->get_result()->fetch_assoc();
//            $stmt->close();
//            return $task;
//        } else {
//            return NULL;
//        }
//    }
// 
//    /**
//     * Fetching all user tasks
//     * @param String $user_id id of the user
//     */
//    public function getAllUserTasks($user_id) {
//        $stmt = $this->conn->prepare("SELECT t.* FROM tasks t, user_tasks ut WHERE t.id = ut.task_id AND ut.user_id = ?");
//        $stmt->bind_param("i", $user_id);
//        $stmt->execute();
//        $tasks = $stmt->get_result();
//        $stmt->close();
//        return $tasks;
//    }
// 
//    /**
//     * Updating task
//     * @param String $task_id id of the task
//     * @param String $task task text
//     * @param String $status task status
//     */
//    public function updateTask($user_id, $task_id, $task, $status) {
//        $stmt = $this->conn->prepare("UPDATE tasks t, user_tasks ut set t.task = ?, t.status = ? WHERE t.id = ? AND t.id = ut.task_id AND ut.user_id = ?");
//        $stmt->bind_param("siii", $task, $status, $task_id, $user_id);
//        $stmt->execute();
//        $num_affected_rows = $stmt->affected_rows;
//        $stmt->close();
//        return $num_affected_rows > 0;
//    }
// 
//    /**
//     * Deleting a task
//     * @param String $task_id id of the task to delete
//     */
//    public function deleteTask($user_id, $task_id) {
//        $stmt = $this->conn->prepare("DELETE t FROM tasks t, user_tasks ut WHERE t.id = ? AND ut.task_id = t.id AND ut.user_id = ?");
//        $stmt->bind_param("ii", $task_id, $user_id);
//        $stmt->execute();
//        $num_affected_rows = $stmt->affected_rows;
//        $stmt->close();
//        return $num_affected_rows > 0;
//    }
// 
//    /* ------------- `user_tasks` table method ------------------ */
// 
//    /**
//     * Function to assign a task to user
//     * @param String $user_id id of the user
//     * @param String $task_id id of the task
//     */
//    public function createUserTask($user_id, $task_id) {
//        $stmt = $this->conn->prepare("INSERT INTO user_tasks(user_id, task_id) values(?, ?)");
//        $stmt->bind_param("ii", $user_id, $task_id);
//        $result = $stmt->execute();
//        $stmt->close();
//        return $result;
//    }
// 
}
 
?>