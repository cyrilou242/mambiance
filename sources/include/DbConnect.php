<?php
 
/**
 * Handling database connection
 *
 * @author Ravi Tamada
 */
class DbConnect {
 
    private $conn;
 
    function __construct() {        
    }
 
    /**
     * Establishing database connection
     * @return database connection handler
     */
    function connect() {
        //getting config info
        require_once 'config.php';
        
        // Connecting to mysql database
        $this->conn = new mysqli(DB_HOST, DB_USERNAME, DB_PASSWORD, DB_NAME);
        
        //WARNING : changer des elements ici si passage sur une base POSTGRE
        //WARNING : code Postgre A PRIORI : $this->conn = new PDO('pgsql:host=http://ser-info-02.ec-nantes.fr dbname = mambiances', mambiances, PAPPLmara14);
        
        // Check for database connection error
        if (mysqli_connect_errno()) {
            echo "Echec de connexion a MySQL: " . mysqli_connect_error();
        }
 
        // returing connection resource
        return $this->conn;
    }
 
}
 
?>