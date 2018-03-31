<?php
/**
 * Database configuration
 */

define('DB_USERNAME', '[YOUR DB USERNAME]');
define('DB_PASSWORD', '[YOUR DB PASSWORD]');
define('DB_HOST', '[YOUR DB ADRESS]');
define('DB_NAME', '[YOUR DB NAME]');

//WARNING : ne pas enlever ca pourrait casser des trucs
define('USER_CREATED_SUCCESSFULLY', 0);
define('USER_CREATE_FAILED', -1);
define('USER_EMAIL_ALREADY_EXISTED', -2);
define('USER_PSEUDO_ALREADY_EXISTED', -3);
define('ADDRESS_CREATED_SUCCESSFULLY', -4); //shouldn't be used
define('ADDRESS_CREATE_FAILED', -5);
define('ADDRESS_ALREADY_EXISTED', -6); //shouldn't be used
define('LOCALISATION_CREATE_FAILED',-7);
define('MARQUEUR_CREATE_FAILED',-8);
define('ROSE_SUCCESSFULLY_CREATED', -9);
define('ROSE_CREATE_FAILED', -10);
define('MOT_SUCCESSFULLY_CREATED', -11);
define('MOT_CREATE_FAILED', -12);
define('MOT_NOT_EXIST', -13);
define('NOTE_SUCCESSFULLY_CREATED',-14);
define('NOTE_CREATE_FAILED', -15);
define('PHOTO_SUCCESSFULLY_CREATED', -16);
define('PHOTO_CREATE_FAILED', -17);

?>