<?php

// DEBUG
ini_set('display_startup_errors',1);
ini_set('display_errors',1);
error_reporting(E_ALL);

//ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, 7);
// self-signed cert disable check
putenv('LDAPTLS_REQCERT=never');

// authorized non-interactive service credentials
// this service has permission to read and write user attributes in specified OU(s)
$svcupn = "service@zsstu.local";
$svcpwd = "Pa$$.w0rd";

// LDAP server URI
$server = "ldaps://ad-server-hostname/";

// check only this domain in UPN
$domain = "zs-studanka.cz";

// allow only users within managed OU
$managed_ou = "OU=Zaci,OU=Uzivatele,OU=Skola,DC=ZSSTU,DC=local";

// TODO
$managed_ous = Array(
    "OU=Zaci,OU=Uzivatele,OU=Skola,DC=ZSSTU,DC=local",
    "OU=Asistenti,OU=Zamestnanci,OU=Uzivatele,OU=Skola,DC=ZSSTU,DC=local",
    "OU=Vychovatelky,OU=Zamestnanci,OU=Uzivatele,OU=Skola,DC=ZSSTU,DC=local",
    "OU=Jidelna,OU=Provoz,OU=Zamestnanci,OU=Uzivatele,OU=Skola,DC=ZSSTU,DC=local",
    "OU=Uklizecky,OU=Provoz,OU=Zamestnanci,OU=Uzivatele,OU=Skola,DC=ZSSTU,DC=local",
);


/********************************************************************************/

// LDAP status code, (can perform password change, localized message)
$err_codes = Array(
                    '-'   => Array(true,  'OK'), // OK
                    '0'   => Array(false, '(neznámá chyba)'), // (unknown error)
                    '525' => Array(false, 'uživatel nebyl nalezen'), // user not found
                    '52e' => Array(false, 'nesprávné údaje'), // invalid credentials
                    '530' => Array(true,  'v tuto chvíli není přihlášení povoleno'), // not permitted to logon at this time
                    '532' => Array(true,  'platnost hesla vypršela'), // password expired
                    '533' => Array(false, 'uživatelský účet je uznamčen'), // account disables
                    '701' => Array(false, 'platnost uživatelského účtu vypršela'), // account expired
                    '773' => Array(true,  'je vyžadována změna hesla'), // user must change password
                    '775' => Array(false, 'účet je uzamčen'), // account locked
                  );

// displayed messages
$messages = Array();

/**
 * Změna hesla.
 * 
 * Perform user password change.
 * 
 * @param string $username uživatelské jméno / user name
 * @param string $oldPassword staré heslo / old password
 * @param string $newPassword nové heslo / new password
 * @param string $newPasswordConfirm potvrzení nového hesla / new password confirmation
 * @return bool 
 */
function changePassword(string $username, string $oldPassword, string $newPassword, string $newPasswordConfirm) : bool
{   
    global $svcpwd, $svcupn;
    global $server, $domain, $managed_ou;
    global $messages;
    global $err_codes;
    
    $con = ldap_connect($server);
    ldap_set_option($con, LDAP_OPT_REFERRALS, 0);
    ldap_set_option($con, LDAP_OPT_PROTOCOL_VERSION, 3);
    // self-signed; don't check certificate
    ldap_set_option($con, LDAP_OPT_X_TLS_REQUIRE_CERT, LDAP_OPT_X_TLS_NEVER);
    
    // bind service account
    ldap_bind($con, $svcupn, $svcpwd);
    
    // normalize username
    $user = $username;
    if (strpos($username, "@") !== false)
    {
        $name_split = explode("@", $username);
        $user = $name_split[0] . "@" . $domain;
    } else {
        $user = $username . "@" . $domain;
    }
 
    // lookup in managed OU
    $user_search = ldap_search($con, $managed_ou, "(|(userprincipalname=" . $user . ")(mail=" . $user . "))");
    
    if ($user_search === false)
    {
        // "Operation cannot be performed, try again later."
        $messages[] = "Nebylo možné provést požadovanou operaci, zkuste to později.";
        return false;
    }
    
    $user_get = ldap_get_entries($con, $user_search);
    
    if ((int) $user_get["count"] < 1)
    {
        // "User account is invalid."
        $messages[] = "Uživatelský účet není platný.";
        return false;
    }
    
    $user_entry = ldap_first_entry($con, $user_search); // first entry
    $user_dn = ldap_get_dn($con, $user_entry); // user DN
    
    if (strlen($newPassword) < 8)
    {
        // "Your new password is too short (must be at least 8 characters long)."
        $messages[] = "Zadané heslo je příliš krátké (je vyžadováno 8 a více znaků).";
        return false;
    }
    
    if (!preg_match("/[0-9]/", $newPassword))
    {
        // "Your new password must contain at least one digit."
        $messages[] = "Nové heslo musí obsahovat alespoň jednu číslici.";
        return false;
    }
    
    if (!preg_match("/[a-zA-Z]/", $newPassword))
    {
        // "Your new password must contain at least one letter."
        $messages[] = "Nové heslo musí obsahovat alespoň jedno písmeno.";
        return false;
    }
    
    if (!preg_match("/[A-Z]/", $newPassword))
    {
        // "Your new password must contain at least one uppercase letter."
        $messages[] = "Nové heslo musí obsahovat alespoň jedno velké písmeno.";
        return false;
    }
    
    if (!preg_match("/[a-z]/", $newPassword))
    {
        // "Your new password must contain at least one lowercase letter."
        $messages[] = "Nové heslo musí obsahovat alespoň jedno malé písmeno.";
        return false;
    }
    
    if (!preg_match('/[\'\/~`\!@#\$%\^&\*\(\)_\-\+=\{\}\[\]\|;:"\<\>,\.\?\\\]/', $newPassword))
    {
        // "Your new password must contain at least one special character."
        $messages[] = "Nové heslo musí obsahovat alespoň jeden zvláštní znak.";
        return false;
    }
    
    if ($newPassword != $newPasswordConfirm )
    {
        // "Your new passwords do not match."
        $messages[] = "Nově zadaná hesla se neshodují.";
        return false;
    }
    
    // check user account
    $login_check = login($user, $oldPassword);
    
    // can be changed?
    if (!$err_codes[$login_check][0]) {
        // "Your password cannot be changed - ... "
        $messages[] = "Heslo nemůže být změněno - " . $err_codes[$login_check][1] . ".";
        return false;
    } else {
        // "Your password can be changed (...)"
        $messages[] = "Heslo může být změněno (" . $err_codes[$login_check][1] . ").";
    }
    
    // create new password (works with MS Active Directory 2016)
    $new_pwd = (mb_convert_encoding("\"" . $newPassword . "\"", 'UTF-16LE', 'UTF-8'));
    
    // create new entry
    $entry = Array();
    $entry["unicodePwd"] = $new_pwd; // unicodePwd
    $entry["pwdLastSet"] = -1; // make new password immediately active
    
    // change password
    if (ldap_modify($con, $user_dn, $entry) === true)
    {
        // "Your password has been changed. <b>Changes will take up to 30 minutes</b>."
        $messages[] = "Heslo bylo změněno. <b>Změna se projeví do 30 minut</b>.";
        return true;
    } else {
        // "Unable to change your password. Please contact system administrator."
        $messages[] = "Heslo nebylo možné změnit. Kontaktujte správce.";
        return false;
    }
    
}

/********************************************************************************/

/**
 * Ověření přihlášení do LDAP se starým heslem a získání rozšířeného stavového
 * kódu pro vyřízení žádosti.
 * 
 * Attempt to get extended status code for this user account.
 * 
 * @param string $username uživatelské jméno / user name
 * @param string $password heslo / current password
 * @return string stavový kód / status code
 */
function login(string $username, string $password) : string
{
    global $server;
    
    $con = ldap_connect($server);
    ldap_set_option($con, LDAP_OPT_REFERRALS, 0);
    ldap_set_option($con, LDAP_OPT_PROTOCOL_VERSION, 3);
    
    // bind attempt as user
    $user_bind = ldap_bind($con, $username, $password);
    
    // check for error
    if (!$user_bind) {
        
        // check for extended error information
        $ext_err = "";
        if (ldap_get_option($con, LDAP_OPT_DIAGNOSTIC_MESSAGE, $ext_err))
        {
            
            $err_code = "0";
            preg_match("/(?<=data\s).*?(?=\,)/", $ext_err, $err_code);
            
            // extended error code
            return $err_code[0];
        } else {
            // other unknown error
            return "0";
        }
    }
    
    // success code
    return "-";
}

/********************************************************************************/

?>

<!DOCTYPE html>
<html lang="cs" dir="ltr" >
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
        <title>ZŠ Pardubice - Studánka | Změna hesla</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/css/bootstrap.min.css" integrity="sha384-Vkoo8x4CGsO3+Hhxv8T/Q5PaXtkKtu6ug5TOeNV6gBiFeWPGFN9MuhOf23Q9Ifjh" crossorigin="anonymous" />
        <link href="style/base.css" rel="stylesheet" />
    </head>

    <body>
        
        <div id="container" class="containter-fluid">
            <div class="row row-cols-1">
                <h1>ZŠ Pardubice - Studánka</h1>
                
                <div class="alert alert-info">
                    Poštovní a&nbsp;další služby jsou pro&nbsp;zaměstnance
                    a&nbsp;žáky školy k&nbsp;dispozici v&nbsp;hostovaném prostředí
                    <a href="https://portal.office.com/">Office&nbsp;365</a>.
                </div>

                <h2>Změna hesla</h2>
                
                <div class="alert alert-info">
                    Zde je možné provést samoobslužnou změnu hesla
                    <strong>žákovského účtu</strong>.<br /><br />
                    <strong>Požadavky:</strong> nové heslo musí mít délku alespoň
                    8&nbsp;znaků, musí obsahovat alespoň jedno velké písmo, alespoň
                    jednu číslici a&nbsp;alespoň jeden symbol (tečka, pomlčka,
                    hvězdička,&nbsp;&hellip;).
                </div>
            
            </div>
            
            
            <div class="row row-cols-1" id="messages">
<?php

// form values
if ( filter_input(INPUT_POST, 'change') !== null ) {

    // change password
    $change = changePassword(
            (string) filter_input(INPUT_POST, 'username'),
            (string) filter_input(INPUT_POST, 'oldPassword'),
            (string) filter_input(INPUT_POST, 'newPassword1'),
            (string) filter_input(INPUT_POST, 'newPassword2')
            );
        
    // display messages
    foreach ($messages as $message) {
        echo "<div class=\"alert alert-primary\">" . $message . "</div>\n";
    }
    
}

?>
            </div>
            
            <div class="row row-cols-1" id="form">
                
                <form action="/" name="changePassword" method="post">
                    <div class="form-group">
                        
                        <label for="username">Uživatel</label>
                        <div class="input-group mb-2 mr-sm-2">
                            <div class="input-group-prepend">
                                <div class="input-group-text">@</div>
                            </div>
                            <input type="text" class="form-control" id="username" name="username" placeholder="novak.adam@zs-studanka.cz">
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label for="oldPassword">Původní heslo</label>
                        <div class="input-group mb-2 mr-sm-2">
                            <div class="input-group-prepend">
                                <div class="input-group-text">P</div>
                            </div>
                            <input type="password" class="form-control" id="oldPassword" name="oldPassword">
                        </div>
                    </div>
                    
                    <div class="form-group">
                      <label for="newPassword1">Nové heslo</label>
                      <div class="input-group mb-2 mr-sm-2">
                            <div class="input-group-prepend">
                                <div class="input-group-text">N</div>
                            </div>
                      <input type="password" class="form-control" id="newPassword1" name="newPassword1">
                      </div>
                    </div>
                    
                    <div class="form-group">
                      <label for="newPassword2">Ověření nového hesla</label>
                      <div class="input-group mb-2 mr-sm-2">
                            <div class="input-group-prepend">
                                <div class="input-group-text">N</div>
                            </div>
                      <input type="password" class="form-control" id="newPassword2" name="newPassword2">
                      </div>
                    </div>
                    
                    <div class="form-group">
                        <input type="hidden" name="change" value="<?php echo md5(time()); ?>">
                    </div>
                           
                    <div class="row row-cols-2">
                        <div class="col">
                            <button id="change" type="submit" class="btn btn-primary">Změnit heslo</button>
                        </div>
                        <div class="col">
                            <button id="reset" type="reset" class="btn btn-secondary">Zrušit</button>
                        </div>
                    </div>
                </form>
                
            </div>
            
            <div class="row row-cols-1"><small class="text-muted">2020 ICT ZŠ Pardubice - Studánka</small></div>
            
        </div>

    </body>

</html>