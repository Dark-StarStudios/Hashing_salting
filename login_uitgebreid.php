<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link rel="shortcut icon" href="marktplaats-logo.ico" type="image/x-icon">
    <!-- Bootstrap 5 CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="css/styles.css" rel="stylesheet"> 
</head>

<?php
    //Mijn kleine bibliotheek verbind met deze pagina 
    //Het is een speciale bibliotheek om accounten te maken of in de accounten te inloggen

    require_once 'account_uitgebreid.php';
    use Identity_uitgebreid\account_uitgebreid;
    $account = new account_uitgebreid();

    //SESSION OPSTARTEN
    session_start();
    //Controleer of email post wel bestaat, als wel dan login functie opstarten
    if ((isset($_POST["email"])))
    {
        
        $account->login(htmlspecialchars($_POST["email"]),htmlspecialchars($_POST["wachtwoord"]));
    }

?>

<body class="bg-oranje">
    <div class="container mb-10 bg-light mt-5 rounded shadow">
        <h1 class="text-grijs"> Login </h1>

        <?php
        //Als account van gebruiker werd nu al gemaakt dan laat het melding zien!
        if(isset($_GET['register'])){
            echo "<div class='alert alert-success'><h4>Uw account is gemaakt!</h4></div>";
        }
        //Controleer of iets mis is. Als wel dan komt een kennisgeving.
        if(isset($_COOKIE["waarschruwing"])){
            echo "<div class='alert alert-warning'><h4>" . $_COOKIE["waarschruwing"] . "<h4></div>";
        }
        ?>

        <form action="login_uitgebreid.php" method="post">
            <div class="mb-3 mt-3">
                <label for="email" class="form-label" >Email:</label>
                <input type="email" name = "email" class="form-control" id="email" placeholder="Vul uw email in">
            </div>
            <div class="mb-5">
                <label for="wachtwoord" class="form-label">Wachtwoord:</label>
                <input type="password" name = "wachtwoord" class="form-control" id="wachtwoord" placeholder="Vul uw wachtwoord in">
            </div>
            <button type="submit" class="btn btn-success text-light mb-3 text-grijs">Inloggen</button>
            <a href="registreer_uitgebreid.php" class="btn btn-warning mb-3">Registreren</a>
        </form>
    </div>
</body>
<!-- Bootstrap 5 JavaScript -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</html>