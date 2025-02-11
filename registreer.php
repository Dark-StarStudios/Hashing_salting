<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registreer</title>
    <link rel="shortcut icon" href="marktplaats-logo.ico" type="image/x-icon">
    <!-- Bootstrap 5 CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="css/styles.css" rel="stylesheet"> 
</head>
<body class="bg-oranje">
    <div class="container bg-light mt-3 rounded shadow">
    <h1 class="text-grijs"> Registreer </h1>

    <?php
    //Mijn kleine bibliotheek verbind met deze pagina
    //Het is een speciale bibliotheek om accounten te maken of in de accounten te inloggen 
    require_once 'account.php';
    use Identity\account;
    $account = new account();
    //Controleer of REQUEST METHOD POST is. Het is om de volgende if-statement niet te beginnen
    if ($_SERVER["REQUEST_METHOD"] == "POST")
    {
        //Controleer of alle post niet leeg zijn. Als ze zijn wel leeg dan komt een kennisgeving.
        if($account->post_control([$_POST["wachtwoord"], $_POST["naam"],$_POST["herhaal_wachtwoord"]]))
        {
            //Controleer of alle twee wachtwoords hetzelfde zijn, als het is niet waar dan komt kennisgeving.
            if($account->herhaal_wachtwoord_control($_POST["wachtwoord"], $_POST["herhaal_wachtwoord"]))
            {
                //Roepen Register functie met argumenten
                $account->Registreren(htmlspecialchars($_POST["naam"]),htmlspecialchars($_POST["wachtwoord"]));
            }
            else
            {
                //kennisgeving 
                echo "<div class='alert alert-warning'><h4>Herhaal wachtwoord is onjust!</h4></div>";
            }
        }else
        {
            //kennisgeving
            echo "<div class='alert alert-warning'><h4>Vul alstublieft alles in!</h4></div>";
        }
    }
    ?>

    <form action="registreer.php" method="post">
        <div class="mb-3">
            <label for="naam" class="form-label">Naam:</label>
            <input type="text" name = "naam" class="form-control" id="naam" placeholder="Vul uw naam in" value="<?php echo htmlspecialchars(isset($_POST['naam'])&&!empty($_POST['naam'])?$_POST['naam']:"");?>">
        </div>
        <div class="mb-3">
            <label for="wachtwoord" class="form-label">Wachtwoord:</label>
            <input type="password" name = "wachtwoord" class="form-control" id="wachtwoord" placeholder="Vul een wachtwoord in">
        </div>
        <div class="mb-5">
            <label for="herhaal_wachtwoord" class="form-label">Herhaal wachtwoord:</label>
            <input type="password" name = "herhaal_wachtwoord" class="form-control" id="herhaal_wachtwoord" placeholder="Herhaal wachtwoord">
        </div>
        <button type="submit" class="btn btn-success mb-3 text-light text-grijs">Registreren</button>
        <a href="login.php" class="btn btn-warning mb-3">Inloggen</a>
    </form>
    </div>
    
</body>
<!-- Bootstrap 5 JavaScript -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</html>