<?php
namespace Identity;

class account{
    // Array met gegevens voor de database connectie naar "beveiligd_wachtwoord_db"
    private $serverConnectieData = ["localhost","root","","beveiligd_wachtwoord_db"];

    // Controleert of het wachtwoord en het herhaalde wachtwoord gelijk zijn
    public function herhaal_wachtwoord_control($wachtwoord,$herhaal_wachtwoord){
        return $wachtwoord === $herhaal_wachtwoord ? true : false;
    }
    // Controleert of alle velden in een array niet leeg zijn
    public function post_control($array){
        foreach($array as $element){
            if(empty($element)){
                return false;
            }
        }
        return true;
    }
    // functie die registreer een nieuwe gebruiker
   public function Registreren($postNaam,$postWachtwoord){
        $serverConnectieData = $this->serverConnectieData;
        try
        {
            // Maak een nieuwe connectie naar de database
            $connectie = new \mysqli($serverConnectieData[0],$serverConnectieData[1],$serverConnectieData[2],$serverConnectieData[3]);
            // Controleer of de connectie gelukt is.
            if ($connectie->error)
            {
                throw new \Exception($connectie->connect_error);
            }
            //salting
            $Salting = uniqid('',true);
            // SQL-code die zal je naar database sturen
            $query = "INSERT INTO Gebruiker(Gebruikersnaam,Salting,Hash_wachtwoord,Aantal_logins,Laatste_login) VALUES (?,?,?,0,null)";
            // Controleer of wachtwoords juist is
            $postHash = password_hash(($postWachtwoord.$Salting), PASSWORD_DEFAULT);
                //Bereid de SQL-query voor en bind de parameters.
                $statement = $connectie->prepare($query);
                // Argumenten binden aan ?
                $statement->bind_param("sss",$postNaam,$Salting,$postHash);
                // Voer de query uit en controleer op fouten
                if (!$statement->execute())
                {
                    throw new \Exception($connectie->error);
                }
        }
        catch(\Exception $e)
        {
            //Als er fouten zijn, komt de volgende melding: 
            echo "<div class='alert alert-warning'><h4>Oops: Is het iets met de Server!</h4></div>"; //. $e->getMessage();
        }
        finally
        {
                // Sluit de statement en de connectie
                if($statement){
                    $statement->close();
                } 
                if($connectie){
                    $connectie->close();
                }
                // Redirect de gebruiker naar de login pagina
                header("location: login.php?register=true");
                exit(); // Zorg ervoor dat het script stopt na de header redirect
        }
    }
    // functie die log een nieuwe gebruiker in
    public function login($postNaam,$postWachtwoord){
        $serverConnectieData = $this->serverConnectieData;
        try
            {
                // Maak een nieuwe connectie naar de database
                $connectie = new \mysqli($serverConnectieData[0],$serverConnectieData[1],$serverConnectieData[2],$serverConnectieData[3]);
                //Controleer of de connectie gelukt is
                if ($connectie->error)
                {
                    throw new \Exception($connectie->connect_error);
                }
                // SQL-code die zal je naar database sturen
                $query = "SELECT ID,Gebruikersnaam,Salting,Hash_wachtwoord,Aantal_logins FROM gebruiker WHERE Gebruikersnaam=?";
                //Bereid de SQL-query voor en bind de parameters.
                $statement = $connectie->prepare($query);

                // Argument email binden aan ?
                $statement->bind_param("s",$postNaam);
                // Voer de query uit en controleer op fouten
                if (!$statement->execute())
                {
                    throw new \Exception($connectie->error);
                }
                // Bind de resultaten van de query aan variabelen
                $statement->bind_result($id,$naam,$Salting,$hash,$aantal_logins);

                $dataNaam = "<error>";
                $ALog = 0;
                // Haal de resultaten op
                while($statement->fetch())
                {
                    //Controleer of wachtowoord juist is
                    $dataWachtwoord = password_verify($postWachtwoord.$Salting,$hash); //ERROR
                    $dataNaam = $naam;
                    if($dataWachtwoord)
                    {
                        //Sla alle gegevens van gebruiker behalve wachtwoord in session"login" op
                        $_SESSION["login"] = [$id,$naam,$Salting];
                        $ALog += 1+$aantal_logins;
                        
                    }
                    else
                    {
                        //Sla session"login" op als null
                        $_SESSION["login"] = null;
                        //kennisgeving
                        setcookie("waarschruwing","Verkeerde wachtowoord!",time()+2);
                    }
                }
                //Controleer of gebruiker onjuiste email opgeschreven als wel dan krijg gebruiker kennisgeving
                if($dataNaam === "<error>"){
                    //kennisgeving
                    setcookie("waarschruwing","Verkeerd e-mailadres of geen dergelijk account!",time()+2);
                    //Sla session"login" op als null
                    $_SESSION["login"] = null;
                }
                if(isset($_SESSION["login"])){
                    //Update aantal logins in database
                    $statement = $connectie->prepare("UPDATE gebruiker SET Aantal_logins=".$ALog.", Laatste_login= NOW() WHERE ID=".$_SESSION["login"][0]);
                        if (!$statement->execute())
                        {
                            throw new \Exception($connectie->error);
                        }
                    }

                
            }
            catch(\Exception $e)
            {
                //Als er fouten zijn, komt de volgende melding: 
                echo "<div class='alert alert-warning'><h4>Oops: Is het iets met de Server!</h4></div>". $e->getMessage();
            }
            finally
            {
                // Sluit de statement en de connectie
                if($statement){
                    $statement->close();
                } 
                if($connectie){
                    $connectie->close();
                }
                // Redirect de gebruiker naar de home pagina
                header("location: index.php");
                exit(); // Zorg ervoor dat het script stopt na de header redirect
            }
    }
}