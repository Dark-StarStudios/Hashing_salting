<!DOCTYPE html>
<html lang="en">
<head>
  <title>Bootstrap 5 Example</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <?php
  require_once 'session.php';
  ?>
</head>
<body>

<div class="container-fluid p-5 bg-primary text-white text-center">
  <h1>Hallo <?php echo $gebruikersNaam ?></h1>
  <p><?php echo $gebruikersSaliting ?></p> 
</div>
  
<div class="container mt-5">
  <div class="row">
    <div class="col-sm-4">
      <h3>Column 1</h3>
      <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit...</p>
      <p>Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris...</p>
    </div>
    <div class="col-sm-4">
      <h3>Column 2</h3>
      <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit...</p>
      <p>Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris...</p>
    </div>
    <div class="col-sm-4">
    <form class='d-grid' action='index.php' method='post'>
                    <input type='hidden' name='uitloggen'>
                    <button type='submit' class='shadow btn btn-danger'>Uitloggen</button>
                </form>    
    </div>
  </div>
</div>

</body>
</html>
