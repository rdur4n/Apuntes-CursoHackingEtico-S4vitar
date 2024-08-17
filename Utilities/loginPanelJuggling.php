<html>
    <font color="red"><h1><marquee>Secure Login Page</marquee></h1></font>
    <hr>
    <body style="background-color:powderblue;">
        <center><form method="POST" name="<?php basename($_SERVER['PHP_SELF']); ?>">
            Usuario: <input type="text" name="usuario" id="usuario" size="30">
            &nbsp;
            Password: <input type="password" name="password" id="password" size="30">
            <input type="submit" value="Login">
        </form></center>
    <?php
        $USER = "admin";
        $PASSWORD = "4st4p4ssw0rd!3simp0siblederomper!$2020..";

        if(isset($_POST['usuario']) && isset($_POST['password'])){
            if($_POST['usuario'] == $USER){
                if(strcmp($_POST['password'], $PASSWORD) == 0){
                    echo "Acceso exitoso!";
                } else { echo "La password es incorrecta!"; }
            } else { echo "El usuario es incorrecto!"; }
        }
    ?>
    </body>
</html>
