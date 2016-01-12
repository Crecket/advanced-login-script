<?php
session_start();

require_once $_SERVER['DOCUMENT_ROOT'] . '/vendor/autoload.php';
require_once $_SERVER['DOCUMENT_ROOT'] . '/src/configfiles/config.php';

$login = new Crecket\AdvancedLogin\Login();
$login->checkLoggedIn();


if (Crecket\AdvancedLogin\Core::$loggedIn !== false) {
    header('Location: index.php');
}

$show_request_form = true; // default is yes whether to show the request email form is shown

// check if code isset
if (!empty($_GET['code'])) {
    $show_request_form = false;
    $show_password_form = $login->checkForgotPasswordCode($_GET['code']);

    // the code is valid and returned user data
    if ($show_password_form !== false) {

        // create new link from user data to stop users from editing the link
        $link = Crecket\AdvancedLogin\Login::ForgotpasswordLinkCreator($show_password_form['forgotpassword_code']);

        // verify the post request
        if (!empty($_POST['password']) && !empty($_POST['repeat_password']) && \SecureFuncs\SecureFuncs::getFormToken('forgot_password', $_POST['form_token']) !== false) {

            // verify the password update request
            if ($login->changeForgotPassword($_POST['password'], $_POST['repeat_password'], $show_password_form['forgotpassword_code'])) {

                //success, return to index
                header('Location: index.php');
            }
        }

    }
}

if (!empty($_POST['email'])) {
    if (\SecureFuncs\SecureFuncs::getFormToken('forgot_password', $_POST['form_token'])) {
        $login->sendForgotPasswordCode($_POST['email']);
    }
}

$formToken = \SecureFuncs\SecureFuncs::setFormtoken('forgot_password');
?>
<!DOCTYPE html>
<html>
<head>
    <title>LoginScript - Forgot password</title>
</head>
<body>
<div class="header">
    <pre>
<?php
print_r($_SESSION[ADVANCEDLOGINSCRIPT_MESSAGE_KEY]);
unset($_SESSION[ADVANCEDLOGINSCRIPT_MESSAGE_KEY]);
?>
    </pre>
</div>
<div class="body">
    <?php if ($show_password_form != false): ?>
        <form method="POST" action="<?php echo $link; ?>">
            <input type="hidden" name="form_token" value="<?php echo $formToken; ?>">
            <p>Please enter a new password.</p>
            <table>
                <tr>
                    <td>Password</td>
                    <td><input type="password" name="password" required></td>
                </tr>
                <tr>
                    <td>Repeat password</td>
                    <td><input type="password" name="repeat_password" required></td>
                </tr>
                <tr>
                    <td>
                        <button>Reset password</button>
                    </td>
                </tr>
            </table>
        </form>
    <?php elseif ($show_request_form): ?>
        <form method="post">
            <input type="hidden" name="form_token" value="<?php echo $formToken; ?>">
            <table>
                <tr>
                    <td>Enter your email</td>
                    <td><input type="email" name="email" required></td>
                </tr>
                <tr>
                    <td>
                        <button>Send email</button>
                    </td>
                </tr>
            </table>
        </form>
    <?php endif; ?>
    <a href="index.php">Return home</a>
</div>
</body>
</html>