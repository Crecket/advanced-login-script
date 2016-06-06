<?php
session_start();

require_once $_SERVER['DOCUMENT_ROOT'] . '/vendor/autoload.php';
require_once $_SERVER['DOCUMENT_ROOT'] . '/src/configfiles/config.php';

$login = new Crecket\AdvancedLogin\Login();

// set the template to be used as a string. {url} will be replaced automatically with the required url
$login->ResetPasswordFunc = "Please click the following link to set a new password. <a href='{url}'>{url}</a>";
// OR a function with the first parameter being the url
$login->ResetPasswordFunc = function ($url) {
    // use a template engine or do some action to generate the template (twig for example)
    $template = file_get_contents(__DIR__ . '/email_templates/password_reset.html');
    return str_replace("{url}", $url, $template);
};

// test your function like this: first parameter will be the reset url
//echo call_user_func($login->ResetPasswordFunc, 'http://some_url');


$login->checkLoggedIn();


if (Crecket\AdvancedLogin\Core::$loggedIn !== false) {
    header('Location: index.php');
}

$show_request_form = true; // default is yes whether to show the request email form is shown

$show_password_form = false;

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