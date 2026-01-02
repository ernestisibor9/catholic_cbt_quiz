<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Diocese Admin Account</title>
</head>
<body>

<h2>Hello {{ $data['name'] }}</h2>

<p>Your Diocese has been successfully registered on the system.</p>

<p><strong>Login Details</strong></p>

<ul>
    <li><strong>Email:</strong> {{ $data['email'] }}</li>
    <li><strong>Password:</strong> {{ $data['password'] }}</li>
</ul>

<p>Please verify your account by clicking the link below:</p>

<p>
    <a href="{{ $data['link'] }}">Verify Email</a>
</p>

<p><em>For security reasons, please change your password after login.</em></p>

<br>

<p>Regards,<br>
System Administrator</p>

</body>
</html>
