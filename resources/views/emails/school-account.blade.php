<!DOCTYPE html>
<html>
<head>
    <title>School Account Created</title>
</head>
<body>

<h2>Welcome, {{ $name }}</h2>

<p>Your school account has been successfully created.</p>

<p><strong>Login Details:</strong></p>
<ul>
    <li>Email: {{ $email }}</li>
    <li>Password: {{ $password }}</li>
</ul>

<p>Please verify your email by clicking the link below:</p>

<p>
    <a href="{{ $link }}">Verify Email</a>
</p>

<p><strong>Note:</strong> Change your password after first login.</p>

</body>
</html>
