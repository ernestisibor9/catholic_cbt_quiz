<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Verify Your Email</title>
</head>
<body>
    <p>Hello {{ $user->name ?? 'Diocesan Admin' }},</p>

    <p>Your diocese account has been created successfully.</p>

    <p>Click the link below to verify your email:</p>

    <p>
        <a href="{{ $link }}" style="padding:10px 15px; background:#2563eb; color:#fff; text-decoration:none;">
            Verify Email
        </a>
    </p>

    <p>This link will expire in 60 minutes.</p>
    <p>Thank you.</p>
</body>
</html>
