# Garde
This is a simple authentication server to use with nginx's auth_request module.
Login page is served at both `/` and `/login`, and the validation endpoint is at `/auth`.
The server uses JWTs and cookies for authentication.

Currently only authentication with a `.htpasswd` file is supported but more methods may be added in the future.

Configuration with nginx is very simple, just add the following to your configuration:
```nginx

location / {
  # Authentication Configuration
  auth_request @auth;
  error_page 401 = @unauthorized;
}

location = @auth {
  internal;
  proxy_pass http://garde/auth;

  proxy_pass_request_body off;
  proxy_set_header Content-Length "";

  # Optional, but recommended for future reasons.
  proxy_set_header X-Original-URI $scheme://$host$request_uri;
}

location @unauthorized {
  internal;

  # Redirect to login page
  return 302 https://garde?redirect=$scheme://$host$request_uri;
}
```

Basic configuration parameters:
```env
# Port to listen for requests
GARDE__PORT=5089

# Domain to use for cookies
# If a domain is not specified, the server will try to
# figure out the root using IANA public suffix list
# for every request
# (eg. auth.example.com = example.com)
# For better performance, it's recommended to set this to the root domain of your application.
GARDE__DOMAIN=auth.example.com
```
See the included `docker-compose.yml` for more parameters and an example of how to run the server with Docker.