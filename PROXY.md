# Proxy examples

In this document, `<SERVER>` refers to the IP or domain where bitwarden_rs is accessible from. If both the proxy and bitwarden_rs are running in the same system, simply use `localhost`.
The ports proxied by default are `80` for the web server and `3012` for the WebSocket server. The proxies are configured to listen in port `443` with HTTPS enabled, which is recommended.

When using a proxy, it's preferrable to configure HTTPS at the proxy level and not at the application level, this way the WebSockets connection is also secured.

## Caddy

```nginx
localhost:443 {
    # The negotiation endpoint is also proxied to Rocket
    proxy /notifications/hub/negotiate <SERVER>:80 {
        transparent
    }
    
    # Notifications redirected to the websockets server
    proxy /notifications/hub <SERVER>:3012 {
        websocket
    }
    
    # Proxy the Root directory to Rocket
    proxy / <SERVER>:80 {
        transparent
    }

    tls ${SSLCERTIFICATE} ${SSLKEY}
}
```

## Nginx (by shauder)
```nginx
server {
  include conf.d/ssl/ssl.conf;

  listen 443 ssl http2;
  server_name vault.*;

  location /notifications/hub/negotiate {
    include conf.d/proxy-confs/proxy.conf;
    proxy_pass http://<SERVER>:80;
  }

  location / {
    include conf.d/proxy-confs/proxy.conf;
    proxy_pass http://<SERVER>:80;
  }

  location /notifications/hub {
    proxy_pass http://<SERVER>:3012;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
  }
}
```

## Apache (by fbartels)
```apache
<VirtualHost *:443>
    SSLEngine on
    ServerName bitwarden.$hostname.$domainname

    SSLCertificateFile ${SSLCERTIFICATE}
    SSLCertificateKeyFile ${SSLKEY}
    SSLCACertificateFile ${SSLCA}
    ${SSLCHAIN}

    ErrorLog \${APACHE_LOG_DIR}/bitwarden-error.log
    CustomLog \${APACHE_LOG_DIR}/bitwarden-access.log combined

    RewriteEngine On
    RewriteCond %{HTTP:Upgrade} =websocket [NC]
    RewriteRule /(.*)           ws://<SERVER>:3012/$1 [P,L]

    ProxyPass / http://<SERVER>:80/

    ProxyPreserveHost On
    ProxyRequests Off
</VirtualHost>
```

## Traefik (docker-compose example)
```traefik
    labels:
      - 'traefik.frontend.rule=Host:vault.example.local'
      - 'traefik.docker.network=traefik'
      - 'traefik.port=80'
      - 'traefik.enable=true'
      - 'traefik.web.frontend.rule=Host:vault.example.local'
      - 'traefik.web.port=80'
      - 'traefik.hub.frontend.rule=Path:/notifications/hub'
      - 'traefik.hub.port=3012'
      - 'traefik.negotiate.frontend.rule=Path:/notifications/hub/negotiate'
      - 'traefik.negotiate.port=80'
```
