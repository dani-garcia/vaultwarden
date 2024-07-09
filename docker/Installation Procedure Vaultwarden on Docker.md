# Vaultwarden Installation

The goal of this procedure is to simplify the installation of Vaultwarden using Docker.

Prerequisites:
A Debian machine virtual or physique; *the method works on multiple distributions, but commands may need to be adapted for Docker installation.*

## Docker Installation

### Configure the Docker Repository

*Source: <https://github.com/NicolasW-7/AIS-Brief-et-TIPS/blob/main/Procedure/Docker/Installation%20Docker.md?plain=1>*

1. Update the package list:

    ```sh
    sudo apt-get update
    ```

2. Install the necessary packages:

    ```sh
    sudo apt-get install ca-certificates curl gnupg
    ```

3. Create the directory for the repository keys:

    ```sh
    sudo install -m 0755 -d /etc/apt/keyrings
    ```

4. Download and add the Docker GPG key:

    ```sh
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    ```

5. Change the permissions of the GPG key:

    ```sh
    sudo chmod a+r /etc/apt/keyrings/docker.gpg
    ```

6. Add the Docker repository to the APT sources list:

    ```sh
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    ```

7. Update the package list to include the Docker repository:

    ```sh
    sudo apt-get update
    ```

8. Install the necessary Docker packages:

    ```sh
    sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    ```

### Verify Docker Installation

9. Check the status of the Docker service:

    ```sh
    systemctl status docker
    ```

10. If Docker is "active (running)", enable the Docker service to start automatically after the machine reboots:

    ```sh
    sudo systemctl enable docker
    ```

### Useful Docker Commands

- `docker ps -a`: Shows all containers, including their status, creation date, age, name, and ID.
- `docker stop <container_id>` / `docker rm <container_id>`: Stops (`stop`) and removes (`rm`) a container by adding its ID.
- `docker compose up -d`: Runs the `docker-compose.yml` file to start the containers in detached mode (`-d`).

#### Command Details

##### `docker ps -a`

Displays all containers, whether running or stopped, with information such as:

- Container ID
- Image used
- Command executed
- Creation date
- Status (running, stopped, etc.)
- Exposed ports
- Container names

##### `docker stop <container_id>` / `docker rm <container_id>`

- `docker stop <container_id>`: Stops a running container.
- `docker rm <container_id>`: Removes a stopped container.

**Example:**

```sh
docker stop 1a2b3c4d5e6f
docker rm 1a2b3c4d5e6f
```

## Creating Self-Signed Certificates with OpenSSL

*For this part, we will use self-signed certificates. In production, we will reproduce this step by copying the certificates.*

1. Once Docker is installed, we will need certificates for connecting to the VaultWarden web interface. To do this, create the `/ssl` and `/docker` directories at the root of our Debian machine if they don't already exist:

    ```sh
    mkdir /ssl
    mkdir /docker
    ```

    */ssl will be used to store the .csr, .crt, and .key files we will create, and /docker will contain the configuration files for our containers.*

2. Continue by generating the self-signed certificates. Move to the `/ssl` directory:

    ```sh
    cd /ssl
    ```

3. Create the following four files: .pem, .key, .crt, and .csr:

    ```sh
    openssl genrsa -des3 -out vaultwarden.key 2048
    openssl req -x509 -new -nodes -key vaultwarden.key -sha256 -days 10000 -out vaultwarden.pem
    openssl genrsa -out vaultwarden.key 2048
    openssl req -new -key vaultwarden.key -out vaultwarden.csr
    openssl x509 -req -days 10000 -in vaultwarden.csr -signkey vaultwarden.key -out vaultwarden.crt
    ```

    *Note: The generated certificate is valid for 10,000 days (about 27 years). This variable can be adjusted as needed. If necessary, a new certificate can be reissued on the machine using the CA created above.*

## Creating Docker-Compose.yml and CaddyFile Configuration Files for Deploying Containers

### A. Creating the Caddyfile

1. Access the `/docker` directory and create the files necessary for deploying the Caddy and Vaultwarden containers via Docker. Start with the Caddyfile:

    ```sh
    nano Caddyfile
    ```

2. Copy the following content into it:

    *The first line corresponds to the title of our vaultwarden page, which will be accessible via a web browser.*

    ```sh  
    *your domain name* {
      tls internal

      encode gzip

      reverse_proxy /notifications/hub vaultwarden:3012
      reverse_proxy vaultwarden:80
    }
    ```

    *To save, simply press Ctrl+X and then O.*

3. With the CaddyFile created, proceed to the docker-compose.yml file:

### B. Creating the Docker-Compose.yml File

    ```sh
    nano docker-compose.yml
    ```

    Copy the following content:

    ```sh
    version: '3.7'

    services:
      vaultwarden:
        image: vaultwarden/server:latest
        container_name: vaultwarden
        restart: always
        environment:
          WEBSOCKET_ENABLED: true
          ADMIN_TOKEN: #YourAdminToken
          DOMAIN: "YourDomain" # Your domain; vaultwarden needs to know it's https to work properly with attachments
        volumes:
          - vw-data:/data

      caddy:
        image: caddy:2
        container_name: caddy
        restart: always
        ports:
          # Needed for the ACME HTTP-01 challenge.
          - 443:443
        volumes:
          - ./Caddyfile:/etc/caddy/Caddyfile:ro
          - ./ssl:/ssl
          - caddy-config:/config
          - caddy-data:/data
          - caddy-logs:/logs
        environment:
          - DOMAIN= # Your domain.
          #EMAIL: "YOUR EMAIL"                 # The email address to use for ACME registration.
          #LOG_FILE: "/data/access.log"

    volumes:
      vw-data:
      caddy-config:
      caddy-data:
      caddy-logs:
    ```

### C. Enabling the Admin Console

These lines enable the admin console:

    ```sh
    WEBSOCKET_ENABLED: true
    ADMIN_TOKEN: YourAdminToken
    ```

**They can be omitted or modified to hide the admin console token (password).**

4. To hide the token, add these lines:

    ```sh
    WEBSOCKET_ENABLED: true
          # Reference the secret
          ADMIN_TOKEN_FILE: "/run/secrets/admin_token"

    secrets:
      admin_token:
        file: ./admin_token.txt
    ```

5. Next, create the `/run/secrets` directory and the `admin_token.txt` file. Enter the following into this file:

    ```sh
    echo "*OurVaultWardenAdminToken*" > admin_token.txt
    ```

### Starting the Docker Containers

1. To start our containers, run the following command:

    ```sh
    docker compose up -d
    ```

    To verify the containers are running properly, use the command:

    ```sh
    docker ps -a  
    ```

    Then, open a browser and enter your Vaultwarden domain here: <http://YourDomain>

    To access the admin console, simply go to <http://YourDomain/admin>

    Although the connection is established via HTTP, it will be automatically redirected to HTTPS by accepting the risks associated with self-signed certificates.

    **Vaultwarden needs to be run in HTTPS for account creation.**

    VaultWarden is now operational.

    You need to set up DNS autorization for your Vaultwarden with your <http://YourDomain>

2. Useful Docker Commands

    ```sh
    • docker ps -a : #View running containers, creation date, container age, name, and ID.
    • docker stop /rm *container id*: #Stop (stop) and remove (rm) a container by adding its ID.
    • docker compose up -d : #Launch docker-compose.yml to run the containers.
    ```
