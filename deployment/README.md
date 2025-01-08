# Setting up the HA cluster with nginx load balancer, keepalived and postgresql

Tested on Ubuntu 24.04 LTS ✅

The architecture is as follows in the diagram below and you need minimal 5 servers to run it. Also you can run it with 3 servers without VIP (nginx, vaultwarden and postgresql).

## General requirments

Copy `inventory/servers.ini.sample` to `inventory/servers.ini`

```bash
cd deployment
cp inventory/servers.ini.sample inventory/servers.ini
```

Install Ansible collections

```bash
ansible-galaxy collection install -r requirements.yml
```

Edit an `inventory/servers.ini` file and fill it with IP addresses, ansible user your domian and etc. If your servers doesn't have a private IP, put your public IP address instead of private ip. For example

```ini
[all]
vaultwarden-srv-1    ansible_host=188.121.112.240     private_ip=188.121.112.240
nginx-srv-1          ansible_host=188.121.112.242     private_ip=188.121.112.242
```

Edit an `inventory/group_vars/all.yml` file and fill it with your variables for the deployment.

In this deployment we deploy one postgres server.
If you want to deploy HA postgres cluster, you can use this repository: https://github.com/sudoix/postgres-ansible and also you should change `use_postgres` to `false` in `inventory/group_vars/all.yml` file and just put your postgres server info in `inventory/group_vars/all.yml` file.

## With five server

<span style="color: red;">Create a domain or subdomain DNS record for the vaultwarden cluster and point it to the first nginx server. (For generate certificates) and after installation finished update the dns record to the VIP address </span>

### Ready to deploy

Just run

```bash
cd deployment
ansible-playbook -i inventory/servers.ini vault_pgsql.yml --become --become-method=sudo
```

```txt
                   +-----------------+
                   |     Client      |
                   +--------+--------+
                            |
                         +--v--+
                         | VIP |
                         +--+--+
                            |
  +--------+--------+       |       +---------+-------+
  |   nginx srv 1   |<------+------>|   nginx srv 2   |
  |   keepalived    |               |   keepalived    |
  +-----------------+               +-----------------+
           |                                 |
           |                                 |
           +----------------+----------------+
                            |
           +----------------+----------------+
           |                                 |
           v                                 v
 +---------+--------+             +----------+--------+
 | vaultwarden srv1 |             | vaultwarden srv 2 |
 +------------------+             +-------------------+
           |                                 |
           +----------------+----------------+
                            |
                            v
                   +--------+--------+
                   | postgresql  srv |
                   +-----------------+

```

## with three server

<span style="color: red;">Create a domain or subdomain DNS record for the vaultwarden cluster and point it to the first nginx server. (For generate certificates) </span>

Change `use_keepalived` to `false` in `inventory/group_vars/all.yml` and run

### Ready to deploy

Just run

```bash
cd deployment
ansible-playbook -i inventory/servers.ini vault_pgsql.yml --become --become-method=sudo
```

```txt
                  +-----------------+
                  |     Client      |
                  +--------+--------+
                           |
                           |
                           v
                  +--------+--------+
                  |   nginx srv 1   |
                  +--------+--------+
                           |
                           |
                           v
                  +--------+--------+
                  |Vaultwarden srv 1|
                  +--------+--------+
                           |
                           |
                           v
                  +--------+--------+
                  | postgresql  srv |
                  +-----------------+

```

TODO:

- [ ] Test on Debian 12
- [ ] Write playbook for Rocky Linux 9
- [ ] Write playbook for mariadb database
