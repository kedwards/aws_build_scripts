#!/bin/bash
# curl https://omnitruck.chef.io/install.sh | sudo bash -s -- -P chefdk -c stable -v 2.0.28
apt-get update
apt-get -y install curl

# create staging directories
if [ ! -d /home/ubuntu/drop ]; then
  mkdir /home/ubuntu/drop
fi
if [ ! -d /home/ubuntu/downloads ]; then
  mkdir /home/ubuntu/downloads
fi

# download the Chef server package
if [ ! -f /home/ubuntu/downloads/chef-server-core_12.17.15-1_amd64.deb ]; then
  echo "Downloading the Chef server package..."
  wget -nv -P /home/ubuntu/downloads https://packages.chef.io/files/stable/chef-server/12.17.15/ubuntu/16.04/chef-server-core_12.17.15-1_amd64.deb
fi

# install Chef server
if [ ! $(which chef-server-ctl) ]; then
  echo "Installing Chef server..."
  dpkg -i /home/ubuntu/downloads/chef-server-core_12.17.15-1_amd64.deb
  chef-server-ctl reconfigure

  echo "Waiting for services..."
  until (curl -D - http://localhost:8000/_status) | grep "200 OK"; do sleep 15s; done
  while (curl http://localhost:8000/_status) | grep "fail"; do sleep 15s; done

  echo "Creating initial user and organization..."
  chef-server-ctl user-create chefadmin Chef Admin chefadmin@kevinedwards.ca chef_9499_admin --filename /home/ubuntu/drop/chefadmin.pem
  chef-server-ctl org-create livity "LivITy Consulting Ltd." --association_user chefadmin --filename livity-validator.pem
fi

echo "Your Chef server is ready!"