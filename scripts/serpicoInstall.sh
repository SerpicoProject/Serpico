# serpicoInstall.sh

#!/bin/bash

username=$(whoami)

# Use this to download the rvm gpg
\curl -sSL https://rvm.io/mpapis.asc | sudo gpg --import -

# Download and install the stable version of RVM in multi user mode
\curl -sSL https://get.rvm.io | sudo bash -s stable

sudo -s <<EOF
gpg --keyserver hkp://keys.gnupg.net --recv-keys 409B6B1796C275462A1703113804BB82D39DC0E3 7D2BAF1CF37B13E2069D6956105BD0E739499BDB
adduser root rvm
adduser $username rvm

# Run this once to allow rvm to be run
source /etc/profile.d/rvm.sh

# This will add the source command to your .bashrc to ensure you don't have to run it each time
echo source /etc/profile >> /home/$username/.bashrc
echo source /etc/profile >> /root/.bashrc

# Install openssl library (required for ruby install 2.1.5)
apt-get install -y libssl1.0-dev

rvm get master

# Install and use Ruby 2.1.5, the version used by Serpico
rvm install 2.3.3

source /etc/profile.d/rvm.sh
rvm use 2.3.3

# Serpico Dependencies
apt-get -y install libsqlite3-dev libxslt-dev libxml2-dev zlib1g-dev gcc

# Get and install the development version of Serpico
git clone https://github.com/SerpicoProject/Serpico.git /opt/Serpico-Dev
cd /opt/Serpico-Dev/

gem install bundler

# The Gemfile has an issue during installation, run the below to preemptively resolve it
gem install msfrpc-client -v 1.0.3

bundle install

# Initialize the findings database
puts "|+| Please run 'ruby scripts/first_time.rb' to complete the installation"
EOF

# One completed, you can edit /opt/Serpico-Dev/config.json so that your Serpico instance is local only.
# Change "bind_address": "0.0.0.0", to "bind_address": "127.0.0.1",
