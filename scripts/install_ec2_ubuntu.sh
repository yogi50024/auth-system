#!/bin/bash

# Update packages
sudo apt update
sudo apt upgrade -y

# Install Node.js
curl -fsSL https://deb.nodesource.com/setup_14.x | sudo -E bash -
sudo apt install -y nodejs

# Install MongoDB
sudo apt install -y mongodb

# Install Redis
sudo apt install -y redis-server
