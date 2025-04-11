# Security Log Analysis and Visualization Tool - Setup Guide

This guide will help you get started with the Security Log Analysis and Visualization Tool. Just follow these steps in order, and you'll be up and running in no time!

## Prerequisites

Make sure you have these installed on your system:
- [Docker](https://www.docker.com/products/docker-desktop/) (Docker Desktop recommended for beginners)
- [Git](https://git-scm.com/downloads)

## Step 1: Get the Code

Open your terminal/command prompt and run these commands:

```bash
# Clone the repository
git clone https://github.com/yourusername/security-log-analyzer.git

# Move into the project directory
cd security-log-analyzer
```

## Step 2: Configure the Environment

```bash
# Copy the example configuration file
cp config.example.yaml config.yaml
```

The default configuration will work out of the box, but if you want to customize:
- Open `config.yaml` in any text editor
- Modify the settings as needed (the file has helpful comments)

## Step 3: Start the Application

```bash
# Build and start all services
docker-compose up -d

# Check if everything is running
docker-compose ps
```

You should see all services showing as "running" in the status.

## Step 4: Access the Dashboard

1. Open your web browser
2. Go to: `http://localhost:8000`
3. Default login credentials:
   - Username: `admin`
   - Password: `admin123`
   
⚠️ **Important**: Change the default password after first login!

## Step 5: Start Analyzing Logs

The tool will automatically start collecting logs from configured sources. To add new log sources:

1. Go to Settings → Log Sources in the dashboard
2. Click "Add New Source"
3. Follow the wizard to configure your log source

## Common Commands

Here are some useful commands you might need:

```bash
# View logs from all services
docker-compose logs

# View logs from a specific service
docker-compose logs analyzer
docker-compose logs dashboard
docker-compose logs collector

# Stop all services
docker-compose down

# Restart all services
docker-compose restart

# Update to latest version
git pull
docker-compose down
docker-compose up -d --build
```

## Troubleshooting

If you encounter any issues:

1. **Services won't start:**
   ```bash
   # Try rebuilding the containers
   docker-compose down
   docker-compose build --no-cache
   docker-compose up -d
   ```

2. **Dashboard not accessible:**
   ```bash
   # Check if all containers are running
   docker-compose ps
   
   # Restart the dashboard container
   docker-compose restart dashboard
   ```

3. **Logs not appearing:**
   ```bash
   # Check collector logs
   docker-compose logs collector
   
   # Verify your config.yaml settings
   ```

## Getting Help

If you need help:
1. Check the logs using `docker-compose logs`
2. Visit our [GitHub Issues](https://github.com/yourusername/security-log-analyzer/issues)
3. Read the [Documentation](https://github.com/yourusername/security-log-analyzer/wiki)

## System Requirements

Minimum requirements:
- 4GB RAM
- 2 CPU cores
- 20GB free disk space
- Docker Engine 20.10 or newer
- Docker Compose V2

## Updating the Tool

To update to the latest version:

```bash
# Pull latest changes
git pull

# Rebuild and restart containers
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

Remember to check the changelog for any breaking changes before updating! 