Résumé du projet "code-keeper"
Ce projet consiste à créer un pipeline DevOps complet pour déployer une application basée sur des microservices. Vous devez mettre en place:

Un système GitLab comme outil de CI/CD
Des pipelines pour l'infrastructure et les applications
Des environnements de staging et production
Des mesures de sécurité tout au long du processus

Architecture de l'application
L'application se compose de trois microservices:

Inventory application: Gère l'inventaire avec sa propre base de données
Billing application: Gère la facturation avec sa base de données et consomme des messages de RabbitMQ
API Gateway: Sert de point d'entrée et redirige les requêtes vers les autres services

Plan d'action détaillé
1. Mise en place de GitLab

Créer un playbook Ansible pour déployer GitLab
Configurer les GitLab Runners pour exécuter les pipelines
Mettre en place l'authentification et les paramètres de base

2. Organisation des repositories

Créer un repository pour chaque microservice (3 repos)
Créer un repository séparé pour l'infrastructure
Configurer les protections de branches

3. Pipeline d'infrastructure (Terraform)

Init: Initialisation de Terraform
Validate: Validation des fichiers de configuration
Plan: Génération du plan d'exécution
Apply to Staging: Déploiement en environnement de staging
Approval: Approbation manuelle
Apply to Production: Déploiement en production

4. Pipeline CI pour chaque microservice

Build: Compilation et packaging
Test: Tests unitaires et d'intégration
Scan: Analyse de sécurité du code
Containerization: Création d'images Docker et push vers un registry

5. Pipeline CD pour chaque microservice

Deploy to Staging: Déploiement en environnement de staging
Approval: Approbation manuelle
Deploy to Production: Déploiement en production

6. Mesures de sécurité à implémenter

Restrictions des déclenchements aux branches protégées
Séparation des credentials du code
Application du principe du moindre privilège
Mise à jour régulière des dépendances et outils

7. Documentation

Créer un README.md complet pour expliquer la solution
Documenter les prérequis, la configuration, l'installation et l'utilisation

Points techniques importants

Infrastructure as Code:

Utiliser Terraform pour provisionner l'infrastructure cloud
Créer des configurations similaires pour staging et production
Stocker l'état Terraform de manière sécurisée


Containerisation:

Créer des Dockerfiles pour chaque microservice
Utiliser un registry pour stocker les images


Automatisation:

Utiliser GitLab CI/CD pour automatiser les pipelines
Configurer les triggers appropriés pour les déploiements automatiques


Sécurité:

Intégrer des outils de scan comme SonarQube ou Snyk
Gérer les secrets de manière sécurisée



Bonuses potentiels

Scanner de sécurité pour l'infrastructure (tfsec)
Intégration d'Infracost pour estimer les coûts
Utilisation de Terragrunt pour faciliter la gestion multi-environnements
Utilisation de votre propre code crud-master

Pour réussir ce projet, je vous recommande de bien comprendre tous les concepts avant de commencer l'implémentation, et de suivre une approche méthodique en commençant par les fondations (GitLab, repositories) avant de passer aux pipelines



# I. Déploiement de GitLab et des Runners avec Ansible
---
- name: Deploy GitLab and GitLab Runners
  hosts: all
  become: yes
  vars:
    gitlab_version: "16.8.1-ce.0"
    gitlab_domain: "gitlab.example.com"
    gitlab_external_url: "https://{{ gitlab_domain }}"
    gitlab_runner_token: "{{ lookup('env', 'GITLAB_RUNNER_TOKEN') }}"

  tasks:
    - name: Update apt cache
      apt:
        update_cache: yes
      when: ansible_os_family == "Debian"

    - name: Install required dependencies
      apt:
        name: "{{ item }}"
        state: present
      loop:
        - curl
        - openssh-server
        - ca-certificates
        - tzdata
        - perl
        - postfix
      when: ansible_os_family == "Debian"

    - name: Add GitLab repository
      shell: |
        curl -sS https://packages.gitlab.com/install/repositories/gitlab/gitlab-ce/script.deb.sh | bash
      args:
        creates: /etc/apt/sources.list.d/gitlab_gitlab-ce.list
      when: ansible_os_family == "Debian"

    - name: Install GitLab
      apt:
        name: "gitlab-ce={{ gitlab_version }}"
        state: present
        update_cache: yes
      environment:
        EXTERNAL_URL: "{{ gitlab_external_url }}"
      when: ansible_os_family == "Debian"

    - name: Configure GitLab
      lineinfile:
        path: /etc/gitlab/gitlab.rb
        regexp: "{{ item.regexp }}"
        line: "{{ item.line }}"
        state: present
      loop:
        - { regexp: "^external_url", line: "external_url '{{ gitlab_external_url }}'" }
        - { regexp: "^gitlab_rails\\['gitlab_shell_ssh_port'\\]", line: "gitlab_rails['gitlab_shell_ssh_port'] = 22" }
      notify: Reconfigure GitLab

    # Install and configure GitLab Runners
    - name: Add GitLab Runner repository
      shell: |
        curl -L https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.deb.sh | bash
      args:
        creates: /etc/apt/sources.list.d/runner_gitlab-runner.list
      when: ansible_os_family == "Debian"

    - name: Install GitLab Runner
      apt:
        name: gitlab-runner
        state: present
        update_cache: yes
      when: ansible_os_family == "Debian"

    - name: Register GitLab Runner
      shell: |
        gitlab-runner register \
          --non-interactive \
          --url "{{ gitlab_external_url }}" \
          --registration-token "{{ gitlab_runner_token }}" \
          --executor "docker" \
          --docker-image alpine:latest \
          --description "docker-runner" \
          --tag-list "docker,aws,terraform,ansible" \
          --run-untagged="true" \
          --locked="false"
      args:
        creates: /etc/gitlab-runner/config.toml

    # Security hardening
    - name: Set proper permissions for GitLab configuration
      file:
        path: /etc/gitlab
        owner: root
        group: root
        mode: '0700'
        state: directory
        recurse: yes

    - name: Set up firewall (UFW)
      ufw:
        rule: allow
        port: "{{ item }}"
        proto: tcp
      loop:
        - 22    # SSH
        - 80    # HTTP
        - 443   # HTTPS
      when: ansible_os_family == "Debian"

    - name: Enable UFW
      ufw:
        state: enabled
      when: ansible_os_family == "Debian"

  handlers:
    - name: Reconfigure GitLab
      command: gitlab-ctl reconfigure


# II. Structure des repositories

flowchart TB
    subgraph "Infrastructure Repository"
        TF[Terraform Code]
        INF_P[Infrastructure Pipeline]
        TF --> INF_P
    end
    
    subgraph "Inventory App Repository"
        INV_C[Inventory Code]
        INV_P[CI/CD Pipeline]
        INV_C --> INV_P
    end
    
    subgraph "Billing App Repository"
        BIL_C[Billing Code]
        BIL_P[CI/CD Pipeline]
        BIL_C --> BIL_P
    end
    
    subgraph "API Gateway Repository"
        API_C[API Gateway Code]
        API_P[CI/CD Pipeline]
        API_C --> API_P
    end
    
    INF_P -- "Provision" --> STAG[Staging Environment]
    INF_P -- "Provision" --> PROD[Production Environment]
    
    INV_P -- "Deploy" --> STAG
    INV_P -- "Deploy" --> PROD
    
    BIL_P -- "Deploy" --> STAG
    BIL_P -- "Deploy" --> PROD
    
    API_P -- "Deploy" --> STAG
    API_P -- "Deploy" --> PROD



# III. Infrastructure avec Terraform

# 1. Terraform Infrastructure (main.tf)
provider "aws" {
  region = var.aws_region
}

# Backend configuration for remote state
terraform {
  backend "s3" {
    bucket         = "microservices-terraform-state"
    key            = "terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-lock"
  }
}

# Create VPC for our environments
module "vpc" {
  source = "./modules/vpc"
  
  environment = var.environment
  vpc_cidr    = var.vpc_cidr
  azs         = var.availability_zones
}

# Security groups
module "security_groups" {
  source = "./modules/security"
  
  vpc_id      = module.vpc.vpc_id
  environment = var.environment
}

# Database instances for services
module "databases" {
  source = "./modules/databases"
  
  environment            = var.environment
  vpc_id                 = module.vpc.vpc_id
  subnet_ids             = module.vpc.private_subnet_ids
  db_security_group_id   = module.security_groups.db_security_group_id
  inventory_db_username  = var.inventory_db_username
  inventory_db_password  = var.inventory_db_password
  billing_db_username    = var.billing_db_username
  billing_db_password    = var.billing_db_password
}

# Message queue (RabbitMQ)
module "message_queue" {
  source = "./modules/rabbitmq"
  
  environment          = var.environment
  vpc_id               = module.vpc.vpc_id
  subnet_ids           = module.vpc.private_subnet_ids
  security_group_id    = module.security_groups.rabbitmq_security_group_id
}

# EC2 instances for our services
module "compute" {
  source = "./modules/compute"
  
  environment                     = var.environment
  vpc_id                          = module.vpc.vpc_id
  public_subnet_ids               = module.vpc.public_subnet_ids
  app_security_group_id           = module.security_groups.app_security_group_id
  api_gateway_security_group_id   = module.security_groups.api_gateway_security_group_id
  inventory_db_endpoint           = module.databases.inventory_db_endpoint
  billing_db_endpoint             = module.databases.billing_db_endpoint
  rabbitmq_endpoint               = module.message_queue.rabbitmq_endpoint
  inventory_app_version           = var.inventory_app_version
  billing_app_version             = var.billing_app_version
  api_gateway_app_version         = var.api_gateway_app_version
}

# Load balancers
module "load_balancers" {
  source = "./modules/load_balancers"
  
  environment                   = var.environment
  vpc_id                        = module.vpc.vpc_id
  public_subnet_ids             = module.vpc.public_subnet_ids
  api_gateway_instance_id       = module.compute.api_gateway_instance_id
  inventory_app_instance_id     = module.compute.inventory_app_instance_id
  billing_app_instance_id       = module.compute.billing_app_instance_id
  lb_security_group_id          = module.security_groups.lb_security_group_id
}


# 2. Terraform Variables (variables.tf)
variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (staging or production)"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "Availability zones to use for the subnets"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

variable "inventory_db_username" {
  description = "Username for inventory database"
  type        = string
  sensitive   = true
}

variable "inventory_db_password" {
  description = "Password for inventory database"
  type        = string
  sensitive   = true
}

variable "billing_db_username" {
  description = "Username for billing database"
  type        = string
  sensitive   = true
}

variable "billing_db_password" {
  description = "Password for billing database"
  type        = string
  sensitive   = true
}

variable "inventory_app_version" {
  description = "Docker image version for inventory app"
  type        = string
  default     = "latest"
}

variable "billing_app_version" {
  description = "Docker image version for billing app"
  type        = string
  default     = "latest"
}

variable "api_gateway_app_version" {
  description = "Docker image version for API gateway"
  type        = string
  default     = "latest"
}



# 3. Terragrunt Configuration (terragrunt.hcl)
# Root terragrunt.hcl file
remote_state {
  backend = "s3"
  generate = {
    path      = "backend.tf"
    if_exists = "overwrite_terragrunt"
  }
  config = {
    bucket         = "microservices-terraform-state"
    key            = "${path_relative_to_include()}/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-lock"
  }
}

# Generate provider config
generate "provider" {
  path      = "provider.tf"
  if_exists = "overwrite_terragrunt"
  contents  = <<EOF
provider "aws" {
  region = "us-east-1"
}
EOF
}

# Inputs to be inherited by all child configurations
inputs = {
  aws_region = "us-east-1"
}


### Terraform Environment Configuration
# staging/terragrunt.hcl
include {
  path = find_in_parent_folders()
}

inputs = {
  environment = "staging"
  vpc_cidr    = "10.0.0.0/16"
  
  inventory_db_username = "inventory_user"
  inventory_db_password = "get_from_parameter_store"
  
  billing_db_username = "billing_user"
  billing_db_password = "get_from_parameter_store"
  
  inventory_app_version = "latest"
  billing_app_version   = "latest"
  api_gateway_app_version = "latest"
}

# production/terragrunt.hcl
include {
  path = find_in_parent_folders()
}

inputs = {
  environment = "production"
  vpc_cidr    = "10.1.0.0/16"
  
  inventory_db_username = "inventory_user"
  inventory_db_password = "get_from_parameter_store"
  
  billing_db_username = "billing_user"
  billing_db_password = "get_from_parameter_store"
  
  inventory_app_version = "stable"
  billing_app_version   = "stable"
  api_gateway_app_version = "stable"
}



# IV. Pipelines CI/CD pour l'infrastructure et les microservices

# 1. Pipeline CI/CD pour l'infrastructure (.gitlab-ci.yml)
image: hashicorp/terraform:1.7.1

variables:
  TF_VAR_inventory_db_username: ${INVENTORY_DB_USERNAME}
  TF_VAR_inventory_db_password: ${INVENTORY_DB_PASSWORD}
  TF_VAR_billing_db_username: ${BILLING_DB_USERNAME}
  TF_VAR_billing_db_password: ${BILLING_DB_PASSWORD}
  TERRAGRUNT_VERSION: "0.53.5"

stages:
  - init
  - validate
  - plan
  - apply-staging
  - approval
  - apply-production
  - security

before_script:
  # Install Terragrunt
  - wget -q -O /tmp/terragrunt "https://github.com/gruntwork-io/terragrunt/releases/download/v${TERRAGRUNT_VERSION}/terragrunt_linux_amd64"
  - chmod +x /tmp/terragrunt
  - mv /tmp/terragrunt /usr/local/bin/terragrunt
  # Install AWS CLI
  - apk add --no-cache aws-cli
  # Configure AWS credentials from GitLab CI/CD variables
  - aws configure set aws_access_key_id $AWS_ACCESS_KEY_ID
  - aws configure set aws_secret_access_key $AWS_SECRET_ACCESS_KEY
  - aws configure set region $AWS_DEFAULT_REGION

init:
  stage: init
  script:
    - cd terraform
    - terragrunt init
  artifacts:
    paths:
      - terraform/.terraform
    expire_in: 1 hour

validate:
  stage: validate
  script:
    - cd terraform
    - terragrunt validate
    - terragrunt fmt -check
  dependencies:
    - init

plan-staging:
  stage: plan
  script:
    - cd terraform/staging
    - terragrunt plan -out=tfplan
  dependencies:
    - validate
  artifacts:
    paths:
      - terraform/staging/tfplan
    expire_in: 1 hour

plan-production:
  stage: plan
  script:
    - cd terraform/production
    - terragrunt plan -out=tfplan
  dependencies:
    - validate
  artifacts:
    paths:
      - terraform/production/tfplan
    expire_in: 1 hour

apply-staging:
  stage: apply-staging
  script:
    - cd terraform/staging
    - terragrunt apply -auto-approve tfplan
  dependencies:
    - plan-staging
  environment:
    name: staging
  only:
    - main

approval-production:
  stage: approval
  script:
    - echo "Approval required for deployment to production"
  dependencies:
    - plan-production
  environment:
    name: production
    on_stop: apply-production
  when: manual
  only:
    - main

apply-production:
  stage: apply-production
  script:
    - cd terraform/production
    - terragrunt apply -auto-approve tfplan
  dependencies:
    - approval-production
  environment:
    name: production
  only:
    - main
  when: manual

security-scan:
  stage: security
  image: aquasec/tfsec:latest
  script:
    - tfsec terraform --no-color
  dependencies: []
  allow_failure: true
  only:
    - main
    - merge_requests

cost-estimate:
  stage: security
  image: infracost/infracost:latest
  script:
    - infracost breakdown --path terraform/staging --format json --out-file infracost-staging.json
    - infracost breakdown --path terraform/production --format json --out-file infracost-production.json
    - infracost output --path infracost-staging.json --format html --out-file infracost-staging.html
    - infracost output --path infracost-production.json --format html --out-file infracost-production.html
  artifacts:
    paths:
      - infracost-staging.html
      - infracost-production.html
    expire_in: 1 week
  allow_failure: true
  only:
    - main
    - merge_requests


# 2. Pipeline CI/CD pour les microservices (.gitlab-ci.yml)
# Base image for all jobs
image: docker:latest

stages:
  - build
  - test
  - scan
  - containerize
  - deploy-staging
  - approval
  - deploy-production

variables:
  # Docker settings
  DOCKER_DRIVER: overlay2
  DOCKER_HOST: tcp://docker:2375
  DOCKER_TLS_CERTDIR: ""
  # Application settings
  APP_NAME: ${CI_PROJECT_NAME}
  # AWS ECR settings
  AWS_ECR_REGISTRY: ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com
  AWS_ECR_REPOSITORY: ${APP_NAME}
  # Environment variables
  STAGING_ENV: staging
  PRODUCTION_ENV: production

.before_script_template: &before_script_def
  before_script:
    - apk add --no-cache curl python3 py3-pip
    - pip3 install awscli
    - aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${AWS_ECR_REGISTRY}

# Build phase
build:
  stage: build
  services:
    - docker:dind
  script:
    - docker build -t ${APP_NAME}:${CI_COMMIT_SHORT_SHA} --target build .
  only:
    - main
    - merge_requests

# Test phase
test:
  stage: test
  services:
    - docker:dind
  script:
    - docker build -t ${APP_NAME}:${CI_COMMIT_SHORT_SHA} --target test .
    - docker run --rm ${APP_NAME}:${CI_COMMIT_SHORT_SHA} npm test
  artifacts:
    paths:
      - coverage/
    expire_in: 1 week
  only:
    - main
    - merge_requests

# Security scan
code-scan:
  stage: scan
  image: sonarsource/sonar-scanner-cli
  script:
    - sonar-scanner -Dsonar.projectKey=${APP_NAME} -Dsonar.sources=. -Dsonar.host.url=${SONAR_HOST_URL} -Dsonar.login=${SONAR_TOKEN}
  only:
    - main
    - merge_requests

dependency-scan:
  stage: scan
  image: node:lts-alpine
  script:
    - npm install -g snyk
    - snyk auth ${SNYK_TOKEN}
    - snyk test --all-projects
  allow_failure: true
  only:
    - main
    - merge_requests

# Containerization phase
containerize:
  stage: containerize
  services:
    - docker:dind
  <<: *before_script_def
  script:
    - docker build -t ${APP_NAME}:${CI_COMMIT_SHORT_SHA} .
    - docker tag ${APP_NAME}:${CI_COMMIT_SHORT_SHA} ${AWS_ECR_REGISTRY}/${AWS_ECR_REPOSITORY}:${CI_COMMIT_SHORT_SHA}
    - docker tag ${APP_NAME}:${CI_COMMIT_SHORT_SHA} ${AWS_ECR_REGISTRY}/${AWS_ECR_REPOSITORY}:latest
    - docker push ${AWS_ECR_REGISTRY}/${AWS_ECR_REPOSITORY}:${CI_COMMIT_SHORT_SHA}
    - docker push ${AWS_ECR_REGISTRY}/${AWS_ECR_REPOSITORY}:latest
  only:
    - main

# Deploy to staging environment
deploy-staging:
  stage: deploy-staging
  image: alpine:latest
  <<: *before_script_def
  script:
    - apk add --no-cache openssh-client
    - mkdir -p ~/.ssh
    - echo "$SSH_PRIVATE_KEY" > ~/.ssh/id_rsa
    - chmod 600 ~/.ssh/id_rsa
    - ssh-keyscan -H ${STAGING_HOST} >> ~/.ssh/known_hosts
    - ssh ${SSH_USER}@${STAGING_HOST} "docker pull ${AWS_ECR_REGISTRY}/${AWS_ECR_REPOSITORY}:${CI_COMMIT_SHORT_SHA} && docker-compose -f docker-compose.yml down && docker-compose -f docker-compose.yml up -d"
  environment:
    name: staging
    url: https://${STAGING_HOST}
  only:
    - main

# Approval for production deployment
approval-production:
  stage: approval
  script:
    - echo "Waiting for approval to deploy to production"
  environment:
    name: production
    on_stop: deploy-production
  when: manual
  only:
    - main

# Deploy to production environment
deploy-production:
  stage: deploy-production
  image: alpine:latest
  <<: *before_script_def
  script:
    - apk add --no-cache openssh-client
    - mkdir -p ~/.ssh
    - echo "$SSH_PRIVATE_KEY" > ~/.ssh/id_rsa
    - chmod 600 ~/.ssh/id_rsa
    - ssh-keyscan -H ${PRODUCTION_HOST} >> ~/.ssh/known_hosts
    - ssh ${SSH_USER}@${PRODUCTION_HOST} "docker pull ${AWS_ECR_REGISTRY}/${AWS_ECR_REPOSITORY}:${CI_COMMIT_SHORT_SHA} && docker-compose -f docker-compose.yml down && docker-compose -f docker-compose.yml up -d"
  environment:
    name: production
    url: https://${PRODUCTION_HOST}
  when: manual
  dependencies:
    - approval-production
  only:
    - main


# 3. Dockerfile pour les microservices

# Multi-stage build for Node.js application

# Stage 1: Build
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Stage 2: Test
FROM build AS test
RUN npm test

# Stage 3: Production
FROM node:20-alpine AS production
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/package*.json ./
RUN npm ci --production
COPY --from=build /app/dist ./dist
COPY --from=build /app/node_modules ./node_modules

# Application configuration
COPY config/config.js ./config/
COPY .env.example ./.env

# Security measures
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
  CMD wget -q --spider http://localhost:3000/health || exit 1

# Set the entrypoint
ENTRYPOINT ["node", "dist/main.js"]



# V. Configuration de l'API Gateway (nginx.conf)

# API Gateway configuration using Nginx

user  nginx;
worker_processes  auto;

error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;

events {
    worker_connections  1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    keepalive_timeout  65;

    # GZIP Configuration
    gzip  on;
    gzip_comp_level 5;
    gzip_min_length 256;
    gzip_proxied any;
    gzip_vary on;
    gzip_types
        application/atom+xml
        application/javascript
        application/json
        application/ld+json
        application/manifest+json
        application/rss+xml
        application/vnd.geo+json
        application/vnd.ms-fontobject
        application/x-font-ttf
        application/x-web-app-manifest+json
        application/xhtml+xml
        application/xml
        font/opentype
        image/bmp
        image/svg+xml
        image/x-icon
        text/cache-manifest
        text/css
        text/plain
        text/vcard
        text/vnd.rim.location.xloc
        text/vtt
        text/x-component
        text/x-cross-domain-policy;

    # Security headers
    server_tokens off;
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; img-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'";
    add_header Referrer-Policy "no-referrer-when-downgrade";

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

    # Upstreams
    upstream inventory-service {
        server inventory-app:3000;
    }

    upstream billing-service {
        server billing-app:3000;
    }

    server {
        listen 80;
        server_name api-gateway;

        # Redirect to HTTPS
        location / {
            return 301 https://$host$request_uri;
        }
    }

    server {
        listen 443 ssl http2;
        server_name api-gateway;

        # SSL configuration
        ssl_certificate /etc/nginx/ssl/server.crt;
        ssl_certificate_key /etc/nginx/ssl/server.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_prefer_server_ciphers on;
        ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 10m;
        ssl_session_tickets off;

        # Root path
        location / {
            root   /usr/share/nginx/html;
            index  index.html;
        }

        # Inventory service
        location /api/inventory/ {
            limit_req zone=api burst=20 nodelay;
            proxy_pass http://inventory-service/;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_cache_bypass $http_upgrade;
        }

        # Billing service
        location /api/billing/ {
            limit_req zone=api burst=20 nodelay;
            proxy_pass http://billing-service/;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_cache_bypass $http_upgrade;
        }

        # Health check endpoint
        location /health {
            access_log off;
            return 200 '{"status":"UP"}';
            add_header Content-Type application/json;
        }

        # Handle errors
        error_page 404 /404.html;
        location = /404.html {
            root /usr/share/nginx/html;
        }

        error_page 500 502 503 504 /50x.html;
        location = /50x.html {
            root /usr/share/nginx/html;
        }
    }
}



# VI. Docker Compose pour l'environnement local de développement

version: '3.8'

services:
  # API Gateway
  api-gateway:
    build:
      context: ./api-gateway
      dockerfile: Dockerfile
    ports:
      - "80:80"
      - "443:443"
    depends_on:
      - inventory-app
      - billing-app
    volumes:
      - ./api-gateway/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./api-gateway/ssl:/etc/nginx/ssl:ro
    networks:
      - frontend
      - backend
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s

  # Inventory Application
  inventory-app:
    build:
      context: ./inventory-app
      dockerfile: Dockerfile
    environment:
      - NODE_ENV=development
      - DB_HOST=inventory-db
      - DB_PORT=5432
      - DB_NAME=inventory
      - DB_USER=${INVENTORY_DB_USER}
      - DB_PASSWORD=${INVENTORY_DB_PASSWORD}
    depends_on:
      - inventory-db
    networks:
      - backend
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s

  # Billing Application  
  billing-app:
    build:
      context: ./billing-app
      dockerfile: Dockerfile
    environment:
      - NODE_ENV=development
      - DB_HOST=billing-db
      - DB_PORT=5432
      - DB_NAME=billing
      - DB_USER=${BILLING_DB_USER}
      - DB_PASSWORD=${BILLING_DB_PASSWORD}
      - RABBITMQ_HOST=rabbitmq
      - RABBITMQ_PORT=5672
      - RABBITMQ_USER=${RABBITMQ_USER}
      - RABBITMQ_PASSWORD=${RABBITMQ_PASSWORD}
    depends_on:
      - billing-db
      - rabbitmq
    networks:
      - backend
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s

  # Inventory Database
  inventory-db:
    image: postgres:16-alpine
    environment:
      - POSTGRES_DB=inventory
      - POSTGRES_USER=${INVENTORY_DB_USER}
      - POSTGRES_PASSWORD=${INVENTORY_DB_PASSWORD}
    volumes:
      - inventory-db-data:/var/lib/postgresql/data
    networks:
      - backend
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${INVENTORY_DB_USER} -d inventory"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s

  # Billing Database
  billing-db:
    image: postgres:16-alpine
    environment:
      - POSTGRES_DB=billing
      - POSTGRES_USER=${BILLING_DB_USER}
      - POSTGRES_PASSWORD=${BILLING_DB_PASSWORD}
    volumes:
      - billing-db-data:/var/lib/postgresql/data
    networks:
      - backend
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${BILLING_DB_USER} -d billing"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s

  # RabbitMQ
  rabbitmq:
    image: rabbitmq:3-management-alpine
    environment:
      - RABBITMQ_DEFAULT_USER=${RABBITMQ_USER}
      - RABBITMQ_DEFAULT_PASS=${RABBITMQ_PASSWORD}
    ports:
      - "15672:15672"  # Management UI
    volumes:
      - rabbitmq-data:/var/lib/rabbitmq
    networks:
      - backend
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "rabbitmq-diagnostics", "-q", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s

volumes:
  inventory-db-data:
  billing-db-data:
  rabbitmq-data:

networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge


# VII. readme.md


# VIII. Exemple de module Terraform pour les VPC

# 1. Module Terraform pour VPC
# modules/vpc/main.tf

# Create VPC
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name        = "${var.environment}-vpc"
    Environment = var.environment
  }
}

# Create Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name        = "${var.environment}-igw"
    Environment = var.environment
  }
}

# Create public subnets
resource "aws_subnet" "public" {
  count                   = length(var.azs)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = var.azs[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name        = "${var.environment}-public-subnet-${count.index + 1}"
    Environment = var.environment
    Type        = "Public"
  }
}

# Create private subnets
resource "aws_subnet" "private" {
  count             = length(var.azs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + length(var.azs))
  availability_zone = var.azs[count.index]

  tags = {
    Name        = "${var.environment}-private-subnet-${count.index + 1}"
    Environment = var.environment
    Type        = "Private"
  }
}

# Create NAT Gateway for private subnets
resource "aws_eip" "nat" {
  domain = "vpc"

  tags = {
    Name        = "${var.environment}-nat-eip"
    Environment = var.environment
  }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    Name        = "${var.environment}-nat-gw"
    Environment = var.environment
  }

  depends_on = [aws_internet_gateway.main]
}

# Create route table for public subnets
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name        = "${var.environment}-public-rt"
    Environment = var.environment
  }
}

# Create route table for private subnets
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name        = "${var.environment}-private-rt"
    Environment = var.environment
  }
}

# Add route to public route table for internet gateway
resource "aws_route" "public_internet_gateway" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main.id
}

# Add route to private route table for NAT gateway
resource "aws_route" "private_nat_gateway" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main.id
}

# Associate public subnets with public route table
resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Associate private subnets with private route table
resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# Security group for VPC endpoints
resource "aws_security_group" "vpc_endpoints" {
  name        = "${var.environment}-vpc-endpoints-sg"
  description = "Security group for VPC endpoints"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = {
    Name        = "${var.environment}-vpc-endpoints-sg"
    Environment = var.environment
  }
}

# VPC Endpoints for S3 and DynamoDB
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id, aws_route_table.public.id]

  tags = {
    Name        = "${var.environment}-s3-endpoint"
    Environment = var.environment
  }
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id, aws_route_table.public.id]

  tags = {
    Name        = "${var.environment}-dynamodb-endpoint"
    Environment = var.environment
  }
}

# 2. Variables pour le module VPC
# modules/vpc/variables.tf

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
}

variable "environment" {
  description = "Environment name (staging or production)"
  type        = string
}

variable "azs" {
  description = "Availability zones to use"
  type        = list(string)
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}


# 3. Outputs pour le module VPC
# modules/vpc/outputs.tf

output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "public_subnet_ids" {
  description = "IDs of public subnets"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "IDs of private subnets"
  value       = aws_subnet.private[*].id
}

output "nat_gateway_ip" {
  description = "Public IP of the NAT Gateway"
  value       = aws_eip.nat.public_ip
}

output "vpc_cidr" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.main.cidr_block
}

output "public_route_table_id" {
  description = "ID of the public route table"
  value       = aws_route_table.public.id
}

output "private_route_table_id" {
  description = "ID of the private route table"
  value       = aws_route_table.private.id
}