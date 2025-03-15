# CODE-KEEPER
# français:
Objectif
Dans ce projet, vous créerez un pipeline complet pour analyser et déployer une application basée sur des microservices. Votre défi consiste à concevoir, mettre en œuvre et optimiser un pipeline intégrant les meilleures pratiques du secteur en matière d'intégration et de déploiement continus, ainsi que de sécurité. Votre mission est la suivante :

Mettre en place un système de contrôle de source pour le code source des microservices et la configuration de l’infrastructure.
Créez un pipeline vers create, update, ou deletel’infrastructure pour l’environnement de préparation et de production.
Créez un continuous integration (CI)pipeline pour créer, tester et analyser le code source.
Créez un continuous deployment (CD)pipeline pour déployer l’application dans un environnement de préparation et de production.
Assurer le securitybon déroulement reliabilityde l'application tout au long des étapes du pipeline.
Prérequis
Pour mener à bien ce projet, vous devez avoir une bonne compréhension des éléments suivants :

GitLab et GitLab CI
Ansible comme outil de gestion de configuration et d'automatisation
Docker et la conteneurisation
Terraform en tant qu'infrastructure en tant que code (IaC)
Plateformes cloud (par exemple, AWS, Azure ou Google Cloud)
Conseils
Passez du temps sur la théorie avant de vous précipiter dans la pratique.
Lisez la documentation officielle.
Tout manque de compréhension des concepts de ce projet peut affecter la difficulté des projets futurs, prenez votre temps pour comprendre tous les concepts.

Soyez curieux et n’arrêtez jamais de chercher !

Jeu de rôle
Afin d'améliorer l'expérience d'apprentissage et d'évaluer les connaissances des étudiants sur les concepts et pratiques DevOps, nous inclurons une séance de questions-réponses sous forme de jeux de rôle dans le cadre du projet. Cet exercice demandera aux étudiants d'appliquer leurs connaissances à divers scénarios réels, les aidant ainsi à consolider leur compréhension du sujet et à se préparer à des situations concrètes.

L'objectif de la séance de questions de jeu de rôle est de :

Évaluez votre compréhension des concepts et des technologies utilisés dans le projet.
Testez votre capacité à communiquer efficacement et à expliquer vos décisions.
Je vous mets au défi de réfléchir de manière critique à votre solution et d’envisager des approches alternatives.
Préparez-vous à une séance de questions-réponses où vous incarnerez un ingénieur DevOps présentant votre solution à votre équipe ou à une partie prenante. Soyez prêt à répondre aux questions et à fournir des explications sur vos décisions, votre architecture et votre implémentation.

Déployer GitLab et les exécuteurs pour l'exécution du pipeline
Vous devez déployer une GitLabinstance à l'aide de Ansible. Cet exercice pratique vous permettra de mieux comprendre .NET Framework Ansibleen tant qu'outil de gestion et d'automatisation de la configuration, tout en vous permettant d'acquérir de l'expérience dans le déploiement et la configuration de GitLab.

Créez un Ansibleplaybook pour déployer et configurer une GitLabinstance. Ce playbook doit automatiser l'installation GitLabet les dépendances requises. Il doit également configurer GitLabdes paramètres tels que l'authentification des utilisateurs, les paramètres du projet et les paramètres CI/CD.

Déployez une GitLabinstance sur une plateforme cloud (par exemple, AWS, Azure ou Google Cloud) ou dans un environnement local à l'aide du Ansibleplaybook. Assurez-vous que l'instance est accessible à tous les membres de l'équipe et configurée pour prendre en charge la collaboration et les revues de code.

Configurez l' GitLabinstance à prendre en charge CI/CD pipelinesen configurant GitLabdes exécuteurs et en les intégrant à votre pipeline existant. Mettez à jour la configuration de votre pipeline pour utiliser GitLab CI/CDles fonctionnalités et exécuter des tâches sur les exécuteurs déployés.

Vous devrez démontrer le déploiement et la configuration réussis de GitLabl'utilisation Ansibledans l'audit.

Les pipelines
Vous êtes ingénieur DevOps dans une entreprise en transition vers une approche Agile et souhaitez atteindre un haut niveau de livraison pour son architecture de microservices. En tant qu'ingénieur DevOps, votre responsable vous a confié la création d'un pipeline prenant en charge les méthodologies Agile et permettant des déploiements de microservices plus rapides et plus cohérents.

gardien du code

Utilisez le crud-mastercode source fourni et votre cloud-designinfrastructure cloud-kubepour créer un pipeline complet pour les applications suivantes :
Inventory applicationest un serveur qui contient votre code d'application d'inventaire en cours d'exécution et connecté à la base de données d'inventaire.
billing applicationest un serveur qui contient votre code d'application de facturation en cours d'exécution et connecté à la base de données de facturation et consommant les messages de la file d'attente RabbitMQ.
api-gateway applicationest un serveur qui contient votre code de passerelle API exécutant et transmettant les requêtes aux autres services.
Chaque application doit exister dans un référentiel unique.

Vous devez provisionner votre cloud-designinfrastructure cloud-kubepour deux environnements sur une plateforme cloud (par exemple, AWS, Azure ou Google Cloud) à l'aide de Terraform.
Production Environment:L'infrastructure en direct où le logiciel est déployé et utilisé par les utilisateurs finaux nécessite des mises à jour stables et soigneusement testées pour garantir des performances et des fonctionnalités optimales.

Staging Environment:Une réplique de l'environnement de production utilisée pour tester et valider les mises à jour logicielles dans un environnement contrôlé avant le déploiement sur le système en direct.

Les deux environnements doivent être similaires en termes de conception, de ressources et de services utilisés ! Votre configuration d'infrastructure doit exister dans un référentiel indépendant avec un pipeline configuré !

Le pipeline devrait comprendre les étapes suivantes :

InitInitialisez le répertoire de travail et le backend de Terraform. Cette tâche télécharge les plugins du fournisseur requis et configure le backend pour le stockage de l'état de Terraform.

ValidateValidez les fichiers de configuration Terraform pour garantir une syntaxe correcte et le respect des bonnes pratiques. Cela permet de détecter les problèmes dès le début du processus.

PlanGénérez un plan d'exécution indiquant les modifications à apporter à votre infrastructure, y compris les ressources à créer, mettre à jour ou supprimer. Cette tâche fournit un aperçu des modifications et vous permet de les consulter avant de les appliquer.

Apply to Staging: Appliquez la configuration Terraform à create, update, ou deleteaux ressources spécifiées dans le plan d'exécution. Cette tâche provisionne et modifie l'infrastructure dans l'environnement de préparation.

Approval: Nécessite une approbation manuelle pour procéder au déploiement sur le production environment. Cette étape doit impliquer les parties prenantes et garantir que l'application est prête pour la production.

Apply to Production: Appliquez la configuration Terraform à create, update, ou deleteaux ressources spécifiées dans le plan d'exécution. Cette tâche provisionne et modifie l'infrastructure dans l'environnement de production.

Concevez et implémentez un pipeline CI pipelinepour chaque dépôt, qui sera déclenché à chaque demande de code (push ou pull). Ce pipeline doit comprendre les étapes suivantes :
Build: Compilez et empaquetez l'application.
Test:Exécutez des tests unitaires et d’intégration pour garantir la qualité et la fonctionnalité du code.
Scan: Analysez le code source et ses dépendances pour détecter les failles de sécurité et les problèmes de codage. Pensez à utiliser des outils tels que SonarQube, Snyk, ou WhiteSource.
Containerization: Empaquetez les applications dans des images Docker à l'aide d'un Dockerfile et envoyez les images vers un registre de conteneurs (par exemple, Docker Hub, Google Container Registry ou AWS ECR).
Concevoir et mettre en œuvre un CD pipelinepipeline qui sera déclenché une fois CI pipelineterminé. Ce pipeline doit comprendre les étapes suivantes :
Deploy to Staging: Déployez l'application sur un serveur staging environmentpour des tests et une validation supplémentaires.
Approval: Nécessite une approbation manuelle pour procéder au déploiement sur le production environment. Cette étape doit impliquer les parties prenantes et garantir que l'application est prête pour la production.
Deploy to Production: Déployez l'application sur le production environment, en garantissant un temps d'arrêt nul et un déploiement fluide.
Chaque dépôt doit avoir un pipeline !

Toute modification dans le code source de l'application doit reconstruire et redéployer la nouvelle version sur le Staging Environmentpuis sur le Production Environmentaprès approbation manuelle.

Cybersécurité
Vos pipelines et votre infrastructure doivent respecter les directives de cybersécurité suivantes :

Restrict triggers to protected branches: Empêchez les utilisateurs non autorisés de déployer ou de falsifier en déclenchant des pipelines uniquement sur les branches protégées, en contrôlant l'accès et en minimisant les risques.

Separate credentials from codeÉvitez de stocker les informations d'identification dans le code de l'application ou dans les fichiers d'infrastructure. Utilisez des méthodes sécurisées, comme des outils de gestion des secrets ou des variables d'environnement, pour éviter toute exposition ou tout accès non autorisé.

Apply the least privilege principle: Limitez l'accès des utilisateurs et des services au minimum requis, réduisant ainsi les dommages potentiels en cas de violation ou de compromission des informations d'identification.

Update dependencies and tools regularlyMinimisez les vulnérabilités de sécurité en maintenant à jour les dépendances et les outils de pipeline. Automatisez les mises à jour et surveillez les avis de sécurité et les correctifs.

Documentation
Vous devez pousser un README.mdfichier contenant la documentation complète de votre solution (prérequis, configuration, installation, utilisation, ...).

Prime
Si vous terminez avec succès la partie obligatoire et qu'il vous reste du temps libre, vous pouvez mettre en œuvre tout ce qui, selon vous, mérite d'être un bonus, par exemple :

Analyse de sécurité pour la configuration de l'infrastructure à l'aide de tfsec.
Ajoutez Infracostvotre pipeline d’infrastructure pour estimer le coût de l’infrastructure.
Utiliser Terragruntpour créer plusieurs environnements.
Utilisez votre propre crud-mastercode source.
Relevez le défi !

Soumission et audit
Vous devez soumettre :

Fichiers de configuration du pipeline CI/CD, scripts et tout autre artefact requis.
Un playbook Ansible et des scripts utilisés pour déployer et configurer une instance GitLab.
Un fichier README bien documenté qui explique la conception du pipeline, les outils utilisés et comment configurer et utiliser le pipeline.
Votre solution doit être en cours d’exécution et votre référentiel d’utilisateurs et d’applications ainsi que CI/CD doivent être correctement configurés pour la session d’audit.

Lors de l'audit, différentes questions vous seront posées sur les concepts et la pratique de ce projet, préparez-vous !

# anglais:
Objective
In this project, you will create a complete pipeline to scan and deploy a microservices-based application. Your challenge is to design, implement, and optimize a pipeline that incorporates industry best practices for continuous integration, continuous deployment, and security. Your mission is to:

Set up a source control system for the microservices source code and the infrastructure configuration.
Create a Pipeline to create, update, or delete the infrastructure for the staging and production environment.
Create a continuous integration (CI) pipeline to build, test, and scan the source code.
Create a continuous deployment (CD) pipeline to deploy the application to a staging and production environment.
Ensure the security and reliability of the application throughout the pipeline stages.
Prerequisites
To complete this project, you should have a good understanding of the following:

GitLab and GitLab CI
Ansible as a configuration management and automation tool
Docker and containerization
Terraform as an Infrastructure as Code (IaC)
Cloud platforms (e.g., AWS, Azure, or Google Cloud)
Tips
Spend time on the theory before rushing into the practice.
Read the official documentation.
Any lack of understanding of the concepts of this project may affect the difficulty of future projects, take your time to understand all concepts.

Be curious and never stop searching!

Role play
To further enhance the learning experience and assess the student's knowledge of DevOps concepts and practices, we will include a role play question session as part of the project. This exercise will require students to apply their knowledge in various real-life scenarios, helping them to solidify their understanding of the material and prepare for real-world situations.

The goal of the role play question session is to:

Assess your understanding of the concepts and technologies used in the project.
Test your ability to communicate effectively and explain your decisions.
Challenge you to think critically about your solution and consider alternative approaches.
Prepare for a role play question session where you will assume the role of a DevOps engineer presenting your solution to your team or a stakeholder. You should be ready to answer questions and provide explanations about your decisions, architecture, and implementation.

Deploy GitLab and Runners for Pipeline Execution
You must deploy a GitLab instance using Ansible. This hands-on exercise will help you gain a deeper understanding of Ansible as a configuration management and automation tool while also giving you experience in deploying and configuring GitLab.

Create an Ansible playbook to deploy and configure a GitLab instance. The playbook should automate the installation of GitLab and any required dependencies. It should also configure GitLab settings such as user authentication, project settings, and CI/CD settings.

Deploy a GitLab instance on a cloud platform (e.g., AWS, Azure, or Google Cloud) or in a local environment using the Ansible playbook. Ensure that the instance is accessible to all team members and is configured to support collaboration and code reviews.

Configure the GitLab instance to support CI/CD pipelines by setting up GitLab Runners and integrating them with your existing pipeline. Update your pipeline configuration to utilize GitLab CI/CD features and execute tasks on the deployed Runners.

You will need to demonstrate the successful deployment and configuration of GitLab using Ansible in the audit.

The pipelines
You are a DevOps engineer at a company that is transitioning to an Agile approach and wants to achieve high delivery for their microservices' architecture. As the DevOps engineer, your manager has tasked you with creating a pipeline that supports Agile methodologies and enables faster, more consistent deployments of the microservices.

code-keeper

Use the provided crud-master source code and your cloud-design or cloud-kube infrastructure, to create a complete pipeline for the following applications:
Inventory application is a server that contains your inventory-app code running and connected to the inventory database.
billing application is a server that contains your billing-app code running and connected to the billing database and consuming the messages from the RabbitMQ queue.
api-gateway application is a server that contains your API gateway code running and forwarding the requests to the other services.
Each application must exist in a single repository.

You must provision your cloud-design or cloud-kube infrastructure for two environments on a cloud platform (e.g., AWS, Azure, or Google Cloud) using Terraform.
Production Environment: The live infrastructure where the software is deployed and used by end-users, requires stable and thoroughly tested updates to ensure optimal performance and functionality.

Staging Environment: A replica of the production environment used for testing and validating software updates in a controlled setting before deployment to the live system.

The two environments should be similar in design, resources, and services used! Your infrastructure configuration must exist in an independent repository with a configured pipeline!

The pipeline should include the following stages:

Init: Initialize the Terraform working directory and backend. This job downloads the required provider plugins and sets up the backend for storing the Terraform state.

Validate: Validate the Terraform configuration files to ensure correct syntax and adherence to best practices. This helps catch any issues early in the pipeline.

Plan: Generate an execution plan that shows the changes to be made to your infrastructure, including the resources that will be created, updated, or deleted. This job provides a preview of the changes and enables you to review them before applying.

Apply to Staging: Apply the Terraform configuration to create, update, or delete the resources as specified in the execution plan. This job provisions and modifies the infrastructure in the staging environment.

Approval: Require manual approval to proceed with deployment to the production environment. This step should involve stakeholders and ensure the application is ready for production.

Apply to Production: Apply the Terraform configuration to create, update, or delete the resources as specified in the execution plan. This job provisions and modifies the infrastructure in the production environment.

Design and implement a CI pipeline for each repository that will be triggered on every code push or pull request. The pipeline should include the following stages:
Build: Compile and package the application.
Test: Run unit and integration tests to ensure code quality and functionality.
Scan: Analyze the source code and dependencies for security vulnerabilities and coding issues. Consider using tools such as SonarQube, Snyk, or WhiteSource.
Containerization: Package the applications into Docker images using a Dockerfile, and push the images to a container registry (e.g., Docker Hub, Google Container Registry, or AWS ECR).
Design and implement a CD pipeline that will be triggered after the CI pipeline has been completed. The pipeline should include the following stages:
Deploy to Staging: Deploy the application to a staging environment for further testing and validation.
Approval: Require manual approval to proceed with deployment to the production environment. This step should involve stakeholders and ensure the application is ready for production.
Deploy to Production: Deploy the application to the production environment, ensuring zero downtime and a smooth rollout.
Each repository must have a pipeline!

Any modification in the application's source code must rebuild and redeploy the new version to the Staging Environment and then to the Production Environment after manual approval.

Cybersecurity
Your pipelines and infrastructure should adhere to the following cybersecurity guidelines:

Restrict triggers to protected branches: Prevent unauthorized users from deploying or tampering by triggering pipelines only on protected branches, controlling access, and minimizing risk.

Separate credentials from code: Avoid storing credentials in application code or infrastructure files. Use secure methods like secret management tools or environment variables to prevent exposure or unauthorized access.

Apply the least privilege principle: Limit user and service access to the minimum required, reducing potential damage in case of breaches or compromised credentials.

Update dependencies and tools regularly: Minimize security vulnerabilities by keeping dependencies and pipeline tools updated. Automate updates and monitor for security advisories and patches.

Documentation
You must push a README.md file containing full documentation of your solution (prerequisites, configuration, setup, usage, ...).

Bonus
If you complete the mandatory part successfully and you still have free time, you can implement anything that you feel deserves to be a bonus, for example:

Security scan for the infrastructure configuration using tfsec.
Add Infracost in your infrastructure pipeline to estimate the infrastructure cost.
Use Terragrunt to create multiple Environments.
Use your own crud-master source code.
Challenge yourself!

Submission and audit
You must submit:

CI/CD pipeline configuration files, scripts, and any other required artifacts.
An Ansible playbook and used scripts for deploying and configuring a GitLab instance.
A well-documented README file that explains the pipeline design, the tools used, and how to set up and use the pipeline.
Your Solution must be running and your users and applications repository and CI/CD must be configured correctly for the audit session.

In the audit you will be asked different questions about the concepts and the practice of this project, prepare yourself!



# Microservices DevOps Pipeline

Ce projet implémente une pipeline DevOps complète pour une architecture microservices. Il comprend la provision d'infrastructure, le CI/CD pour chaque microservice, et les mesures de sécurité appropriées.

## Architecture

L'architecture consiste en trois microservices principaux :
- **API Gateway** : Point d'entrée unique pour toutes les requêtes
- **Inventory App** : Service de gestion des inventaires
- **Billing App** : Service de facturation

Les environnements déployés sont :
- **Staging** : Pour les tests et la validation
- **Production** : Pour le déploiement en production

## Prérequis

- [GitLab](https://about.gitlab.com/)
- [Docker](https://www.docker.com/) et [Docker Compose](https://docs.docker.com/compose/)
- [Terraform](https://www.terraform.io/) (v1.7.0+)
- [Terragrunt](https://terragrunt.gruntwork.io/) (v0.53.0+)
- [Ansible](https://www.ansible.com/) (v2.15+)
- [AWS CLI](https://aws.amazon.com/cli/) configuré avec les permissions appropriées

## Configuration et installation

### 1. Déploiement de GitLab avec Ansible

```bash
# Cloner le repo
git clone https://github.com/your-org/microservices-devops.git
cd microservices-devops

# Installer Ansible
pip install ansible

# Configurer les variables Ansible
export GITLAB_RUNNER_TOKEN=your-token-here

# Exécuter le playbook
ansible-playbook -i inventory.yml ansible/gitlab-deploy.yml
```

### 2. Configuration des repositories

Créez les repositories suivants dans GitLab :
- `infrastructure` : Pour le code Terraform
- `inventory-app` : Pour l'application d'inventaire
- `billing-app` : Pour l'application de facturation
- `api-gateway` : Pour l'API Gateway

### 3. Configuration des variables CI/CD

Configurez les variables suivantes dans GitLab pour chaque projet :

**Variables d'infrastructure :**
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_DEFAULT_REGION`
- `INVENTORY_DB_USERNAME`
- `INVENTORY_DB_PASSWORD`
- `BILLING_DB_USERNAME`
- `BILLING_DB_PASSWORD`

**Variables d'application :**
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_DEFAULT_REGION`
- `AWS_ACCOUNT_ID`
- `SSH_PRIVATE_KEY`
- `SSH_USER`
- `STAGING_HOST`
- `PRODUCTION_HOST`
- `SONAR_HOST_URL`
- `SONAR_TOKEN`
- `SNYK_TOKEN`

### 4. Déploiement de l'infrastructure

```bash
cd infrastructure
terragrunt run-all apply
```

### 5. Lancement des pipelines CI/CD

Poussez votre code vers les branches protégées (`main`) pour déclencher les pipelines CI/CD.

## Flux de travail DevOps

### Flux de l'infrastructure

1. Init : Initialise Terraform
2. Validate : Valide la configuration Terraform
3. Plan : Crée un plan d'exécution
4. Apply to Staging : Déploie les changements dans l'environnement Staging
5. Approval : Attente d'approbation manuelle
6. Apply to Production : Déploie les changements dans l'environnement Production

### Flux des microservices

1. Build : Compile l'application
2. Test : Exécute les tests
3. Scan : Analyse le code pour les vulnérabilités de sécurité
4. Containerize : Crée et publie l'image Docker
5. Deploy to Staging : Déploie l'application dans l'environnement Staging
6. Approval : Attente d'approbation manuelle
7. Deploy to Production : Déploie l'application dans l'environnement Production

## Mesures de sécurité

Ce projet implémente plusieurs mesures de sécurité :

1. **Protection des branches** : Les pipelines ne sont déclenchés que sur les branches protégées
2. **Gestion sécurisée des secrets** : Les identifiants sont stockés dans des variables CI/CD protégées
3. **Principe du moindre privilège** : Les utilisateurs et services n'ont que les accès minimums requis
4. **Analyse de sécurité** : Le code et les dépendances sont analysés pour les vulnérabilités
5. **Infrastructure sécurisée** : Configuration sécurisée des services cloud
6. **TLS/SSL** : Toutes les communications sont chiffrées

## Monitoring et alertes

- Les applications exposent des endpoints `/health` pour le health checking
- Des health checks Docker sont configurés pour tous les conteneurs
- Toutes les applications journalisent des informations pertinentes
- Pour un monitoring avancé, considérez l'intégration avec Prometheus et Grafana

## Bonnes pratiques implémentées

1. **GitOps** : Toute la configuration est stockée dans Git
2. **Infrastructure as Code** : L'infrastructure est définie et gérée via du code
3. **CI/CD** : Intégration et déploiement continus
4. **Environnements de test** : Staging avant Production
5. **Containerisation** : Tous les services sont containerisés
6. **Déploiement automatisé** : Déploiement automatique via les pipelines
7. **Sécurité intégrée** : La sécurité est intégrée à toutes les étapes

## Fonctionnalités Bonus

- **Analyse de coût** : Infracost est intégré pour estimer les coûts d'infrastructure
- **Analyse de sécurité de l'infrastructure** : tfsec est utilisé pour analyser les configurations Terraform
- **Gestion multi-environnements** : Terragrunt est utilisé pour faciliter la gestion de multiples environnements

## Troubleshooting

### Problèmes courants

1. **Erreur de connexion à la base de données**
   - Vérifiez les variables d'environnement de connexion
   - Vérifiez les groupes de sécurité AWS

2. **Échec de la pipeline CI/CD**
   - Vérifiez les logs dans GitLab CI
   - Assurez-vous que toutes les variables nécessaires sont définies

3. **Erreur de déploiement Terraform**
   - Vérifiez les logs Terraform pour des erreurs spécifiques
   - Assurez-vous que les credentials AWS sont correctement configurés

## Contribution

1. Forkez le repo
2. Créez une branche pour votre fonctionnalité (`git checkout -b feature/amazing-feature`)
3. Commitez vos changements (`git commit -m 'Add some amazing feature'`)
4. Poussez vers la branche (`git push origin feature/amazing-feature`)
5. Ouvrez une Pull Request

## License

Ce projet est sous license MIT. Voir le fichier `LICENSE` pour plus de détails.
