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