# Python-Pwned

Projet Python LP Pro U-PEC ASSR (Administration Sécurité Systèmes et Réseaux)

Ce script a été développé par Dylan DE MIRANDA et Alexy DA CRUZ dans le cadre d'un projet scolaire.

Le but du projet est de rechercher si les hash se trouvant dans un fichier CSV sont dans la base de données de HaveIBeenPwned.
Afin de savoir s'ils ont fuité ou non.

## Utilisation

L'utilisation des arguments n'est pas obligatoire si un fichier de configuration se trouve au même emplacement que le script.

```
script.py [-a|--api <0000000000000> -f|--filename <file.csv>]
```

Il est possible de n'utiliser qu'un argument mais alors l'autre doit être rempli dans le fichier de configuration config.yml

## Configuration

Le fichier de configuration doit s'appelé "config.yml". Le fichier est donc au format Yaml.

Exemple d'un fichier de configuration :

```
api_key: #########################
csv_database_file: users-database.csv
```

## Packages requis pour utiliser le script Python

Pour utiliser le script Python, il faut installer les bibliothèques suivantes : 

- requests
- tabulate
- PyYAML

