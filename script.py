#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Auteur(s) : Dylan DE MIRANDA (dylandemiranda@gmail.com) & Alexy DA CRUZ (adacruz@geomtech.fr)
# Version : 0.1
# Date : 04/02/2021
# Thème du script : Vérification de mots de passe contenu dans un fichier CSV avec l'API de Have I Been Pwned.

# Importations des packages requis
import yaml
import csv
import argparse
import requests
from tabulate import tabulate

def check_password(login: str, hashed_password: str, api_key: str) -> list:
    # En tête HTTP
    # User-Agent pour dire quel est le client qui se connecte à leur API
    # hibp-api-key : clé d'API HaveIbeenPwned mais apparement inutile, mais peut-être un rate limit donc je l'ai mis quand même.
    headers = {
        "User-Agent": "DylanAlexy_PythonScript_LPASSR",
        "hibp-api-key": api_key,
    }
    
    # On met le hashed_password qui est en entrée en majuscule
    # Car les résultats retournées par l'API sont en majuscule et c'est donc utile pour la comparaison.
    hashed_password = hashed_password.upper()
    
    # On récupère les 5 premiers caractères
    hash_prefix = hashed_password[:5]

    # On requête l'API avec les 5 premiers caractères
    # Plus d'informations sur la documentation officielle de l'API HaveIBeenPwned : https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange
    r = requests.get(f'https://api.pwnedpasswords.com/range/{ hash_prefix }', headers=headers)
    
    # Pour chaque ligne retournée par l'API
    for line in r.text.split('\n'):
        # On récupère le hash (les 5 premiers caractères ne s'y trouve pas)
        hash_suffix = line.split(':')[0]
        # On récupère le compte des mots de passes trouvées
        password_count = line.split(':')[1]
        # On concataine les 5 premiers caractères à la suite avec le hash trouvé dans l'API
        hash_complete_password = hash_prefix + hash_suffix
        # On compare le hash qu'on demande à vérifier avec ce qu'il trouve dans l'API
        if (hashed_password == hash_complete_password):
            # Si c'est le même, c'est que le mot de passe est pwned.
            # On retourne donc les informations login, pwned = True, et le compte.
            return [login, True, int(password_count)]
    # Si le mot de passe n'est pas trouvé, on retourne les informations login, pwned = False, et 0 car aucun mdp trouvé.
    return [login, False, 0]

def display_results(filename: str, api_key: str) -> None:
    """
    Fonction qui affiche les résultats
    Entrées : 
        filename : Chemin du fichier CSV de base de données des utilisateurs
        api_key  : Clé d'API HaveIBeenPwned
    Sorties :
        Aucune
    """

    # Init variable
    results = []

    # On ouvre le fichier CSV
    with open(filename, newline='') as csvfile:
        # On le lit en tant que CSV avec comme séparateur ';'
        user_database = csv.reader(csvfile, delimiter=';')
        # On saute la première ligne (c'est l'entête)
        next(user_database)
        # Pour chaque ligne, donc chaque user dans le fichier
        for user in user_database:
            # On ajoute dans la liste results le resultat pour chaque utilisateur la liste retourné par la fonction check_password
            results.append(check_password(user[0], user[1], api_key))
        
    # On affiche le tableau (liste) results avec tabulate afin que ce soit jolie
    print(tabulate(results, headers=['Login', 'Pwned', 'Count']))

def config(config_path: str) -> list:
    """
    Fonction pour le fichier de configuration
    Entrées :
        config_path : chemin du fichier de configuration
    Sorties :
        list : liste contenant la clé d'API et le nom du fichier
    """

    # On ouvre un stream sur le fichier de config en lecture
    stream = open(config_path, 'r')
    # On le charge dans la bibliothèque yaml
    cfg = yaml.safe_load(stream)

    # Assignation des variables
    api_key = str(cfg['api_key'])
    filename = str(cfg['csv_database_file'])

    # et on les retourne
    return api_key, filename

def main() -> None:   
    """
    Fonction principale
    Entrées : 
        Aucune
    Sorties :
        Aucune
    """

    # Init des variables
    api_key = ""
    filename = ""

    # Parsing des arguments lancé dans le CLI
    parser = argparse.ArgumentParser()
    # Argument pour la clé d'API
    parser.add_argument("-a", "--api_key", help="Clé d'API HaveIBeenPwned APIv3", type=str)
    # Argument pour le nom du fichier CSV
    parser.add_argument("-f", "--filename", help="Nom du fichier CSV", type=str)
    args = parser.parse_args()

    # Assignation des variables avec les arguments. SI pas d'arguments, les variables seront None    
    api_key = args.api_key
    filename = args.filename

    # Si les variables retournent None (donc aucun argument)
    if api_key == None:
        # On va chercher dans le fichier de configuration config.yml
        api_key = config("config.yml")[0]
    if filename == None:
        # On va chercher dans le fichier de configuration config.yml
        filename = config("config.yml")[1]    

    # On affiche les résultats
    display_results(filename, api_key)    

if __name__ == "__main__":
    # Appel de notre fonction principale
    main()
