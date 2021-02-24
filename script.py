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
    headers = {
        "User-Agent": "DylanAlexy_PythonScript_LPASSR",
    }
    
    hashed_password = hashed_password.upper()
    
    hash_prefix = hashed_password[:5]

    r = requests.get(f'https://api.pwnedpasswords.com/range/{ hash_prefix }', headers=headers)
    
    for line in r.text.split('\n'):
        hash_suffix = line.split(':')[0]
        password_count = line.split(':')[1]
        hash_complete_password = hash_prefix + hash_suffix
        if (hashed_password == hash_complete_password):
            return [login, True, int(password_count)]
    return [login, False, 0]

def display_results(filename: str, api_key: str) -> None:
    results = []

    with open(filename, newline='') as csvfile:
        user_database = csv.reader(csvfile, delimiter=';', quotechar='|')
        next(user_database)
        for user in user_database:
            results.append(check_password(user[0], user[1], api_key))
        
    print(tabulate(results, headers=['Login', 'Pwned', 'Count']))

def config(config_path: str) -> list:
    stream = open(config_path, 'r')
    cfg = yaml.safe_load(stream)

    api_key = str(cfg['api_key'])
    filename = str(cfg['csv_database_file'])

    return api_key, filename

def main() -> None:   
    api_key = ""
    filename = ""

    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--api_key", help="Clé d'API HaveIBeenPwned APIv3", type=str)
    parser.add_argument("-f", "--filename", help="Nom du fichier CSV", type=str)
    args = parser.parse_args()
    
    api_key = args.api_key
    filename = args.filename

    if api_key == None:
        api_key = config("config.yml")[0]
    if filename == None:
        filename = config("config.yml")[1]    

    display_results(filename, api_key)    

if __name__ == "__main__":
    main()
