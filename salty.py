import PySimpleGUI as sg
import hashlib as hs
import os
import json
import binascii
import sys
import uuid
import re

actual_folder = os.path.abspath(".")

sg.theme('Dark Grey 6')  # color theme

def generateSalt():
    return uuid.uuid1()


def salage():
    guerande = salt.bytes.hex()
    return message_encode + guerande

def hashing(selected_hash, value):
    value = bytes(value, 'utf-8')
    if selected_hash == 'SHA-1':
        return hs.sha1(value).hexdigest()
    elif selected_hash == 'SHA-256':
        return hs.sha256(value).hexdigest()
    elif selected_hash == 'SHA-512':
        return hs.sha512(value).hexdigest()
    elif selected_hash == 'MD5':
        return hs.md5(value).hexdigest()
    elif selected_hash == 'blake2b':
        return hs.blake2b(value).hexdigest()


## Gestionnaire de clé ##
def generateKey(bits):
    if bits == '128':
        return binascii.hexlify(os.urandom(16)).decode()
    elif bits == '192':
        return binascii.hexlify(os.urandom(24)).decode()
    elif bits == '256':
        return binascii.hexlify(os.urandom(32)).decode()

def isValidKey(dataFile, keyName):
    for val in dataFile:
        if val['name'] == keyName:
            return False
    return True

def getKeys():
    with open('keys.json') as keys:
        dataFile = json.load(keys)
    return dataFile

def getKeysName():
    names = []
    dataFile = getKeys()

    for val in dataFile:
        if val['activate'] == False:
            names.append(val['name'] + ' - Clé désactivé')
        else:
            names.append(val['name'])
    return names

def writeKeyFile(data):
    with open('keys.json', 'w') as keys:
        json.dump(data, keys)

def updateKeyFile(data, name):
    dataFile = getKeys()
    if isValidKey(dataFile, name) :
        dataFile.append(data)
        with open('keys.json', 'w') as keys:
            json.dump(dataFile, keys)


def addKey(name, key):
    data = {'name': name, 'key': key, 'activate': True}
    updateKeyFile(data, name)

def activateOrDesactivateKey(name, action):
    key = {}
    dataFile = getKeys()
    counter = 0
    for val in dataFile:
        if val['name'] == name:
            key = val
            if action:
                key['activate'] = True
            elif not action:
                key['activate'] = False
            dataFile[counter] = key
        counter += 1

    writeKeyFile(dataFile)




## Fin gestionnaire de clé ##

salt = generateSalt()# Génération du sel


#columns for tabs layouts
#------------------------
col1_hash = [
    [sg.T('Hacher un fichier')],
    [sg.Input(key='path'), sg.FileBrowse('Importer un fichier', key='browse', button_color=('white', 'black'))],
    [sg.T()],
    [sg.T()],
    [sg.T('Liste des hash')],
    [sg.Listbox(values=('SHA-1', 'SHA-256', 'SHA-512', 'MD5', 'blake2b'),  size=(30, 5), default_values=["SHA-1"],
 select_mode='LISTBOX_SELECT_MODE_SINGLE', enable_events='true', key='hash_list'), sg.Checkbox('appliquer un salage', key="salage")],
    [sg.Text('Hash actuel: SHA-1', size=(17, 1), relief=sg.RELIEF_RIDGE, key='display_hash', background_color='grey')]
]

col2_hash = [
    [sg.T('Hacher un message')],
    [sg.Input(key='message')],
    [sg.T()],
    [sg.T()],
    [sg.T('Résultat')],
    [sg.Text('', size=(40, 5), relief=sg.RELIEF_RIDGE, key='output_hash')],
    [sg.Button('Hasher', button_color=('black', 'lightblue'), size=(20, 1), key='now')]
]

col1_chiffr = [
    [sg.T('Liste des hash')],
    [sg.Listbox(values=('SHA-1', 'SHA-256', 'SHA-512', 'MD5', 'blake2b'),  size=(30, 5), default_values=["SHA-1"],
 select_mode='LISTBOX_SELECT_MODE_SINGLE', enable_events='true', key='hash_list_chiffr')],
    [sg.Text('Hash actuel: SHA-1', size=(17, 1), relief=sg.RELIEF_RIDGE, key='display_hash_chiffr', background_color='grey')]
]

col2_chiffr = [
    [sg.T('Liste des clés')],
    [sg.Listbox(values=('KAES1', 'KAES2', 'KAES3', 'KAES4', 'KAES5'), size=(30, 5), default_values=["KAES1"],
 select_mode='LISTBOX_SELECT_MODE_SINGLE', enable_events='true', key='AES_list')],
    [sg.Text('Clé actuelle: KAES1', size=(17, 1), relief=sg.RELIEF_RIDGE, key='display_aes', background_color='grey')]
]

col3_chiffr = [
    [sg.T('Chiffrement', font='Arial 11')],
    [sg.Input(size=(30, 1), key='path_chiffr'), sg.FileBrowse('Importer un fichier', key='browse_chiffr', button_color=('white', 'black'))],
    [sg.Button('Chiffrer le fichier ', button_color=('black', 'lightblue'))]
]

col4_chiffr = [
    [sg.T('Déchiffrement', font='Arial 11')],
    [sg.Input(size=(30, 1), key='path_dechiffr'), sg.FileBrowse('Importer un fichier', key='browse_dechiffr', button_color=('white', 'black'))],
    [sg.Button('Déchiffrer le fichier ', button_color=('black', 'lightblue'))]
]

col_gestion = [
    [sg.Button('Activer la clé',  button_color=('black', 'gray'), key='activate', enable_events='true')],
    [sg.Button('Désactiver la clé', button_color=('black', 'gray'), key='disable', enable_events='true')],
    [sg.Button('Supprimer la clé ', button_color=('black', 'red'), key='delete', enable_events='true')]
]




#Layouts for tab
#---------------
hash_layout = [
    [sg.T()],
    [sg.T()],
    [sg.Column(col1_hash), sg.Column(col2_hash)]
]

chiffr_layout = [
    [sg.T()],
    [sg.Text('Configuration', font='Arial 12')],
    [sg.Column(col1_chiffr), sg.Text(' '*35), sg.Column(col2_chiffr)],
    [sg.T('_' * 116)],
    [sg.Text('Transformation des fichiers', font='Arial 12')],
    [sg.Column(col3_chiffr), sg.T(' '*9), sg.Column(col4_chiffr)],
    [sg.T()]
]

gestion_layout = [
    [sg.T()],
    [sg.Text('Création d\'une clé AES'), sg.T(' ' * 42), sg.Text('Nombre de bits')],
    [sg.Input(key='create', do_not_clear=False), sg.Combo(['128', '192', '256'], size=(12, 1), default_value='128', enable_events='true', key='AES_Bits'), sg.Button('Créer la clé ', button_color=('black', 'white'), enable_events='true', key='addKey')],
    [sg.Text('Gestionnaire de clé', font='Arial 12')],
    [sg.Listbox(values=(getKeysName()), size=(30, 5), default_values=["KAES1"],
                select_mode='LISTBOX_SELECT_MODE_SINGLE', enable_events='true', key='gestion_list'), sg.Column(col_gestion)]
]

#header of the application
#------------------------
logo = [[sg.Image('logo.png')]]
watermark = [[sg.Text()],[sg.Text('Arthur Geay', size=(70, 1), justification='right')], [sg.Text('Jérémie Delécrin', size=(73, 1), justification='right')]]

#layout of the application
#------------------------
layout = [
    [sg.Column(logo), sg.Column(watermark, element_justification='right')],
    [sg.TabGroup([[sg.Tab('Hash', hash_layout), sg.Tab('Chiffrement/Déchiffrement', chiffr_layout), sg.Tab('Gestionnaire clés', gestion_layout)]])],
    [sg.Text()]
]

# Create the Window
window = sg.Window('Salty', layout)
window.SetIcon(icon='salty-icon.ico', pngbase64=None)




# Event Loop to process "events" and get the "values" of the inputs
while True:
    event, values = window.read()
    if event in (None, 'Cancel'):  # if user closes window or clicks cancel
        break




#input browing file
    update_file_path = values['browse']
    update_file_path2 = values['browse_chiffr']
    update_file_path3 = values['browse_dechiffr']
    window['path'].update(update_file_path)
    window['path_chiffr'].update(update_file_path2)
    window['path_dechiffr'].update(update_file_path3)


    #Hash Lists
    update_hash = window['hash_list'].get()
    update_hash = 'Hash actuel: ' + update_hash[0]
    window['display_hash'].update(update_hash)

    update_hash_chiffr = window['hash_list_chiffr'].get()
    update_hash_chiffr = 'Hash actuel: ' + update_hash_chiffr[0]
    window['display_hash_chiffr'].update(update_hash_chiffr)

    #AES_list
    update_aes = window['AES_list'].get()
    update_aes = 'Clé actuelle: ' + update_aes[0]
    window['display_aes'].update(update_aes)

    #bouton de gestion des clés

    if event == 'delete':
        deleted_aes = window['gestion_list'].get()
        deleted_aes = deleted_aes[0]
        #supprimer dans le tableau de variable

    if event == 'now':
        message_hash = values['message']
        update_hash = window['hash_list'].get()
        message_encode = hashing(update_hash[0], message_hash)
        if values['salage']:
            new_hash = salage()
        else:
            new_hash = message_encode

        if update_file_path != '':
            file = open(f'{update_file_path}', 'r')
            file_hash = hashing(update_hash[0], file.read())
            window['output_hash'].update(file_hash)
        else:
            window['output_hash'].update(new_hash)



    ## Evènements du gestionnaire de clé ##

    # Evènement pour générer une clé
    if event == 'addKey':
        if values['create'] != '':
            bits = values['AES_Bits']
            key = generateKey(bits)
            nameKey = values['create']
            addKey(nameKey, key)
            window['gestion_list'].update(values=getKeysName())


    if event == 'disable':
        selected_key = window['gestion_list'].get()
        activateOrDesactivateKey(selected_key[0], False)
        window['gestion_list'].update(values=getKeysName())


    if event == 'activate':
        selected_key = window['gestion_list'].get()

        if re.search(' - Clé désactivé', selected_key[0]):
            selected_key = selected_key[0].replace(' - Clé désactivé', '')

        activateOrDesactivateKey(selected_key, True)
        window['gestion_list'].update(values=getKeysName())


window.close()
