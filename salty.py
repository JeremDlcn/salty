import PySimpleGUI as sg
import hashlib as hs
import os
import json
import binascii
import sys
import uuid
import re
import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode


actual_folder = os.path.abspath(".")

sg.theme('Dark Grey 6')  # color theme

## Hachage ##

def generate_salt():
    return uuid.uuid1()

def salage(encode):
    guerande = salt.bytes.hex()
    return encode + guerande

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

######

## Gestionnaire de clé ##
def generate_key(bits):
    if bits == '128':
        return b64encode(get_random_bytes(16)).decode('utf-8')
    elif bits == '192':
        return b64encode(get_random_bytes(24)).decode('utf-8')
    elif bits == '256':
        return b64encode(get_random_bytes(32)).decode('utf-8')


def is_valid_key(dataFile, keyName):
    for val in dataFile:
        if val['name'] == keyName:
            raise ValueError('La clé existe déjà')
    return True

def get_keys():
    with open('keys.json') as keys:
        dataFile = json.load(keys)
    return dataFile

def get_keys_name(without_desactivate_keys=False):
    names = []
    dataFile = get_keys()

    for val in dataFile:
        if val['activate'] is False:
            if without_desactivate_keys is False:
                names.append(val['name'] + ' - Clé désactivé')
        else:
            names.append(val['name'])
    return names

def write_file(path, data):
    with open(path, 'w') as file:
        json.dump(data, file, indent=3)

def update_key_file(data, name):
    dataFile = get_keys()
    if is_valid_key(dataFile, name) :
        dataFile.append(data)
        with open('keys.json', 'w') as keys:
            json.dump(dataFile, keys, indent=3)


def add_key(name, key):
    data = {'name': name, 'key': key, 'activate': True }
    update_key_file(data, name)

def activate_or_desactivate_key(name, action):
    key = {}
    dataFile = get_keys()
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

    write_file('keys.json', dataFile)


def delete_key(name):
    dataFile = get_keys()
    counter = 0
    for val in dataFile:
        if val['name'] == name:
            del dataFile[counter]
        counter += 1
    write_file('keys.json', dataFile)

## Fin gestionnaire de clé ##

## Chiffrement##

def find_key(name):
    with open('keys.json') as file:
        data = json.load(file)
        for val in data:
            if val['name'] == name:
                return val['key']


def encrypt(key_name, file_path, details):
    file_name = os.path.basename(file_path).split('.')[0]
    with open(file_path, 'rb') as file:
        data = file.read()

    key = b64decode(find_key(key_name)) #Récupération de la clé AES

    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size)) # Chiffrement des données
    iv = b64encode(cipher.iv).decode('utf-8') #Encodage en base 64 du vecteur d'initialisation
    encryptedData = ct_bytes #Encodage en base 64 des données chiffrées

    details['iv'] = iv
    details['filename'] = file_name
    details['extension_file'] = os.path.splitext(file_path)[1]

    write_encrypted_file(encryptedData, file_path, file_name, details)



def write_encrypted_file(encryptedData, file_path, file_name, details):

    path = os.path.dirname(file_path) + '/' + str(file_name) + str(datetime.datetime.now()) + '_encrypted/' + str(
        file_name)

    if not os.path.exists(path):
        os.makedirs(path)

    with open(os.path.join(path, file_name + '.encrypted'), 'wb') as file:
        file.write(encryptedData)

    write_file(os.path.join(path, 'data-relations.json'), details)



###############

salt = generate_salt()# Génération du sel


#columns for tabs layouts
#------------------------
col1_hash = [
    [sg.T('Hacher un fichier')],
    [sg.Input(key='path'), sg.FileBrowse('Importer un fichier', key='browse', button_color=('white', 'black'))],
    [sg.Button('Hacher le fichier', button_color=('black', 'lightblue'), size=(13, 1), key='file_now')],
    [sg.T()],
    [sg.T()],
    [sg.T('Liste des hash')],
    [sg.Listbox(values=('SHA-1', 'SHA-256', 'SHA-512', 'MD5', 'blake2b'),  size=(30, 5), default_values=["SHA-1"],
 select_mode='LISTBOX_SELECT_MODE_SINGLE', enable_events='true', no_scrollbar=True, key='hash_list'), sg.Checkbox('appliquer un salage', key="salage")],
    [sg.Text('Hash actuel: SHA-1', size=(17, 1), relief=sg.RELIEF_RIDGE, key='display_hash', background_color='grey')]
]

col2_hash = [
    [sg.T('Hacher un message')],
    [sg.Input(key='message')],
    [sg.Button('Hacher', button_color=('black', 'lightblue'), size=(6, 1), key='now')],
    [sg.T()],
    [sg.T()],
    [sg.T('Résultat')],
    [sg.Text('', size=(40, 5), relief=sg.RELIEF_RIDGE, key='output_hash')]
]

col1_chiffr = [
    [sg.T('Liste des hash')],
    [sg.Listbox(values=('SHA-1', 'SHA-256', 'SHA-512', 'MD5', 'blake2b'),  size=(30, 5), default_values=["SHA-256"],
 select_mode='LISTBOX_SELECT_MODE_SINGLE', enable_events='true', no_scrollbar=True, key='hash_list_chiffr')],
    [sg.Text('Hash actuel: SHA-256', size=(17, 1), relief=sg.RELIEF_RIDGE, key='display_hash_chiffr', background_color='grey')]
]

col2_chiffr = [
    [sg.T('Liste des clés')],
    [sg.Listbox(values=(get_keys_name(True)), size=(30, 5), default_values=[get_keys_name()],
 select_mode='LISTBOX_SELECT_MODE_SINGLE', enable_events='true', key='AES_list')],
    [sg.Text('Clé actuelle: KAES1', size=(17, 1), relief=sg.RELIEF_RIDGE, key='display_aes', background_color='grey')]
]

col3_chiffr = [
    [sg.T('Chiffrement', font='Arial 11')],
    [sg.Input(size=(30, 1), key='path_chiffr'), sg.FileBrowse('Importer un fichier', key='browse_chiffr', button_color=('white', 'black'))],
    [sg.Button('Chiffrer le fichier ', button_color=('black', 'lightblue'), key='chiffr_now')]
]

col4_chiffr = [
    [sg.T('Déchiffrement', font='Arial 11')],
    [sg.Input(size=(30, 1), key='path_dechiffr'), sg.FileBrowse('Importer un fichier', key='browse_dechiffr', button_color=('white', 'black'))],
    [sg.Button('Déchiffrer le fichier ', button_color=('black', 'lightblue'), key='dechiffr_now')]
]

col_gestion = [
    [sg.Button('Activer la clé', button_color=('black', 'lightgreen'), key='activate', enable_events='true', size=(13,1))],
    [sg.Button('Désactiver la clé', button_color=('black', 'gray'), key='disable', enable_events='true',size=(13,1))],
    [sg.Button('Supprimer la clé ', button_color=('black', 'red'), key='delete', enable_events='true', size=(13,1))]
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
    [sg.Input(key='display_create', do_not_clear=False), sg.Combo(['128', '192', '256'], size=(12, 1), default_value='128', enable_events='true', key='AES_Bits'), sg.Button('Créer la clé ', button_color=('black', 'white'), enable_events='true', key='create_key')],
    [sg.Text('Gestionnaire de clé', font='Arial 12')],
    [sg.Listbox(values=(get_keys_name()), size=(30, 5), default_values=["KAES1"],
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




    #input browsing file
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
    if(len(update_aes) > 0):
        update_aes = 'Clé actuelle: ' + update_aes[0]
        window['display_aes'].update(update_aes)


#Events Hachage
    #hachage d'un message
    if event == 'now':
        try:

            message_hash = values['message']
            assert message_hash != ''
            update_hash = window['hash_list'].get()
            #message_encode = hashing(update_hash[0], message_hash)
            if values['salage']:
                new_hash = hashing(update_hash[0], salage(message_hash))
            else:
                new_hash = hashing(update_hash[0], message_hash)
            window['output_hash'].update(new_hash)
        except:
            sg.Popup('Vous n\'avez pas écrit de message', title='Erreur', custom_text=' Ok ', button_color=('black', 'lightblue'), icon='close.ico')

    #hachage de fichier
    if event == 'file_now':
        try:
            file = open(f'{update_file_path}', 'r')
            update_hash = window['hash_list'].get()
            file_encode = hashing(update_hash[0], file.read())
            if values['salage']:
                file_hash = hashing(update_hash[0], salage(file.read()))
            else:
                file_hash = file_encode
            window['output_hash'].update(file_hash)
        except UnicodeDecodeError:
            sg.Popup('Le fichier que vous avez selectionné possède le mauvais format (essayez avec un fichier texte ou ePub)', title='Erreur', custom_text=' Ok ', button_color=('black', 'lightblue'), icon='close.ico')
        except FileNotFoundError:
            sg.Popup('Vous n\'avez pas selectioné de fichier', title='Erreur', custom_text=' Ok ', button_color=('black', 'lightblue'), icon='close.ico')

#Events Chiffrement/Déchiffrement

    #chiffrement d'un fichier
    if event == 'chiffr_now':
        try:
            with open(update_file_path2) as file:
                hash_method = window['hash_list_chiffr'].get()[0]
                hash_file = hashing(hash_method, salage(file.read()))

                assert len(window['AES_list'].get()) != 0
                key_name = window['AES_list'].get()[0]

                details = { 'hash_method': hash_method, 'hash': hash_file, 'key_name': key_name, 'salt': salt.bytes.hex(), 'iv': ''}

                encrypt(key_name, update_file_path2, details)

                sg.Popup(
                    'Votre fichier a été chiffré avec succès. Un répertoire a été créé au même emplacement que votre fichier source.',
                    title='Succès', custom_text=' Ok ', button_color=('black', 'lightblue'), icon='close.ico')
        except UnicodeDecodeError:
            sg.Popup(
                'Ce type de format de fichier n\'est pas pris en charge. Veuillez réssayer avec une autre extension de fichier.',
                title='Erreur', custom_text=' Ok ', button_color=('black', 'lightblue'), icon='close.ico')
        except FileNotFoundError:
            sg.Popup('Vous n\'avez pas selectioné de fichier', title='Erreur', custom_text=' Ok ',
                     button_color=('black', 'lightblue'), icon='close.ico')
        except:
            sg.Popup('Veuillez sélectionner une clé AES pour chiffrer votre fichier', title='Erreur', custom_text=' Ok ',
                     button_color=('black', 'lightblue'), icon='close.ico')



    #dechiffrement d'un fichier
    if event == 'dechiffr_now':
        try:
            with open(f'{update_file_path3}', 'rb') as file:
                data = file.read()
            with open(f'{update_file_path3}', 'r') as rel:
                details = json.load(rel)

            iv = b64decode(details['iv'])
            data = b64decode(data)
            key = b64decode(find_key(details['key_name']))

            cipher = AES.new(key, AES.MODE_CBC, iv)
            result = unpad(cipher.decrypt(data), AES.block_size)
            with open("text.txt", 'w') as test:
                test.write(result)



        except UnicodeDecodeError:
            sg.Popup('Ce type de format de fichier n\'est pas pris en charge. Veuillez réssayer avec une autre extension de fichier.', title='Erreur', custom_text=' Ok ', button_color=('black', 'lightblue'), icon='close.ico')
        except FileNotFoundError:
            sg.Popup('Vous n\'avez pas selectioné de fichier', title='Erreur', custom_text=' Ok ', button_color=('black', 'lightblue'), icon='close.ico')



    ## Evènements du gestionnaire de clé ##

    #Création d'une clé
    if event == 'create_key':
        try:
            nameKey = values['display_create']
            assert nameKey != ''

            bits = values['AES_Bits']
            key = generate_key(bits)
            add_key(nameKey, key)
            window['gestion_list'].update(values=get_keys_name())
            window['AES_list'].update(values=get_keys_name(True))
            sg.Popup('La clé ' + nameKey + ' a été créée avec succès', title='Succès', custom_text=' Fermer ',
                     button_color=('black', 'lightblue'), icon='close.ico')
        except AssertionError:
            sg.Popup('Veuillez nommer la clé pour générer une nouvelle clé', title='Erreur', custom_text=' Ok ',
                     button_color=('black', 'lightblue'), icon='close.ico')
        except ValueError:
            sg.Popup('La clé existe déjà. Veuillez choisir un autre nom de clé', title='Erreur', custom_text=' Ok ',
                     button_color=('black', 'lightblue'), icon='close.ico')



    if event == 'disable':
        selected_key = window['gestion_list'].get()
        try:
            activate_or_desactivate_key(selected_key[0], False)
            window['gestion_list'].update(values=get_keys_name())
            window['AES_list'].update(values=get_keys_name(True))
        except:
            sg.Popup('Vous n\'avez pas selectioné de clé', title='Erreur', custom_text=' Ok ',
                     button_color=('black', 'lightblue'), icon='close.ico')


    if event == 'activate':
        selected_key = window['gestion_list'].get()
        try:
            if re.search(' - Clé désactivé', selected_key[0]):
                selected_key = selected_key[0].replace(' - Clé désactivé', '')

            activate_or_desactivate_key(selected_key, True)
            window['gestion_list'].update(values=get_keys_name())
            window['AES_list'].update(values=get_keys_name(True))
        except:
            sg.Popup('Vous n\'avez pas selectioné de clé', title='Erreur', custom_text=' Ok ',
                     button_color=('black', 'lightblue'), icon='close.ico')


    if event == 'delete':
        selected_key = window['gestion_list'].get()
        try:
            selected_key = selected_key[0]
            if re.search(' - Clé désactivé', selected_key):
                selected_key = selected_key.replace(' - Clé désactivé', '')
            delete_key(selected_key)
            window['gestion_list'].update(values=get_keys_name())
            window['AES_list'].update(values=get_keys_name(True))
        except:
            sg.Popup('Vous n\'avez pas selectioné de clé', title='Erreur', custom_text=' Ok ',
                     button_color=('black', 'lightblue'), icon='close.ico')


window.close()
