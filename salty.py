import PySimpleGUI as sg
import hashlib as hs

sg.theme('Dark Grey 6')  # color theme

def hashing(selected_hash, value):
    print(selected_hash)
    if selected_hash == 'SHA-1':
        return hs.sha1(value)
    elif selected_hash == 'SHA-256':
        return hs.sha256(value)
    elif selected_hash == 'SHA-512':
        return hs.sha512(value)
    elif selected_hash == 'MD5':
        return hs.md5(value)
    elif selected_hash == 'blake2b':
        return hs.blake2b(value)

#columns for tabs layouts
#------------------------
col1_hash = [
    [sg.T('Hacher un fichier')],
    [sg.Input(key='path'), sg.FileBrowse('Importer un fichier', key='browse', button_color=('white', 'black'))],
    [sg.T()],
    [sg.T()],
    [sg.T('Liste des hash')],
    [sg.Listbox(values=('SHA-1', 'SHA-256', 'SHA-512', 'MD5', 'blake2b'),  size=(30, 5), default_values=["SHA-1"],
 select_mode='LISTBOX_SELECT_MODE_SINGLE', enable_events='true', key='hash_list'), sg.Checkbox('appliquer un salage')],
    [sg.Text('Hash actuel: SHA-1', size=(17, 1), relief=sg.RELIEF_RIDGE, key='display_hash', background_color='grey')]
]

col2_hash = [
    [sg.T('Hacher un message')],
    [sg.Input(key='message')],
    [sg.T()],
    [sg.T()],
    [sg.T('Résultat')],
    [sg.Text('', size=(40, 5), relief=sg.RELIEF_RIDGE, key='output_hash')],
    [sg.Button('Hasher', button_color=('black', 'lightblue'), size=(20, 1), key='hash_now')]
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
    [sg.Input(key='create'), sg.Combo(['128', '192', '256'], size=(12, 1), default_value='128', enable_events=True, key='AES_Bits'), sg.Button('Créer la clé ', button_color=('black', 'white'))],
    [sg.Text('Gestionnaire de clé', font='Arial 12')],
    [sg.Listbox(values=('KAES1', 'KAES2', 'KAES3', 'KAES4', 'KAES5'), size=(30, 5), default_values=["KAES1"],
                select_mode='LISTBOX_SELECT_MODE_SINGLE', enable_events='true', key='gestion_list'), sg.Column(col_gestion)]
]

#header of the application
#------------------------
logo = [[sg.Image(r'salty\logo.png')]]
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
window.SetIcon(icon=r'salty\salty-icon.ico', pngbase64=None)






# Event Loop to process "events" and get the "values" of the inputs
while True:
    event, values = window.read()
    if event in (None, 'Cancel'):  # if user closes window or clicks cancel
        break

#hashage du message
    if event == 'hash_now':
        message_hash = values['message']
        update_hash = window['hash_list'].get()
        new_hash = hashing(update_hash[0], message_hash)
        #window['output'].update(new_hash)

#input browing file
    update_file_path = values['browse']
    update_file_path2 = values['browse_chiffr']
    update_file_path3 = values['browse_dechiffr']
    window['path'].update(update_file_path)
    window['path_chiffr'].update(update_file_path2)
    window['path_dechiffr'].update(update_file_path3)


#Listes de hash

    #récupération
    update_hash_chiffr = window['hash_list_chiffr'].get()

    #transformation du message

    new_hash_chiffr = hashing(update_hash_chiffr[0])
    update_hash = 'Hash actuel: ' + update_hash[0]
    update_hash_chiffr = 'Hash actuel: ' + update_hash_chiffr[0]
    
    window['display_hash'].update(update_hash)
    window['display_hash_chiffr'].update(update_hash_chiffr)

    #AES_list
    update_aes = window['AES_list'].get()
    update_aes = 'Clé actuelle: ' + update_aes[0]
    window['display_aes'].update(update_aes)

    #bouton de gestion des clés
    if event == 'disable':
        selected_aes = window['gestion_list'].get()
        aes_complete = window['gestion_list'].get_list_values()
        aes_complete = list(aes_complete)
        i = 0
        for x in aes_complete:
            if x == selected_aes[0]:
                aes_complete[i] = '(disabled)' + selected_aes[0]
            i = i + 1
        lists = window['gestion_list'].update(values=aes_complete)

    if event == 'delete':
        deleted_aes = window['gestion_list'].get()
        deleted_aes = deleted_aes[0]
        #supprimer dans le tableau de variable


    #récupération du nombre de bits utilisées pour créer la clé aes
    bits = values['AES_Bits']


window.close()


