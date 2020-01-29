from bullet import *
from utils.sec_utils import *

def pick_ciphers(cc):
    hash_types=['MD5','SHA2','SHA3']
    sym_alg_types=['AES','CAM','FER']
    sym_mode_types=['CBC','CTR','OFB','CFB','CFB8']
    padd_types=['OAEP','PKCS1v15','PSS']
    if cc:
        cli=YesNo(prompt='Do you wish to use default cipher suite (SHA2-AES-CBC-OAEP-PKCS1v15-SHA2)? ')
    else:
        cli=YesNo(prompt='Do you wish to use default cipher suite (SHA2-AES-CBC-OAEP-PSS-SHA2)? ')
    cl=cli.launch()
    if cl:
        if cc:
            return get_cipher_methods("SHA2-AES-CBC-OAEP-PKCS1v15-SHA2")
        else:
            return get_cipher_methods("SHA2-AES-CBC-OAEP-PSS-SHA2")
    cli=SlidePrompt(
        [
            Bullet(
                    prompt='Regular hash method to use: ',
                    choices=hash_types,
                    align= 5, 
                    bullet="●",
                    bullet_color=colors.foreground["magenta"],
                    word_color=colors.foreground["white"],
                    word_on_switch=colors.foreground["black"],
                    background_color=colors.background["black"],
                    background_on_switch=colors.background["white"],
                    pad_right = 5
            ),
            Bullet(
                    prompt='Symmetric ciphering algorithm: ',
                    choices=sym_alg_types,
                    align= 5, 
                    bullet="●",
                    bullet_color=colors.foreground["magenta"],
                    word_color=colors.foreground["white"],
                    word_on_switch=colors.foreground["black"],
                    background_color=colors.background["black"],
                    background_on_switch=colors.background["white"],
                    pad_right = 5
            ),
            Bullet(
                    prompt='Symmetric ciphering mode: ',
                    choices=sym_mode_types,
                    align= 5, 
                    bullet="●",
                    bullet_color=colors.foreground["magenta"],
                    word_color=colors.foreground["white"],
                    word_on_switch=colors.foreground["black"],
                    background_color=colors.background["black"],
                    background_on_switch=colors.background["white"],
                    pad_right = 5
            ),
            Bullet(
                    prompt='Asymmetric ciphering padding: ',
                    choices=padd_types,
                    align= 5, 
                    bullet="●",
                    bullet_color=colors.foreground["magenta"],
                    word_color=colors.foreground["white"],
                    word_on_switch=colors.foreground["black"],
                    background_color=colors.background["black"],
                    background_on_switch=colors.background["white"],
                    pad_right = 5
            ),
            Bullet(
                    prompt='Asymmetric signing hashing: ',
                    choices=hash_types[1:],
                    align= 5, 
                    bullet="●",
                    bullet_color=colors.foreground["magenta"],
                    word_color=colors.foreground["white"],
                    word_on_switch=colors.foreground["black"],
                    background_color=colors.background["black"],
                    background_on_switch=colors.background["white"],
                    pad_right = 5
            )
        ]
    )
    rez=cli.launch()
    types=[]
    for r in rez:
        types+=[r[1]]
    if cc:
        suite=types[0]+"-"+types[1]+'-'+types[2]+'-'+types[3]+'-PKCS1v15-'+types[4]
    else:
        suite=types[0]+"-"+types[1]+'-'+types[2]+'-'+types[3]+'-PSS-'+types[4]
    client_logger.info('SUITE: '+suite)
    return get_cipher_methods(suite)
