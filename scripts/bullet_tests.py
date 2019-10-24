from bullet import Bullet, Check, YesNo, Input, colors

cli=Bullet(
    prompt="Choose from the items below: ",
    choices=['ola','mundo','luke'],
    bullet_color=colors.foreground['white']
)
result=cli.launch()
