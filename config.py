from os import environ

def config(app):
    app.config['DISCORD_AUTH_WEBHOOK'] = environ.get('DISCORD_AUTH_WEBHOOK')
    app.config['DISCORD_AUTH_CLIENT_ID'] = environ.get('DISCORD_AUTH_CLIENT_ID')
    app.config['DISCORD_AUTH_SECRET'] = environ.get('DISCORD_AUTH_SECRET')
