from .config import config

from flask import request, redirect, session
import requests
from requests.utils import quote
from CTFd.utils.decorators import authed_only
from CTFd.utils.user import get_current_user
from CTFd.utils.security.auth import login_user
from CTFd.utils.crypto import hash_password
from CTFd.utils import db
from CTFd.models import Users
import hmac


class DiscordUser(db.Model):
    __tablename__ = 'discord_users'
    id = db.Column(db.Integer, primary_key=True)
    discord_id = db.Column(db.String(64), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)


def get_state_secret(app, user_id=None):
    key = app.config['DISCORD_AUTH_SECRET'].encode('utf8')
    data = user_id.to_bytes(8, 'big') if user_id else b' anon '
    return hmac.new(key, data, 'sha256').hexdigest()


def load(app):
    config(app)

    with app.app_context():
        db.create_all()

    @app.route("/discordauth", methods=['GET'])
    def discordauth():
        error = request.values.get('error')
        if error:
            return f"Discord error: {error}"

        user = None
        try:
            user = get_current_user()
        except:
            pass

        code = request.args.get('code')
        if code is None:
            state = get_state_secret(app, user.id if user else None)
            return redirect(
                "https://discord.com/oauth2/authorize?response_type=code" +
                "&client_id=" + quote(app.config['DISCORD_AUTH_CLIENT_ID']) +
                "&redirect_uri=" + quote(request.base_url) +
                "&scope=identify" +
                "&state=" + quote(state)
                , code=302)

        expected_state = get_state_secret(app, user.id if user else None)
        if not hmac.compare_digest(expected_state, request.args.get('state', '')):
            return "Invalid state - possible CSRF"

        r = requests.post('https://discord.com/api/v8/oauth2/token', data={
            'client_id': app.config['DISCORD_AUTH_CLIENT_ID'],
            'client_secret': app.config['DISCORD_AUTH_SECRET'],
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': request.base_url
        }, headers={
            'Content-Type': 'application/x-www-form-urlencoded'
        })
        r.raise_for_status()
        access_token = r.json()['access_token']

        r = requests.get('https://discord.com/api/v8/users/@me', headers={
            'Authorization': 'Bearer ' + access_token
        })
        r.raise_for_status()
        discord_user = r.json()
        discord_id = discord_user['id']
        discord_username = discord_user.get('username', 'discord_user')

        discord_link = DiscordUser.query.filter_by(discord_id=discord_id).first()

        if user:
            if discord_link is None:
                discord_link = DiscordUser(discord_id=discord_id, user_id=user.id)
                db.session.add(discord_link)
                db.session.commit()
                msg = f"Linked Discord <@{discord_id}> to account"
            elif discord_link.user_id != user.id:
                msg = f"Discord <@{discord_id}> already linked to another account"
            else:
                msg = f"Discord <@{discord_id}> already linked to this account"

            info = (f"User profile: {request.url_root}users/{user.id}\n"
                    f"User admin: {request.url_root}admin/users/{user.id}\n"
                    f"<@{discord_id}>\n{msg}")
            requests.post(app.config['DISCORD_AUTH_WEBHOOK'], json={'content': info})
            return redirect("/", code=302)

        if discord_link:
            ctfd_user = Users.query.filter_by(id=discord_link.user_id).first()
            if ctfd_user:
                login_user(ctfd_user)
                info = (f"Login via Discord: <@{discord_id}>\n"
                        f"User: {ctfd_user.name}\n"
                        f"Profile: {request.url_root}users/{ctfd_user.id}")
                requests.post(app.config['DISCORD_AUTH_WEBHOOK'], json={'content': info})
                return redirect("/", code=302)
            else:
                db.session.delete(discord_link)
                db.session.commit()

        password_hash = hash_password(discord_id + app.config['DISCORD_AUTH_SECRET'])
        new_user = Users(
            name=discord_username[:32],
            email=f"{discord_id}@discord.local",
            password=password_hash
        )
        db.session.add(new_user)
        db.session.flush()

        discord_link = DiscordUser(discord_id=discord_id, user_id=new_user.id)
        db.session.add(discord_link)
        db.session.commit()

        login_user(new_user)

        info = (f"New user registered via Discord: <@{discord_id}>\n"
                f"Username: {discord_username}\n"
                f"User profile: {request.url_root}users/{new_user.id}")
        requests.post(app.config['DISCORD_AUTH_WEBHOOK'], json={'content': info})

        return redirect("/", code=302)
