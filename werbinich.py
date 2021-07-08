""" a server to complement werbinichbot """
import os
import redis

from components.py_input_validator.validator import (
    validate_username,
    validate_pw
)

from werkzeug.urls import url_parse
from werkzeug.wrappers import Request, Response
from werkzeug.routing import Map, Rule
from werkzeug.exceptions import HTTPException, NotFound
from werkzeug.middleware.shared_data import SharedDataMiddleware
from werkzeug.utils import redirect
from secure_cookie.session import FilesystemSessionStore
from jinja2 import Environment, FileSystemLoader
from passlib.hash import pbkdf2_sha256 as sha256

session_store = FilesystemSessionStore()

class Werbinich(object):

    def __init__(self):
        self.redis = redis.StrictRedis(decode_responses=True, db=2)
        template_path = os.path.join(os.path.dirname(__file__), 'templates')
        self.jinja_env = Environment(loader=FileSystemLoader(template_path),
                                 autoescape=True)
        self.url_map = Map([
            Rule('/', endpoint='load'),
        ])

    def render_template(self, template_name, **context):
        t = self.jinja_env.get_template(template_name)
        return Response(t.render(context), mimetype='text/html')

    def dispatch_request(self, request):
        adapter = self.url_map.bind_to_environ(request.environ)
        try:
            endpoint, values = adapter.match()
            return getattr(self, f'on_{endpoint}')(request, **values)
        except HTTPException as e:
            return e

    def wsgi_app(self, environ, start_response):
        request = Request(environ)
        response = self.dispatch_request(request)
        return response(environ, start_response)

    def __call__(self, environ, start_response):
        return self.wsgi_app(environ, start_response)

    def on_load(self, request):
        """ Handle all form submit events """
        error=None
        sid = request.cookies.get('session_id')
        if sid is None:
            request.session = session_store.new()
        else:
            request.session = session_store.get(sid)
        username = self.get_user(sid)
        if request.method == 'POST':
            op = request.form["operation"]
            if username != "None" or op in ["login", "register", "registration_form"]:
                return getattr(self, op)(request, sid)  # call operation method
            else:
                return self.render_template('login.html', error=error)
        response = self.render_template('login.html', error=error)
        return response

    def login(self, request, sid):
        """ Handle user login """
        args = list(request.form.keys())
        required = ["username", "login_pw"]
        if not all(item in args for item in required):
            error = "Das funktioniert nicht."
            return self.render_template('login.html', error=error)
        username = request.form["username"].strip()
        pw = request.form["login_pw"].strip()
        pw_hash = self.get_user_pw(username)
        if pw_hash and sha256.verify(pw, pw_hash):
            self.set_user_session(username, request.session.sid)
            if self.redis.hexists(username, "change_pw"):
                response = self.render_template("change_pw.html")
                response.set_cookie("session_id", request.session.sid)
                self.redis.hdel(username, "change_pw")
                return response
            games_list = self.get_list_of_games()
            success = "Angemeldet."
            if self.redis.hexists(username, "game_id"):
                saved_game_id = self.redis.hget(username, "game_id")
                if saved_game_id != "None":
                    success = "Spiel beigetreten."
                    player_list = self.get_other_players(username)
                    response = self.render_template(
                        'game.html',
                        error=None,
                        success=success,
                        player_list=player_list,
                        username=username,
                        game_id=saved_game_id
                    )
                    self.set_user_session(username, request.session.sid)
                    response.set_cookie("session_id", request.session.sid)
                    return response
            response = self.render_template(
                'index.html',
                error=None,
                success=success,
                username=username
            )
            if request.session.should_save:
                session_store.save(request.session)
            self.set_user_session(username, request.session.sid)
            response.set_cookie("session_id", request.session.sid)
            return response
        elif pw_hash:
            error = "Falsches Passwort."
        else:
            error = "Nutzer nicht gefunden."
        return self.render_template("login.html", error=error)

    def registration_form(self, request, sid):
        """ handle clicking registration link """
        return self.render_template('registration_form.html', error=None)

    def cancel_registration(self, request, sid):
        return self.render_template('login.html')

    def register(self, request, sid):
        """ handle user registration """
        args = list(request.form.keys())
        required = ["username", "pw", "name", "pw_confirm"]
        if not all(item in args for item in required):
            error = "Das funktioniert nicht."
            return self.render_template('login.html', error=error)
        username = request.form["username"].strip()
        keys = self.get_all_keys()
        if username in keys:
            error = "Diese:r Nutzer:in existiert bereits."
            return self.render_template('registration_form.html', error=error)
        name = request.form["name"].strip()
        pw = request.form["pw"].strip()
        pw_confirm = request.form["pw_confirm"].strip()
        if pw == pw_confirm and validate_pw(pw) and validate_username(username) and validate_username(username):
            self.set_user_name_and_pw(username, name, pw)
            games_list = self.get_list_of_games()
            success = "Registriert und angemeldet."
            response = self.render_template(
                'index.html',
                error=None,
                success=success,
                username=username
            )
            self.set_user_session(username, request.session.sid)
            if request.session.should_save:
                session_store.save(request.session)
            response.set_cookie("session_id", request.session.sid)
        else:
            error = "Die Passwörter stimmen nicht überein."
            response = self.render_template('registration_form.html', error=error)
        return response

    def join_game(self, request, sid):
        """ join or create a game """
        args = list(request.form.keys())
        required = ["game_id", "game_pw"]
        if not all(item in args for item in required):
            error = "Das funktioniert nicht."
            return self.render_template('login.html', error=error)
        session_user_name = self.get_user(request.session.sid)
        game_id = request.form["game_id"].strip()
        game_pw = request.form["game_pw"].strip()
        if not validate_username(game_id):
            error = "Bitte gib gültige Daten ein."
            games_list = self.get_list_of_games()
            return self.render_template(
                'join_game.html',
                error=error,
                game_list=games_list
            )
        games_list = self.get_list_of_games()
        if game_id in games_list:# if game exists
            pw_hash = self.get_game_pw(game_id)
            if sha256.verify(game_pw, pw_hash):#... and pw is correct
                self.redis.hset(session_user_name, "game_id", game_id)
                player_list = self.get_other_players(session_user_name)
                success = "Spiel beigetreten."
                response = self.render_template(
                    'game.html',
                    error=None,
                    success=success,
                    player_list=player_list,
                    username=session_user_name,
                    game_id=game_id
                )
            else:# game exists, pw incorrect
                response = self.render_template(
                    'join_game.html',
                    error="Falsches Passwort",
                    game_list=games_list,
                    username=session_user_name
                )
        else:
            # create game
            self.redis.hset(session_user_name, "game_host", "true")
            pw_hash = sha256.hash(game_pw)
            self.redis.hset(session_user_name, "game_pw", pw_hash)
            self.redis.hset(session_user_name, "game_id", game_id)
            player_list = self.get_other_players(session_user_name)
            response = self.render_template(
                    'game.html',
                    error=None,
                    success="Spiel erstellt!",
                    player_list=player_list,
                    username=session_user_name,
                    game_id=game_id
                )
        return response

    def set_player_character(self, request, sid):
        """ define a character for another player """
        success = None
        error = None
        args = list(request.form.keys())
        required = ["player", "character"]
        if not all(item in args for item in required):
            error = "Das funktioniert nicht."
            return self.render_template('login.html', error=error)
        session_user_name = self.get_user(request.session.sid)
        player_id = request.form["player"]
        player_character = request.form["character"].strip()
        old_character = self.redis.hget(player_id, "character")
        character_solved = self.redis.hget(player_id, "solved")
        if old_character is None or str(old_character) == "None" or character_solved == "true":
            self.redis.hset(player_id, "character", player_character)
            self.redis.hset(player_id, "solved", "false")
        else:
            error = "Da steht schon ein Charakter."
        game_id = self.redis.hget(player_id, "game_id")
        player_list = self.get_other_players(session_user_name)
        response = self.render_template(
            'game.html',
            error=error,
            success=success,
            player_list=player_list,
            username=session_user_name,
            game_id=game_id
        )
        return response

    def reload_game(self, request, sid):
        """ reload other players in game """
        session_user_name = self.get_user(request.session.sid)
        player_list = self.get_other_players(session_user_name)
        game_id = self.redis.hget(session_user_name, "game_id")
        response = self.render_template(
            'game.html',
            error=None,
            success=None,
            player_list=player_list,
            username=session_user_name,
            game_id=game_id
        )
        return response

    def leave_game(self, request, sid):
        """ leave game and transfer host if necessary """
        session_user_name = self.get_user(request.session.sid)
        if self.redis.hexists(session_user_name, "game_host"):
            game_id = self.redis.hget(session_user_name, "game_id")
            other_players = self.get_other_players(session_user_name)
            game_pw = self.redis.hget(session_user_name, "game_pw")
            self.redis.hdel(session_user_name, "game_pw", "game_host")
            self.redis.hset(session_user_name, "character", "None")
            if other_players:
                new_host = next(iter(other_players.keys()))
                self.redis.hset(new_host, "game_host", "true")
                self.redis.hset(new_host, "game_pw", game_pw)
        games_list = self.get_list_of_games()
        response = self.render_template(
            'index.html',
            error=None,
            username=session_user_name
        )
        self.redis.hset(session_user_name, "game_id", "None")
        self.redis.hset(session_user_name, "character", "None")
        self.redis.hset(session_user_name, "solved", "false")
        return response

    def logout(self, request, sid):
        response = self.render_template("login.html", success="Abgemeldet.")
        session_user_name = self.get_user(request.session.sid)
        self.redis.hset(session_user_name, "session_id", "None")
        return response

    def start(self, request, sid):
        username = self.get_user(request.session.sid)
        return self.render_template("index.html", username=username)

    def index(self, request, sid):
        return self.on_load(request)

    def impressum(self, request, sid):
        return self.render_template("impressum.html", auth=False)

    def impressum_auth(self, request, sid):
        return self.render_template("impressum.html", auth=True)

    def show_games(self, request, sid):
        username = self.get_user(request.session.sid)
        games_list = self.get_list_of_games()
        response = self.render_template(
            'join_game.html',
            error=None,
            game_list=games_list,
            username=username
        )
        return response

    def enter_new_pw(self, request, sid):
        username = self.get_user(request.session.sid)
        return self.render_template("change_pw.html", username=username, back_link="true")

    def set_new_pw(self, request, sid):
        args = list(request.form.keys())
        required = ["old_pw", "new_pw", "new_pw_confirm"]
        if not all(item in args for item in required):
            error = "Das funktioniert nicht."
            return self.render_template('login.html', error=error)
        username = self.get_user(request.session.sid)
        old_pw = request.form["old_pw"].strip()
        new_pw = request.form["new_pw"].strip()
        new_pw_confirm = request.form["new_pw_confirm"].strip()
        pw_hash = self.get_user_pw(username)
        if (
            pw_hash and
            sha256.verify(old_pw, pw_hash) and
            new_pw == new_pw_confirm and
            validate_pw(new_pw)
        ):
            self.set_user_pw(username, new_pw)
            success = "Passwort geändert.\n\nBitte neu einloggen!"
            return self.render_template("login.html", success=success)
        else:
            error = "Das hat nicht geklappt."
            return self.render_template("change_pw.html", error=error, back_link="true")

    def delete_user_data(self, request, sid):
        username = self.get_user(request.session.sid)
        return self.render_template("confirm_delete.html", username=username)

    def confirm_delete(self, request, sid):
        username = self.get_user(request.session.sid)
        self.redis.delete(username)
        success = "Daten gelöscht."
        return self.render_template("login.html", success=success)

    def enter_new_name(self, request, sid):
        return self.render_template("change_name.html")

    def set_new_name(self, request, sid):
        error = None
        args = list(request.form.keys())
        required = ["pw", "new_name"]
        if not all(item in args for item in required):
            error = "Das funktioniert nicht."
            return self.render_template('login.html', error=error)
        username = self.get_user(request.session.sid)
        pw = request.form["pw"].strip()
        new_name = request.form["new_name"].strip()
        pw_hash = self.get_user_pw(username)
        if sha256.verify(pw, pw_hash) and validate_username(new_name):
            self.set_user_name(username, new_name)
            success = "Anzeigename geändert."
            response = self.render_template('index.html', success=success)
        else:
            error = "Falsches Passwort."
            response = self.render_template('change_name.html', error=error)
        return response

    def toggle_solved(self, request, sid):
        error = None
        session_user_name = self.get_user(request.session.sid)
        user_id = request.form["user_id"]
        if not user_id:
            error = "Das funktioniert nicht."
            player_list = self.get_other_players(session_user_name)
            game_id = self.redis.hget(session_user_name, "game_id")
            response = self.render_template(
                'game.html',
                error=error,
                success=None,
                player_list=player_list,
                username=session_user_name,
                game_id=game_id
            )
            return response
        if self.redis.hget(user_id, "solved") == "true":
            self.redis.hset(user_id, "solved", "false")
        else:
            self.redis.hset(user_id, "solved", "true")
        return self.reload_game(request, sid)

    def get_list_of_games(self):
        """ get a `set` of game IDs """
        keys = self.get_all_keys()
        games_list = []
        if keys:
            for key in keys:
                game_id = self.redis.hget(key, "game_id") or "None"
                if not game_id in games_list and game_id != "None":
                    games_list.append(game_id)
        return games_list

    def set_user_pw(self, username, password):
        """ insert new pw hash into db """
        pw_hash = sha256.hash(password)
        self.redis.hset(username, "pw_hash", pw_hash)

    def set_user_name(self, username, name):
        self.redis.hset(username, "name", name)

    def set_user_name_and_pw(self, username, name, password):
        """ insert name, pw into db """
        pw_hash = sha256.hash(password)
        self.redis.hset(username, "pw_hash", pw_hash)
        self.redis.hset(username, "name", name)

    def get_user_pw(self, username):
        """ get hash of user pw """
        keys = self.get_all_keys()
        if username in keys:
            res = self.redis.hget(username, "pw_hash")
        else:
            res = None
        return res

    def check_cookie_data(self, request):
        """ check whether cookie was tampered with """
        keys = self.get_all_keys()
        cookie_user_name = request.cookies.get("username")
        if cookie_user_name in keys:
            cookie_sid = request.cookies.get("session_id")
            cookie_game_id = request.cookies.get("game_id")
            saved_session_id = self.redis.hget(cookie_user_name, "session_id")
            if self.redis.hexists(cookie_user_name, "game_id"):
                saved_game_id = self.redis.hget(cookie_user_name, "game_id")
            else:
                saved_game_id = "None"
            return saved_session_id == cookie_sid and (saved_game_id == str(cookie_game_id) or saved_game_id == "None")
        else:
            return False

    def get_other_players(self, user_id):
        """ get other players in the same game """
        keys = self.get_all_keys()
        player_list = {}
        user_game_id = self.redis.hget(user_id, "game_id")
        for key in keys:
            if self.redis.hget(key, "game_id") == str(user_game_id) and str(user_id) != key:
                name, character, solved = self.redis.hmget(key, "name", "character", "solved")
                player_list[key] = {
                    "name": name,
                    "character": character if str(character) != "None" else "-",
                    "solved": solved
                }
        return player_list

    def get_game_pw(self, game_id):
        """ get game pw from host """
        keys = self.get_all_keys()
        res = "None"
        for key in keys:
            if self.redis.hexists(key, "game_host") and self.redis.hget(key, "game_id") == game_id:
                res = str(self.redis.hget(key, "game_pw"))
        return res

    def get_user(self, session_id):
        keys = self.get_all_keys()
        for key in keys:
            if self.redis.hexists(key, "session_id"):
                key_session_id = self.redis.hget(key, "session_id")
                if key_session_id == session_id:
                    return key
        return "None"

    def session_exists(self, session_id):
        keys = self.get_all_keys()
        for key in keys:
            if self.redis.hexists(key, "session_id"):
                key_session_id = self.redis.hget(key, "session_id")
                if key_session_id == session_id:
                    return key
        return False

    def set_user_session(self, user, session_id):
        self.redis.hset(user, "session_id", session_id)

    def get_all_keys(self):
        i = 0
        res = self.redis.scan(i)
        keys = res[1]
        while res[0] != 0:
            res = self.redis.scan(i)
            keys += res[1]
            i += 1
        return set(keys)


def create_app(with_static=True):
    app = Werbinich()
    if with_static:
        app.wsgi_app = SharedDataMiddleware(app.wsgi_app, {
            '/static':  os.path.join(os.path.dirname(__file__), 'static')
        })
        return app

if __name__ == '__main__':
    from werkzeug.serving import run_simple
    app = create_app()
    run_simple('127.0.0.1', 5000, app, use_debugger=True, use_reloader=True)
