""" a server to complement werbinichbot """
import os
import redis

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
        sid = request.cookies.get("session_id")
        if sid is None:
            request.session = session_store.new()
            sid = request.session.sid
        else:
            request.session = session_store.get(sid)
        if request.method == 'POST':
            op = request.form["operation"]
            if self.check_cookie_data(request) or op in ["login", "registration_form", "register"]:
                return getattr(self, op)(request, sid)  # call operation method
            else:
                error = "Falsche Cookiedaten."
        return self.render_template('login.html', error=error)

    def login(self, request, sid):
        """ Handle user login """
        args = list(request.form.keys())
        required = ["username", "login_pw"]
        if not all(item in args for item in required):
            error = "Das funktioniert nicht."
            return self.render_template('login.html', error=error)
        username = request.form["username"]
        pw = request.form["login_pw"]
        pw_hash = self.get_user_pw(username)
        if pw_hash and sha256.verify(pw, pw_hash):
            games_list = self.get_list_of_games()
            success = "Angemeldet."
            saved_game_id = self.redis.hget(username, "game_id")
            response.set_cookie("username", username)
            if saved_game_id != "None":
                success = "Spiel beigetreten."
                player_list = self.get_other_players(username)
                response = self.render_template('game.html', error=None, success=success, player_list=player_list)
                response.set_cookie("game_id", saved_game_id)
                response.set_cookie("session_id", request.session.sid)
                self.redis.hset(username, "session_id", sid)
                return response
            response = self.render_template('join_game.html', error=None, success=success, game_list=games_list)
            if request.session.should_save:
                session_store.save(request.session)
            response.set_cookie("session_id", request.session.sid)
            self.redis.hset(username, "session_id", sid)
            return response
        elif pw_hash:
            error = "Falsches Passwort."
        else:
            error = "Nutzer nicht gefunden."
        return self.render_template("login.html", error=error)

    def registration_form(self, request, sid):
        return self.render_template('registration_form.html', error=None)

    def register(self, request, sid):
        """ handle user registration """
        args = list(request.form.keys())
        required = ["username", "pw", "name", "pw_confirm"]
        if not all(item in args for item in required):
            error = "Das funktioniert nicht."
            return self.render_template('login.html', error=error)
        username = request.form["username"]
        keys = self.redis.scan(0)[1]
        if username in keys:
            error = "Diese:r Nutzer:in existiert bereits."
            return self.render_template('registration_form.html', error=error)
        name = request.form["name"]
        pw = request.form["pw"]
        pw_confirm = request.form["pw_confirm"]
        if pw == pw_confirm:
            self.set_user_name_and_pw(username, name, pw)
        games_list = self.get_list_of_games()
        success = "Registriert und angemeldet."
        response = self.render_template('join_game.html', error=None, success=success, game_list=games_list)
        response.set_cookie("username", username)
        if request.session.should_save:
            session_store.save(request.session)
        response.set_cookie("session_id", request.session.sid)
        self.redis.hset(username, "session_id", sid)
        return response

    def join_game(self, request, sid):
        args = list(request.form.keys())
        required = ["game_id", "game_pw"]
        if not all(item in args for item in required):
            error = "Das funktioniert nicht."
            return self.render_template('login.html', error=error)
        cookie_user_name = request.cookies.get("username")
        game_id = request.form["game_id"]
        game_pw = request.form["game_pw"]
        games_list = self.get_list_of_games()
        if game_id in games_list:# if game exists
            pw_hash = self.get_game_pw(game_id)
            if sha256.verify(game_pw, pw_hash):#... and pw is correct
                self.redis.hset(cookie_user_name, "game_id", game_id)
                player_list = self.get_other_players(cookie_user_name)
                success = "Spiel beigetreten."
                response = self.render_template('game.html', error=None, success=success, player_list=player_list)
                response.set_cookie("game_id", game_id)
            else:# game exists, pw incorrect
                response = self.render_template('join_game.html', error="Falsches Passwort", game_list=games_list)
        else:
            # create game
            self.redis.hset(cookie_user_name, "game_host", "true")
            pw_hash = sha256.hash(game_pw)
            self.redis.hset(cookie_user_name, "game_pw", pw_hash)
            self.redis.hset(cookie_user_name, "game_id", game_id)
            player_list = self.get_other_players(cookie_user_name)
            response = self.render_template('game.html', error=None, player_list=player_list)
            response.set_cookie("game_id", game_id)
        return response

    def set_player_character(self, request, sid):
        args = list(request.form.keys())
        required = ["player", "character"]
        if not all(item in args for item in required):
            error = "Das funktioniert nicht."
            return self.render_template('login.html', error=error)
        cookie_user_name = request.cookies.get("username")
        player_id = request.form["player"]
        player_character = request.form["character"]
        self.redis.hset(player_id, "character", player_character)
        player_list = self.get_other_players(cookie_user_name)
        response = self.render_template('game.html', error=None, player_list=player_list)
        return response

    def reload_game(self, request, sid):
        cookie_user_name = request.cookies.get("username")
        player_list = self.get_other_players(cookie_user_name)
        response = self.render_template('game.html', error=None, success=None, player_list=player_list)
        return response

    def leave_game(self, request, sid):
        cookie_user_name = request.cookies.get("username")
        if "game_host" in self.redis.hkeys(cookie_user_name):
            game_id = request.cookies.get("game_id")
            other_players = self.get_other_players(cookie_user_name)
            game_pw = self.redis.hget(cookie_user_name, "game_pw")
            self.redis.hdel(cookie_user_name, "game_pw")
            self.redis.hdel(cookie_user_name, "game_host")
            if other_players:
                new_host = next(iter(other_players.keys()))
                self.redis.hset(new_host, "game_host", "true")
                self.redis.hset(new_host, "game_pw", game_pw)
        games_list = self.get_list_of_games()
        response = self.render_template('join_game.html', error=None, game_list=games_list)
        response.set_cookie("game_id", "None")
        self.redis.hset(cookie_user_name, "game_id", "None")
        return response

    def get_list_of_games(self):
        """ get a `set` of game IDs """
        keys = self.redis.scan(0)[1]
        games_list = []
        if keys:
            for key in keys:
                game_id = self.redis.hget(key, "game_id") or "None"
                if not game_id in games_list and game_id != "None":
                    games_list.append(game_id)
        return games_list

    def set_user_name_and_pw(self, username, name, password):
        """ insert name, pw into db """
        pw_hash = sha256.hash(password)
        self.redis.hset(username, "pw_hash", pw_hash)
        self.redis.hset(username, "name", name)

    def get_user_pw(self, username):
        """ get hash of user pw """
        keys = self.redis.scan(0)[1]
        if username in keys:
            res = self.redis.hget(username, "pw_hash")
        else:
            res = None
        return res

    def check_cookie_data(self, request):
        keys = self.redis.scan(0)[1]
        cookie_user_name = request.cookies.get("username")
        if cookie_user_name in keys:
            cookie_sid = request.cookies.get("session_id")
            cookie_game_id = request.cookies.get("game_id")
            saved_session_id = self.redis.hget(cookie_user_name, "session_id")
            saved_game_id = self.redis.hget(cookie_user_name, "game_id")
            return saved_session_id == cookie_sid and saved_game_id == cookie_game_id
        else:
            return False

    def get_other_players(self, user_id):
        """ get other players in the same game """
        keys = self.redis.scan(0)[1]
        player_list = {}
        user_game_id = self.redis.hget(user_id, "game_id")
        for key in keys:
            if self.redis.hget(key, "game_id") == str(user_game_id) and str(user_id) != key:
                player_list[key] = {
                    "name": self.redis.hget(key, "name"),
                    "character": self.redis.hget(key, "character")
                }
        return player_list

    def get_game_pw(self, game_id):
        """ get game pw from host """
        keys = self.redis.scan(0)[1]
        res = "None"
        for key in keys:
            if "game_host" in self.redis.hkeys(key) and self.redis.hget(key, "game_id") == game_id:
                res = str(self.redis.hget(key, "game_pw"))
        return res

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
