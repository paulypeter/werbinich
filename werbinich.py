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
            return getattr(self, op)(request, sid)  # call operation method
        return self.render_template('login.html', error=error)

    def login(self, request, sid):
        username = request.form["username"]
        pw = request.form["pw"]
        pw_hash = self.get_user_pw(username)
        if pw_hash and sha256.verify(pw, pw_hash):
            games_list = self.get_list_of_games()
            response = self.render_template('join_game.html', error=None, game_list=games_list)
            response.set_cookie("username", username)
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

    def get_user_pw(self, username):
        keys = self.redis.scan(0)[1]
        if username in keys:
            res = self.redis.hget(username, "pw_hash")
        else:
            res = None
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