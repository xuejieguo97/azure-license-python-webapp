from email.policy import default
import uuid
import requests
from flask import Flask, render_template, session, request, redirect, url_for, flash, abort
from flask_session import Session  # https://pythonhosted.org/Flask-Session
import msal
from sqlalchemy import false, null
import app_config
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.config.from_object(app_config)
Session(app)
# app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///example.sqlite"
db = SQLAlchemy(app)

# This section is needed for url_for("foo", _external=True) to automatically
# generate http scheme when this sample is running on localhost,
# and to generate https scheme when it is deployed behind reversed proxy.
# See also https://flask.palletsprojects.com/en/1.0.x/deploying/wsgi-standalone/#proxy-setups
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# define the model
user_licenses = db.Table(
    'user_licenses',
    db.Column('user_email', db.String(50), db.ForeignKey('user.email'), primary_key=True),
    db.Column('license_id', db.Integer, db.ForeignKey('license.id'), primary_key=True)
)
class User(db.Model):
    __tablename__ = "user"
    email = db.Column(db.String(50), primary_key=True)
    firstname = db.Column(db.String(80), nullable=False)
    lastname = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    licenses = db.relationship("License", backref="owner", lazy=True)
    user_licenses = db.relationship("License", secondary=user_licenses, back_populates="users")

    def __init__(self, email, firstname, lastname, is_admin=False):
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.is_admin = is_admin

    def __repr__(self):
           return '<User %r>' % self.username

class License(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(200), nullable=True)
    owner_email = db.Column(db.Integer, db.ForeignKey('user.email'), nullable=False)
    users = db.relationship("User", secondary=user_licenses, back_populates="user_licenses")

    def __init__(self, name, description, owner_email):
        self.name = name
        self.description = description
        self.owner_email = owner_email



@app.before_first_request
def create_tables():
    db.create_all()
    if User.query.filter_by(email="xuejieguo97@gmail.com").count() == 0:
        admin_user = User('xuejieguo97@gmail.com', "Xuejie", "Guo", True)
        db.session.add(admin_user)
        db.session.commit()


@app.route("/")
def index():
    if not session.get("user"):
        return redirect(url_for("login"))
    email = session['user']['emails'][0]
    user = User.query.filter_by(email=email).first()
    users = User.query.filter_by(is_admin=False)
    return render_template('index.html', licenses=user.user_licenses, user=user, users=users, version=msal.__version__)

@app.route("/login")
def login():
    # Technically we could use empty list [] as scopes to do just sign in,
    # here we choose to also collect end user consent upfront
    session["flow"] = _build_auth_code_flow(scopes=app_config.SCOPE)
    return render_template("login.html", auth_url=session["flow"]["auth_uri"], version=msal.__version__)


@app.route(app_config.REDIRECT_PATH)  # Its absolute URL must match your app's redirect_uri set in AAD
def authorized():
    try:
        cache = _load_cache()
        result = _build_msal_app(cache=cache).acquire_token_by_auth_code_flow(
            session.get("flow", {}), request.args)
        if "error" in result:
            return render_template("auth_error.html", result=result)
        session["user"] = result.get("id_token_claims")
        # save user in the db
        email = session['user']['emails'][0]
        _add_new_user(email)
        _save_cache(cache)
    except ValueError:  # Usually caused by CSRF
        pass  # Simply ignore them
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.clear()  # Wipe out user and its token cache from session
    return redirect(  # Also logout from your tenant's web session
        app_config.AUTHORITY + "/oauth2/v2.0/logout" +
        "?post_logout_redirect_uri=" + url_for("index", _external=True))


@app.route("/license_add", methods=["GET", "POST"])
def add():
    if not session.get("user"):
        return redirect(url_for("login"))
    if request.method == "POST":
        if not request.form["name"]:
            flash("Title is required", "error")
        else:
            email = session['user']['emails'][0]
            user = User.query.filter_by(email=email).first()
            # only admin user can add license
            if (user.is_admin):
                new_license = License(request.form["name"], request.form["description"], email)
                db.session.add(new_license)
                user.user_licenses.append(new_license)
                db.session.add(user)
                db.session.commit()
            return redirect(url_for("index"))
    return render_template("portal.html")


@app.route('/license/<int:license_id>', methods=['GET', "POST"])
def license(license_id):
    if not session.get("user"):
        return redirect(url_for("login"))
    license = License.query.filter_by(id=license_id).first()
    if license == None:
            abort(404)
    if license.owner_email != session['user']['emails'][0]:
        return redirect(url_for("index"))
    users = User.query.filter_by(is_admin=False).all()
    if request.method == "POST":
        if not request.form['user']:
            print('user is empty')
            flash("User should not be empty")
        else:
            user = User.query.filter_by(email=request.form['user']).first()
            print(request.form['user'])
            user.user_licenses.append(license)
            db.session.add(user)
            db.session.commit()
        return redirect(url_for('license', license_id=license_id))
    return render_template('license.html', license=license, users=users)


@app.route('/users/<string:user_email>', methods=['GET'])
def delete_user(user_email):
    user = User.query.filter_by(email=user_email).first()
    if user == None:
        abort(404)
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('index'))


# @app.route("/graphcall")
# def graphcall():
#     token = _get_token_from_cache(app_config.SCOPE)
#     if not token:
#         return redirect(url_for("login"))
#     graph_data = requests.get(  # Use token to call downstream service
#         app_config.ENDPOINT,
#         headers={'Authorization': 'Bearer ' + token['access_token']},
#         ).json()
#     return render_template('display.html', result=graph_data)


def _add_new_user(email):
    if User.query.filter_by(email=email).count() == 0:
        firstname = session['user']['given_name']
        lastname = session['user']['family_name']
        new_user = User(email, firstname, lastname, False)
        db.session.add(new_user)
        db.session.commit()


def _load_cache():
    cache = msal.SerializableTokenCache()
    if session.get("token_cache"):
        cache.deserialize(session["token_cache"])
    return cache


def _save_cache(cache):
    if cache.has_state_changed:
        session["token_cache"] = cache.serialize()


def _build_msal_app(cache=None, authority=None):
    return msal.ConfidentialClientApplication(
        app_config.CLIENT_ID, authority=authority or app_config.AUTHORITY,
        client_credential=app_config.CLIENT_SECRET, token_cache=cache)


def _build_auth_code_flow(authority=None, scopes=None):
    return _build_msal_app(authority=authority).initiate_auth_code_flow(
        scopes or [],
        redirect_uri=url_for("authorized", _external=True))


def _get_token_from_cache(scope=None):
    cache = _load_cache()  # This web app maintains one cache per session
    cca = _build_msal_app(cache=cache)
    accounts = cca.get_accounts()
    if accounts:  # So all account(s) belong to the current signed-in user
        result = cca.acquire_token_silent(scope, account=accounts[0])
        _save_cache(cache)
        return result


app.jinja_env.globals.update(_build_auth_code_flow=_build_auth_code_flow)  # Used in template

if __name__ == "__main__":
    app.run(host='0.0.0.0',port=5000)

