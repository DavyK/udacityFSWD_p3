__author__ = 'davidkavanagh'

import os
import random
import string

from flask import Flask, render_template, redirect, request, url_for, make_response, flash
from flask import session as login_session
from werkzeug import secure_filename
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, CatalogItem

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
import requests

app = Flask(__name__)

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

session = DBSession()

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "UDACITY Catalog App"


STATIC_DIR = 'static/'
ALLOWED_IMG_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

app.config.update({
    'STATIC_DIR': 'static',
    'ITEM_IMAGES': 'catalog_images'
})


def allowed_file(filename):
    allowed = False
    if '.' in filename:
        extension = filename.rsplit('.', 1)[1]
        if extension in ALLOWED_IMG_EXTENSIONS:
            allowed = True

    return allowed


def store_image_to_media(image_object):
    if image_object and allowed_file(image_object.filename):
        filename = secure_filename(image_object.filename)
        # save path to image without 'static/' prepended to path
        image_path = os.path.join(app.config['ITEM_IMAGES'], filename)
        # but actually save in static
        image_object.save(os.path.join(app.config['STATIC_DIR'], image_path))

        return image_path
    else:

        return None

@app.route('/')
def index():
    # May limit to first whatever number
    categories = session.query(Category).all()
    items = session.query(CatalogItem).all()

    return render_template('index.html', categories=categories, items=items)


# Create anti-forgery state token
@app.route('/login/')
def show_login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 100px; height: 100px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


@app.route('/gdisconnect')
def gdisconnect():
        # Only disconnect a connected user.
    access_token = login_session.get('credentials')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    #access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response



@app.route('/item/<int:item_id>/')
def view_item(item_id):
    item = session.query(CatalogItem).get(item_id)

    return render_template('view_item.html', item=item)


@app.route('/item/add/', methods=['GET','POST'])
def add_item():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        category_id = int(request.form['category_id'])

        category = session.query(Category).get(category_id)
        image = request.files['image']

        image_path = store_image_to_media(image)

        if image_path is not None:
            new_item = CatalogItem(title=title, description=description, image_path=image_path, category=category)
            session.add(new_item)
            session.commit()

            return redirect(url_for('view_item', item_id=new_item.id))

    categories = session.query(Category).all()

    return render_template('add_new_item.html', categories=categories)


@app.route('/category/<int:category_id>/')
def view_category(category_id):
    category = session.query(Category).get(category_id)
    items = session.query(CatalogItem).filter_by(category_id=category_id)

    return render_template('view_category.html', category=category, items=items)


@app.route('/category/add/', methods=['GET', 'POST'])
def add_category():
    if request.method == 'POST':
        title = request.form['title']

        new_category = Category(title=title)
        session.add(new_category)
        session.commit()

        return redirect(url_for('view_category', category_id=new_category.id))

    return render_template('add_new_category.html')


if __name__=="__main__":
    #client-id: 1089899698683-8ub3ds0ra6fkjhliiri1j8jdm6d2a219.apps.googleusercontent.com
    app.secret_key = 'this_is_a_very_secure_password'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)