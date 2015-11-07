__author__ = 'davidkavanagh'

import os
import random
import string
import httplib2
import json
import requests
from functools import wraps
import filecmp
from flask import Flask, render_template, redirect, request, url_for, make_response, flash, abort, jsonify
from flask import session as login_session

from werkzeug import secure_filename

from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

from database_setup import Base, Category, CatalogItem


app = Flask(__name__)

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

session = DBSession()

CLIENT_ID = json.loads(
    open('client_secret.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "UDACITY Catalog App"


STATIC_DIR = 'static/'
ALLOWED_IMG_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

app.config.update({
    'STATIC_DIR': 'static',
    'ITEM_IMAGES': 'catalog_images'
})


def generate_csrf_token():
    if '_csrf_token' not in login_session:
        login_session['_csrf_token'] = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    return login_session['_csrf_token']


def check_for_csrf():
    token = login_session.pop('_csrf_token', None)
    if not token or token != request.form['_csrf_token']:
        abort(403)
    else:
        return None


def login_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if 'username' not in login_session:
            flash('You must login to access that page')
            return redirect('/')
        return func(*args, **kwargs)
    return decorated_view

@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=login_session['state'])


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
        print filename
        # save path to image without 'static/' prepended to path

        db_path = os.path.join(app.config['ITEM_IMAGES'], filename)
        # but actually save in static
        save_path = os.path.join(app.config['STATIC_DIR'], db_path)
        print db_path
        print save_path

        if os.path.exists(save_path):
            tmp_path = save_path + '_tmp'
            image_object.save(tmp_path)
            if not filecmp.cmp(save_path, tmp_path):
                os.remove(save_path)
                os.rename(tmp_path, save_path)

        else:
            image_object.save(save_path)

        return db_path

    else:
        return None

'''
@app.context_processor
def set_state():
    """
    Create the anti-forgery state token
    In order to log the user in from any page, there must be a state token ready at all times.
    This context processor checks if a state has already been generates for this session,
    then generates (or retrieves) and inserts a state to all pages.
    """
    try:
        state = login_session['state']
    except KeyError:
        state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
        login_session['state'] = state
    return dict(STATE=state)
'''

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
        oauth_flow = flow_from_clientsecrets('client_secret.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
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

    flash("you are now logged in as %s" % login_session['username'])

    return 'Login Successful!'


@app.route('/gdisconnect')
def gdisconnect(next_url='/'):
        # Only disconnect a connected user.
    access_token = login_session.get('credentials')
    if access_token is None:
        flash("No User connected!")
        return redirect(next_url) # validate next_url

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

        flash("User logged out!")
        return redirect(next_url)# validate next_url
    else:
        # For whatever reason, the given token was invalid.
        login_session.clear()
        flash('Something went wrong there!')
        return redirect(next_url)# validate next_url



@app.route('/')
def index():
    # May limit to first whatever number
    categories = session.query(Category).all()

    cat_counts = session.query(
        Category,
        func.count(Category.id).label('num')
    ).join(
        CatalogItem
    ).group_by(Category.id).order_by('num DESC')

    for c in cat_counts:
        print c.Category.title
        print c.num

    items = session.query(CatalogItem).all()

    return render_template('index.html', categories=categories, items=items, cat_counts=cat_counts)


@app.route('/item/<int:item_id>/')
def view_item(item_id):
    item = session.query(CatalogItem).get(item_id)
    return render_template('view_item.html', item=item)


@app.route('/item/add/', methods=['GET','POST'])
@login_required
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

@app.route('/item/edit/<int:item_id>/', methods=['GET', 'POST'])
@login_required
def edit_item(item_id):
    item = session.query(CatalogItem).get(item_id)

    if request.method == 'POST':
        #form checking???
        title = request.form['title']
        item.title = title

        description = request.form['description']
        item.description = description

        category_id = int(request.form['category_id'])
        category = session.query(Category).get(category_id)
        item.category = category

        image = request.files['image']
        image_path = store_image_to_media(image)
        if image_path is not None:
            item.image_path = image_path

        session.add(item)
        session.commit()

        return redirect(url_for('view_item', item_id=item.id))

    categories = session.query(Category).all()

    return render_template('edit_item.html', item=item, categories=categories)


@app.route('/item/delete/<int:item_id>/', methods=['GET', 'POST'])
@login_required
def delete_item(item_id):
    item = session.query(CatalogItem).get(item_id)
    category_id = item.category.id
    if request.method == 'POST':

        check_for_csrf()

        session.delete(item)
        session.commit()

        return redirect(url_for('view_category', category_id=category_id))
    else:
        return render_template('delete_item.html', item=item, csrf_token=generate_csrf_token)


@app.route('/category/<int:category_id>/')
def view_category(category_id):
    category = session.query(Category).get(category_id)
    items = session.query(CatalogItem).filter_by(category_id=category_id)
    return render_template('view_category.html', category=category, items=items)


@app.route('/category/add/', methods=['GET', 'POST'])
@login_required
def add_category():
    if request.method == 'POST':
        title = request.form['category-title']
        new_category = Category(title=title)

        session.add(new_category)
        session.commit()

        return redirect(url_for('view_category', category_id=new_category.id))

    return render_template('add_new_category.html')


#JSON API METHODS HERE
@app.route('/api/json/item/<int:item_id>/', methods=['GET'])
def get_item_json(item_id):
    item = session.query(CatalogItem).get(item_id)
    return jsonify(item.serialize())

@app.route('/api/json/category/<int:category_id>/')
def get_category_json(category_id):
    category = session.query(Category).get(category_id)
    items = session.query(CatalogItem).filter_by(category_id=category_id)
    return jsonify(Category=category.serialize(), CategoryItems=[i.serialize() for i in items])

@app.route('/api/json/item/')
def get_all_items_json():
    items = session.query(CatalogItem).all()
    return jsonify(Items=[i.serialize() for i in items])

@app.route('/api/json/category/')
def get_all_categories_json():
    cats = session.query(Category).all()
    return jsonify(Categories=[i.serialize() for i in cats])

if __name__=="__main__":
    app.secret_key = 'this_is_a_very_secure_password'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)