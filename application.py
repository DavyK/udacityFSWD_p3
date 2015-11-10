__author__ = 'davidkavanagh'

import os
import random
import string
import httplib2
import json
import requests
from functools import wraps
import datetime
from flask import Flask, render_template, redirect, request, url_for
from flask import make_response, flash, abort, jsonify
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
ALLOWED_IMG_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config.update({
    'STATIC_DIR': 'static',
    'ITEM_IMAGES': 'catalog_images'
})


def generate_csrf_token():
    """
    generate the cross site request forgery token (random 32
    character string), and add it to the login_session.

    :return: csrf token
    """
    if '_csrf_token' not in login_session:
        login_session['_csrf_token'] = ''.join(
            random.choice(
                string.ascii_uppercase + string.digits
            ) for x in xrange(32)
        )
    return login_session['_csrf_token']


def check_for_csrf(supplied_token):
    """
    Check for the csrf token in the login session and the one
    submitted by the form. If the token is None or not the
    same as the one in the login_session return a 403
    (unauthorized) error. If it is the same, return None

    :return: None or abort(403)
    """
    token = login_session.pop('_csrf_token', None)
    if not token or token != supplied_token:
        abort(403)
    else:
        return None


def login_required(func_to_dec):
    """
    Makes a decorator for protecting pages from anonymous non-logged
    in users.

    :param function (view) that requires user to be logged in:
    :return: decorated function.
    """
    @wraps(func_to_dec)
    def decorated_view(*args, **kwargs):
        if 'username' not in login_session:
            flash('You must login to access that page', 'alert-info')
            return redirect('/')
        return func_to_dec(*args, **kwargs)
    return decorated_view


@app.context_processor
def inject_categories():
    """
    Context processor to ensure categories sidebar is on every page.

    :return: dictionary to the categories and their counts to inserted
    into the response context.
    """
    # May limit to first whatever number
    categories = session.query(Category).all()

    cat_counts = session.query(
        Category,
        func.count(Category.id).label('num')
    ).join(
        CatalogItem
    ).group_by(Category.id).order_by('num DESC')

    return dict(categories=categories, cat_counts=cat_counts)


@app.route('/login')
def show_login():
    """
    Show the login page, and generate a state token to prevent Man
    in the middle attack.

    :return: rendered template of login page
    """
    state = ''.join(
        random.choice(
            string.ascii_uppercase + string.digits
        ) for x in xrange(32)
    )
    login_session['state'] = state
    return render_template('login.html', STATE=login_session['state'])


def allowed_file(filename):
    """
    Check if the extension of the supplied file is an allowed
    type as defined in the app.config dict.

    :param filename: name of file to check extension of.
    :return: true if filename ext is allowed.
    """
    allowed = False
    if '.' in filename:
        extension = filename.rsplit('.', 1)[1]
        if extension in ALLOWED_IMG_EXTENSIONS:
            allowed = True

    return allowed


def store_image_to_media(image_object):
    """
     This function takes the image object submitted by either the
     create or edit item forms, and it ensures the file name is secure
     and prepends it with the current timestamp (down to the
     microsecond).
     It then saves the image in the STATIC_DIR/ITEM_IMAGES folder
     as defined by app.config, and returns the appropriate path
      - ITEM_IMAGES/filename - for saving to the database.

    :param image_object:
    :return: path to image for saving in the DB, or None if the image
    object is none OR the allowed_file check is false.
    """
    if image_object or allowed_file(image_object.filename):
        filename = secure_filename(image_object.filename)

        # prepend timestamp to filename
        now = datetime.datetime.now()
        filename = now.strftime(
            '%Y%m%d%H%M%S%f_{fname}'
        ).format(fname=filename)

        # save path to image without 'static/' prepended to path
        db_path = os.path.join(app.config['ITEM_IMAGES'], filename)
        # but actually save in static
        save_path = os.path.join(app.config['STATIC_DIR'], db_path)

        image_object.save(save_path)

        return db_path

    else:
        return None


def delete_item_image(item_obj):
    """
    delete the image associated with a catalog item.

    :param item_obj: item object
    :return: True if item deleted, False if OSerror (likely because
    file not found)
    """
    try:
        os.remove(os.path.join('static', item_obj.image_path))
        return True
    except OSError:
        return False


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """
    Connect to Google + and sign the user in.

    :return: various response objects
    """
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
    url = (
        'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
        % access_token
    )
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
        response = make_response(json.dumps(
            'Current user is already connected.'
        ), 200)
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

    flash(
        "you are now logged in as %s" % login_session['username'],
        "alert-success"
    )

    return "Login Successful!"


@app.route('/gdisconnect')
def gdisconnect(next_url='/'):
    """
    disconnect from Google+ and sign the user out.

    :param next_url: the next page to be forwared onto
    :return: various redirects, with flash messages.
    """
    # Only disconnect a connected user.
    access_token = login_session.get('credentials')
    if access_token is None:
        flash("No User connected!", 'alert-danger')
        return redirect(next_url)  # validate next_url

    # access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # Reset the user's session.
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        flash("User logged out!", 'alert-success')
        return redirect(next_url)  # validate next_url
    else:
        # For whatever reason, the given token was invalid.
        login_session.clear()
        flash('Something went wrong there!', 'alert-danger')
        return redirect(next_url)  # validate next_url


@app.route('/')
def index():
    """
    Show home page

    :return: rendered tempate of home/index page
    """
    items = session.query(CatalogItem).all()

    return render_template('index.html', items=items)


@app.route('/item/<int:item_id>/')
def view_item(item_id):
    """
    View single item page

    :param item_id: id of the item to be viewed
    :return: rendered template of the view item page.
    """
    item = session.query(CatalogItem).get(item_id)
    return render_template('view_item.html', item=item)


@app.route('/item/add/', methods=['GET', 'POST'])
@login_required
def add_item():
    """
    Show page with add item form.
    If the form was filled out, process the form and add new item
    to database.

    :return: Redirect the user to the new item page on
    a successful additon, else return to the add_item page.
    """
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']

        category_id = int(request.form['category_id'])
        category = session.query(Category).get(category_id)

        image = request.files['image']
        image_path = store_image_to_media(image)

        if image_path is not None:
            new_item = CatalogItem(
                title=title,
                description=description,
                image_path=image_path,
                category=category
            )
            session.add(new_item)
            session.commit()
            return redirect(url_for('view_item', item_id=new_item.id))

    categories = session.query(Category).all()
    return render_template('add_new_item.html', categories=categories)


@app.route('/item/edit/<int:item_id>/', methods=['GET', 'POST'])
@login_required
def edit_item(item_id):
    """
    Show page with add item form.
    If the form was filled out, process the form update the item
    in the database. Make sure old item image is deleted and new
    image is saved.

    :param item_id: id of item to be edited
    :return: Redirect the user to the updated item page on
    a successful edit else return to edit_item page.
    """
    item = session.query(CatalogItem).get(item_id)

    if request.method == 'POST':
        # form checking???
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
            # delete the old image, and then update the new image path
            delete_item_image(item)
            item.image_path = image_path

        session.add(item)
        session.commit()

        return redirect(url_for('view_item', item_id=item.id))

    categories = session.query(Category).all()

    return render_template('edit_item.html', item=item, categories=categories)


@app.route('/item/delete/<int:item_id>/', methods=['GET', 'POST'])
@login_required
def delete_item(item_id):
    """
    Show the delete_item page. If the form is filled out check for
    csrf token, and make sure the item image is also deleted.

    :param item_id: id of item to be deleted.
    :return: Redirect the user to the category page of the deleted
    item, or the delete_item page, or the view_item page on a cancelled
    delete.
    """
    item = session.query(CatalogItem).get(item_id)
    category_id = item.category.id
    if request.method == 'POST':

        check_for_csrf(request.form['_csrf_token'])
        delete_item_image(item)
        session.delete(item)
        session.commit()

        return redirect(url_for('view_category', category_id=category_id))
    else:
        return render_template(
            'delete_item.html',
            item=item,
            csrf_token=generate_csrf_token
        )


@app.route('/category/<int:category_id>/')
def view_category(category_id):
    """
    View Category page and list of all items in that category.

    :param category_id: id of requested category.
    :return: rendered template of category page
    """
    category = session.query(Category).get(category_id)
    items = session.query(CatalogItem).filter_by(category_id=category_id)
    return render_template(
        'view_category.html',
        category=category,
        items=items
    )


@app.route('/category/add/', methods=['GET', 'POST'])
@login_required
def add_category():
    """
    Show add category page with form. If form has been filled out,
    processs the form, and add new category to the database.

    :return: rendered template of the add category page or the new
    category on successful addition.
    """
    if request.method == 'POST':
        title = request.form['category-title']
        new_category = Category(title=title)

        session.add(new_category)
        session.commit()

        return redirect(url_for('view_category', category_id=new_category.id))

    return render_template('add_new_category.html')


# JSON API METHODS HERE
@app.route('/api/json/item/<int:item_id>/', methods=['GET'])
def get_item_json(item_id):
    """
    Return json reprsentation of item.

    :param item_id: id of item to return
    :return: jsonified serialized item.
    """
    item = session.query(CatalogItem).get(item_id)
    return jsonify(item.serialize())


@app.route('/api/json/category/<int:category_id>/')
def get_category_json(category_id):
    """
    Return json reprsentation of a category and its items.

    :param category_id: id of category to return
    :return: jsonified serialized category and items
    """
    category = session.query(Category).get(category_id)
    items = session.query(CatalogItem).filter_by(category_id=category_id)
    return jsonify(
        Category=category.serialize(),
        CategoryItems=[i.serialize() for i in items]
    )


@app.route('/api/json/item/')
def get_all_items_json():
    """
    Return json reprsentation of all items

    :return: jsonified serialized items - all of them
    """
    items = session.query(CatalogItem).all()
    return jsonify(Items=[i.serialize() for i in items])


@app.route('/api/json/category/')
def get_all_categories_json():
    """
    Return json reprsentation of all categories

    :return: jsonified serialized categories
    """
    cats = session.query(Category).all()
    return jsonify(Categories=[i.serialize() for i in cats])


if __name__ == "__main__":
    app.secret_key = 'this_is_a_very_secure_password'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
