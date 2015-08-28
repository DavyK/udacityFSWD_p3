__author__ = 'davidkavanagh'

import os
import random
import string

from flask import Flask, render_template, redirect, request, url_for, send_from_directory
from flask import session as login_session
from werkzeug import secure_filename
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, CatalogItem

app = Flask(__name__)

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

session = DBSession()


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

@app.route('/login/')
def show_login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return "The current session state is %s" % login_session['state']

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