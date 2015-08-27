__author__ = 'davidkavanagh'

from flask import Flask, render_template
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, CatalogItem

app = Flask(__name__)

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

session = DBSession()

@app.route('/')
def index():
    # May limit to first whatever number
    categories = session.query(Category).all()
    items = session.query(CatalogItem).all()

    return render_template('index.html', categories=categories, items=items)


if __name__=="__main__":
    app.debug = True
    app.run(host='0.0.0.0', port=5000)