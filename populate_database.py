__author__ = 'davidkavanagh'

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base, Category, CatalogItem

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

session = DBSession()

"""
Create a category and add an item to it.
"""
my_first_category = Category(title='Gaming')
session.add(my_first_category)
session.commit()

my_first_item = CatalogItem(
    title='d20',
    description='A 20 sided die, most commonly used in table-top roleplaying games, such as D&D.',
    image_link='catalog_images/d20.jpeg',
    category=my_first_category
)
session.add(my_first_item)
session.commit()






