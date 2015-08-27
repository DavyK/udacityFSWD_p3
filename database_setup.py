__author__ = 'davidkavanagh'

from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class Category(Base):
    __tablename__ = 'Category'
    id = Column(Integer, primary_key=True)
    title = Column(String(50), nullable=False)


class CatalogItem(Base):
    __tablename__ = 'catalog_items'
    id = Column(Integer, primary_key=True)
    title = Column(String(50), nullable=False)
    description = Column(String(1000), nullable=False)
    image_link = Column(String(200), nullable=False)
    category_id = Column(Integer, ForeignKey('Category.id'))
    category = relationship(Category)


engine = create_engine('sqlite:///catalog.db')
Base.metadata.create_all(engine)



