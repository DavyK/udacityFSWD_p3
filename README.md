
Udacity fullstack web developer nanodegree - catalog app project
================================================================

The catalog app allows users to see a list of items added to a catalog, along with the categories 
those items belong too.
Logged in users can be add new items to the catalog through the web interface, as well as modified and deleted.

The app provides JSON endpoints for retrieving the catalog's items and the categories.

Requirments:
------------
* Virtual Box 4.3.28
* Vagrant
* Python 2.7+
* Flask 0.10.1

This code is developed inside a vagrant virtual box VM.

run:

    git clone http://github.com/udacity/fullstack-nanodegree-vm fullstack
    cd fullstack/vagrant
    vagrant up
    vagrant ssh 
    cd /vagrant/catalog


To obtain the same starting dev environment. By default the unmodified starting code of this project will live in: 

    /vagrant/catalog
    
To get this instance of the catalog app then enter:

    rm -r catalog
    git clone git@github.com:DavyK/udacityFSWD_p3.git


Installation:
-------------

**NOTE: if you run the application with the included catalog.db database, you may skip these steps.

To setup the database first run:

    python database_setup.py

To add an initial category and item to the database (mostly for testing) run:

    python populate_database.py
    
    
Running the Application:
------------------------
    
To run the webserver that comes with flask enter:
    
    python application.py
    
By default this makes the web app accessible at http://0.0.0.0:8000

JSON API:
---------

get a specific item in json format

    /api/json/item/<item_id>/

get all items

    /api/json/item/

get specific category and its items

    /api/json//category/<category_id>/
 
get all categories
    
    /api/json/category/
   









