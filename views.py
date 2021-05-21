from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from .models import User, inventory
from . import db
import re

views = Blueprint('views', __name__)

def removescripts(words):
  cleantextcompile = re.compile('<.*?>')
  cleantext = re.sub(cleantextcompile, '', words)
  return cleantext
  
@views.route('/')
def index():
    return render_template('index.html')

@views.route('/login')
def login():
    return render_template('login.html')

@views.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    if not user:
        flash('Please check your login details and try again.')
        return redirect(url_for('views.login'))
    elif user and not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        return redirect(url_for('views.login'))


    login_user(user, remember=remember)

    return redirect(url_for('views.profile'))

@views.route('/signup')
def signup():
    return render_template('signup.html')

@views.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    user = User.query.filter_by(email=email).first()

    if user:
        flash('Email address already exists.')
        return redirect(url_for('views.signup'))

    new_user = User(email=email, name=name, password=generate_password_hash(password, method='sha256'))

    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('views.login'))

@views.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('views.index'))

@views.route('/profile')
@login_required
def profile():
    user = current_user
    items = inventory.query.filter_by(seller_id=user.id)
    return render_template('profile.html', name=user.name, items = items)

@views.route('/inventorypage')
def inventorypage():
    items = inventory.query.all()
    print(items)
    return render_template('inventory.html', items = items)

@views.route('/inventorycreate')
@login_required
def inventorycreatepage():
    return render_template('createinventory.html')

@views.route('/inventorycreate', methods=["POST"])
@login_required
def inventorycreate():
    item = request.form.get('name')
    price = request.form.get('price')
    item = removescripts(item)
    user = current_user
    inventoryitem = inventory(name=item, price=price, seller_id=user.id)
    db.session.add(inventoryitem)
    db.session.commit()
    return redirect(url_for('views.inventorypage'))

@views.route('/updateitems/<int:nid>', methods=['POST','GET'])
@login_required
def updateitems(nid):
    user = current_user
    item_update = inventory.query.get_or_404(nid)
    item_name = item_update.name
    if request.method == "POST":
        newname = request.form['name']
        newname = removescripts(newname)
        item_update.name = newname
        item_update.price = request.form['price']
        if (item_update.seller_id==current_user.id):
            db.session.commit()
            flash('Succesfully Updates ' + item_name)
            return redirect(url_for('views.profile'))
        else:
            flash('Unable to update ' + item_name)
            return redirect(url_for('views.profile'))
    else:
        return render_template('updateinventory.html', items = item_update)

@views.route('/delete/<int:nid>')
@login_required
def deleteitems(nid):
    print(nid)
    user = current_user
    item_delete = inventory.query.get_or_404(nid)
    print(item_delete)
    item_name = item_delete.name
    if(item_delete.seller_id==current_user.id):
        db.session.delete(item_delete)
        db.session.commit()
        flash('Succesfully Deleted ' + item_name)
        return redirect(url_for('views.profile'))
    else:
        flash('UnSuccesful')
        return redirect(url_for('views.profile'))
