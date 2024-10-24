# app.py
from flask import Flask, render_template, make_response, request, redirect, url_for, session, flash, jsonify, abort
from functools import wraps
from database import (init_db, add_link, get_link, get_all_links, update_password, 
                      add_traffic_log, get_traffic_logs, get_total_accesses, 
                      get_blocked_accesses, get_approved_accesses, get_hourly_accesses,
                      clear_old_logs, delete_link, update_link, get_all_products,
                      add_product, get_product, update_product, delete_product, get_all_links_with_products, add_user, get_user, update_user_password, get_all_users, delete_user,get_unique_countries,get_links_by_product,get_filtered_accesses)
import user_agents
import requests
from apscheduler.schedulers.background import BackgroundScheduler
from pytz import timezone
import bcrypt

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta_aqui'  # Substitua por uma chave secreta real

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def admin_panel():
    links = get_all_links()
    return render_template('admin_panel.html', links=links)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user(username)
        if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('admin_panel'))
        else:
            flash('Credenciais inválidas', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        if new_password == confirm_password:
            if update_user_password(session['username'], new_password):
                flash('Senha alterada com sucesso', 'success')
                return redirect(url_for('admin_panel'))
            else:
                flash('Erro ao alterar a senha', 'error')
        else:
            flash('As senhas não coincidem', 'error')
    return render_template('change_password.html')

@app.route('/links')
@login_required
def view_links():
    links = get_all_links_with_products()  # Crie esta função no arquivo database.py
    return render_template('links.html', links=links)

from flask import jsonify

@app.route('/add_link', methods=['POST'])
@login_required
def add_new_link():
    offer_url = request.form['offer_url']
    safe_url = request.form['safe_url']
    device_filter = request.form['device_filter']
    country_filter = request.form['country_filter']
    product_id = request.form.get('product_id')
    
    if product_id == '':
        product_id = None
    
    short_id, access_code = add_link(offer_url, safe_url, device_filter, country_filter, product_id)
    
    return jsonify({
        'success': True,
        'short_id': short_id,
        'access_code': access_code
    }), 200

@app.route('/<short_id>')
def redirect_link(short_id):
    link = get_link(short_id)
    if not link:
        abort(404)  # Link não encontrado

    # Verificar se o cookie existe
    cookie_name = f'cloakopen_{short_id}'
    if request.cookies.get(cookie_name) == 'true':
        return redirect(link['offer_url'])

    ip = get_client_ip()
    user_agent = request.headers.get('User-Agent')
    is_mobile = user_agents.parse(user_agent).is_mobile
    device_type = 'mobile' if is_mobile else 'desktop'
    country_code = get_country_code(ip)
    access_code = request.args.get('access_code')
    
    passed_filter = True
    
    # Verificar filtro de dispositivo
    if (link['device_filter'] == 'mobile_only' and not is_mobile) or \
       (link['device_filter'] == 'desktop_only' and is_mobile):
        passed_filter = False
    
    # Verificar filtro de país
    if link['country_filter'] != 'all' and country_code != link['country_filter']:
        passed_filter = False
    
    # Verificar código de acesso
    if access_code != link['access_code']:
        passed_filter = False
    
    # Registrar o log
    add_traffic_log(short_id, ip, user_agent, country_code, device_type, passed_filter)
    
    if passed_filter:
        response = make_response(redirect(link['offer_url']))
        response.set_cookie(cookie_name, 'true', max_age=30*24*60*60)  # Cookie válido por 30 dias
        return response
    else:
        return render_template('block.html', safe_url=link['safe_url'])

@app.route('/api/link/<short_id>', methods=['GET'])
@login_required
def get_link_api(short_id):
    link = get_link(short_id)
    if link:
        return jsonify(link)
    return jsonify({'error': 'Link not found'}), 404

@app.route('/api/link', methods=['POST'])
@login_required
def add_link_api():
    offer_url = request.form['offer_url']
    safe_url = request.form['safe_url']
    device_filter = request.form['device_filter']
    country_filter = request.form['country_filter']
    short_id = add_link(offer_url, safe_url, device_filter, country_filter)
    return jsonify({'success': True, 'short_id': short_id})

@app.route('/api/link/<short_id>', methods=['PUT'])
@login_required
def update_link_api(short_id):
    offer_url = request.form['offer_url']
    safe_url = request.form['safe_url']
    device_filter = request.form['device_filter']
    country_filter = request.form['country_filter']
    product_id = request.form.get('product_id', None) 
    success = update_link(short_id, offer_url, safe_url, device_filter, country_filter, product_id)
    return jsonify({'success': success})

@app.route('/api/link/<short_id>', methods=['DELETE'])
@login_required
def delete_link_api(short_id):
    success = delete_link(short_id)
    return jsonify({'success': success})

@app.route('/logs')
@login_required
def view_logs():
    logs = get_traffic_logs()
    return render_template('logs.html', logs=logs)

def get_client_ip():
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    return request.remote_addr

def get_country_code(ip):
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}')
        data = response.json()
        if data['status'] == 'success':
            return data['countryCode']
    except Exception as e:
        print(f"Error getting country code: {e}")
    return None

@app.route('/test_ip')
def test_ip():
    ip = get_client_ip()
    country_code = get_country_code(ip)
    return jsonify({
        'ip': ip,
        'country_code': country_code
    })

@app.route('/api/total_accesses')
@login_required
def api_total_accesses():
    filters = {
        'start_date': request.args.get('start_date'),
        'end_date': request.args.get('end_date'),
        'product_id': request.args.get('product_id'),
        'short_id': request.args.get('short_id'),
        'country': request.args.get('country'),
        'device': request.args.get('device')
    }
    return jsonify({'total_accesses': get_total_accesses(filters)})

@app.route('/api/blocked_accesses')
@login_required
def api_blocked_accesses():
    filters = {
        'start_date': request.args.get('start_date'),
        'end_date': request.args.get('end_date'),
        'product_id': request.args.get('product_id'),
        'short_id': request.args.get('short_id'),
        'country': request.args.get('country'),
        'device': request.args.get('device')
    }
    return jsonify({'blocked_accesses': get_blocked_accesses(filters)})

@app.route('/api/approved_accesses')
@login_required
def api_approved_accesses():
    filters = {
        'start_date': request.args.get('start_date'),
        'end_date': request.args.get('end_date'),
        'product_id': request.args.get('product_id'),
        'short_id': request.args.get('short_id'),
        'country': request.args.get('country'),
        'device': request.args.get('device')
    }
    return jsonify({'approved_accesses': get_approved_accesses(filters)})

@app.route('/api/hourly_accesses')
@login_required
def api_hourly_accesses():
    filters = {
        'start_date': request.args.get('start_date'),
        'end_date': request.args.get('end_date'),
        'product_id': request.args.get('product_id'),
        'short_id': request.args.get('short_id'),
        'country': request.args.get('country'),
        'device': request.args.get('device')
    }
    return jsonify({'hourly_accesses': get_hourly_accesses(filters)})

def scheduled_log_cleanup():
    deleted_count = clear_old_logs()
    print(f"Deleted {deleted_count} old log entries.")

@app.route('/products')
@login_required
def view_products():
    products = get_all_products()
    return render_template('products.html', products=products)

@app.route('/api/products', methods=['GET'])
@login_required
def get_products_api():
    products = get_all_products()
    return jsonify(products)

@app.route('/api/products', methods=['POST'])
@login_required
def add_product_api():
    name = request.form['name']
    product_id = add_product(name)
    return jsonify({'success': True, 'id': product_id})

@app.route('/api/products/<int:product_id>', methods=['GET'])
@login_required
def get_product_api(product_id):
    product = get_product(product_id)
    if product:
        return jsonify(product)
    return jsonify({'error': 'Product not found'}), 404

@app.route('/api/products/<int:product_id>', methods=['PUT'])
@login_required
def update_product_api(product_id):
    name = request.form['name']
    success = update_product(product_id, name)
    return jsonify({'success': success})

@app.route('/api/products/<int:product_id>', methods=['DELETE'])
@login_required
def delete_product_api(product_id):
    success = delete_product(product_id)
    return jsonify({'success': success})

@app.route('/users')
@login_required
def view_users():
    return render_template('users.html')

@app.route('/api/users', methods=['GET'])
@login_required
def get_users():
    users = get_all_users()  # Você precisa implementar esta função no arquivo database.py
    return jsonify(users)

@app.route('/api/users', methods=['POST'])
@login_required
def create_user():
    data = request.json
    username = data['username']
    password = data['password']
    success = add_user(username, password)
    return jsonify({'success': success})

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user_route(user_id):
    success = delete_user(user_id)
    return jsonify({'success': success})

@app.route('/api/users/<int:user_id>/change-password', methods=['POST'])
@login_required
def change_user_password(user_id):
    data = request.json
    new_password = data['newPassword']
    success = update_user_password(user_id, new_password)
    return jsonify({'success': success})

@app.route('/api/countries')
@login_required
def get_countries():
    return jsonify(get_unique_countries())  # Implemente esta função no database.py

@app.route('/api/links')
@login_required
def get_filtered_links():
    product_id = request.args.get('product_id')
    return jsonify(get_links_by_product(product_id))  # Implemente esta função no database.py

def init_admin_user():
    try:
        user = get_user('admin')
        if not user:
            initial_password = 'admin'  # Alterado para 'admin'
            add_user('admin', initial_password)
            print("Usuário admin criado com sucesso.")
        else:
            print("Usuário admin já existe.")
    except Exception as e:
        print(f"Erro ao criar usuário admin: {e}")
        raise  # Propaga o erro para poder ser visto

# Configurar o agendador para limpar logs diariamente
scheduler = BackgroundScheduler(timezone=timezone('America/Sao_Paulo'))
scheduler.add_job(scheduled_log_cleanup, 'interval', days=30)
scheduler.start()

if __name__ == '__main__':
    init_db()
    init_admin_user()
    app.run(debug=True, port=3000)

@app.get('/up')
def health_check():
    return {"status": "OK"}