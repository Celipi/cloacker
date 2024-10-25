# database.py
import os
import psycopg2
from psycopg2 import sql
import shortuuid
from datetime import datetime, timedelta
from pytz import timezone
import random
import string
import bcrypt

DB_USER = os.getenv('POSTGRES_USER', 'postgres')
DB_PASSWORD = os.getenv('POSTGRES_PASSWORD')
DB_HOST = os.getenv('POSTGRES_HOST', 'cloacker-db')
DB_NAME = os.getenv('POSTGRES_DB', 'cloacker')
DB_PORT = os.getenv('POSTGRES_PORT', '5432')

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

def generate_access_code():
    digits = ''.join(random.choices(string.digits, k=4))
    letters = ''.join(random.choices(string.ascii_uppercase, k=3))
    return f"{digits}{letters}"

def init_db():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    
    # Criar tabela de produtos
    cur.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL
        )
    """)
    
    # Criar tabela de links
    cur.execute("""
        CREATE TABLE IF NOT EXISTS links (
            id SERIAL PRIMARY KEY,
            short_id TEXT UNIQUE NOT NULL,
            offer_url TEXT NOT NULL,
            safe_url TEXT NOT NULL,
            device_filter TEXT NOT NULL,
            country_filter TEXT NOT NULL,
            access_code TEXT NOT NULL
        )
    """)
    
    # Criar tabela de logs de tráfego
    cur.execute("""
        CREATE TABLE IF NOT EXISTS traffic_logs (
            id SERIAL PRIMARY KEY,
            short_id TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            user_agent TEXT NOT NULL,
            country_code TEXT,
            device_type TEXT NOT NULL,
            passed_filter BOOLEAN NOT NULL,
            timestamp TIMESTAMPTZ NOT NULL
        )
    """)
    
    # Adicionar coluna product_id à tabela links
    cur.execute("""
        ALTER TABLE links
        ADD COLUMN IF NOT EXISTS product_id INTEGER REFERENCES products(id)
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS login (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS ab_tests (
            id SERIAL PRIMARY KEY,
            test_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            device_filter TEXT NOT NULL,
            country_filter TEXT NOT NULL,
            access_code TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ab_test_urls (
            id SERIAL PRIMARY KEY,
            test_id TEXT REFERENCES ab_tests(test_id) ON DELETE CASCADE,
            url TEXT NOT NULL,
            visits INTEGER DEFAULT 0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    
    conn.commit()
    cur.close()
    conn.close()
    create_login_table()

def create_login_table():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS login (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    cur.close()
    conn.close()

def add_traffic_log(short_id, ip_address, user_agent, country_code, device_type, passed_filter):
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    
    # Usar timezone São Paulo
    sp_timezone = timezone('America/Sao_Paulo')
    current_time = datetime.now(sp_timezone)
    
    cur.execute(
        "INSERT INTO traffic_logs (short_id, ip_address, user_agent, country_code, device_type, passed_filter, timestamp) VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (short_id, ip_address, user_agent, country_code, device_type, passed_filter, current_time)
    )
    conn.commit()
    cur.close()
    conn.close()

def get_traffic_logs(limit=100):
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("""
        SELECT 
            id, 
            short_id, 
            ip_address, 
            user_agent, 
            country_code, 
            device_type, 
            passed_filter, 
            timestamp AT TIME ZONE 'America/Sao_Paulo' as timestamp
        FROM traffic_logs 
        ORDER BY timestamp DESC 
        LIMIT %s
    """, (limit,))
    logs = cur.fetchall()
    cur.close()
    conn.close()
    
    # Formatar o timestamp diretamente aqui
    return [
        {
            'id': log[0],
            'short_id': log[1],
            'ip_address': log[2],
            'user_agent': log[3],
            'country_code': log[4],
            'device_type': log[5],
            'passed_filter': log[6],
            'timestamp': log[7].strftime('%d/%m/%Y %H:%M')  # Formatação feita aqui
        }
        for log in logs
    ]

def add_link(offer_url, safe_url, device_filter, country_filter, product_id):
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    short_id = shortuuid.uuid()[:8]
    access_code = generate_access_code()
    cur.execute(
        "INSERT INTO links (short_id, offer_url, safe_url, device_filter, country_filter, access_code, product_id) VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (short_id, offer_url, safe_url, device_filter, country_filter, access_code, product_id if product_id else None)
    )
    conn.commit()
    cur.close()
    conn.close()
    return short_id, access_code

def get_link(short_id):
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("SELECT * FROM links WHERE short_id = %s", (short_id,))
    link = cur.fetchone()
    cur.close()
    conn.close()
    if link:
        return {
            'id': link[0],
            'short_id': link[1],
            'offer_url': link[2],
            'safe_url': link[3],
            'device_filter': link[4],
            'country_filter': link[5],
            'access_code': link[6]
        }
    return None

def get_all_links():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("SELECT * FROM links")
    links = cur.fetchall()
    cur.close()
    conn.close()
    return [
        {
            'id': link[0],
            'short_id': link[1],
            'offer_url': link[2],
            'safe_url': link[3],
            'device_filter': link[4],
            'country_filter': link[5]
        }
        for link in links
    ]

def get_all_links_with_products():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("""
        SELECT l.*, p.name as product_name 
        FROM links l 
        LEFT JOIN products p ON l.product_id = p.id
    """)
    links = cur.fetchall()
    cur.close()
    conn.close()
    return [
        {
            'id': link[0],
            'short_id': link[1],
            'offer_url': link[2],
            'safe_url': link[3],
            'device_filter': link[4],
            'country_filter': link[5],
            'access_code': link[6],
            'product_id': link[7],
            'product_name': link[8]
        }
        for link in links
    ]

def update_password(username, new_password_hash):
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("UPDATE users SET password = %s WHERE username = %s", (new_password_hash, username))
    conn.commit()
    cur.close()
    conn.close()


def get_total_accesses(filters=None):
    return get_filtered_accesses(filters)

def get_blocked_accesses(filters=None):
    return get_filtered_accesses(filters, passed_filter=False)

def get_approved_accesses(filters=None):
    return get_filtered_accesses(filters, passed_filter=True)

def get_filtered_accesses(filters=None, passed_filter=None):
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    try:
        query = "SELECT COUNT(*) FROM traffic_logs"
        conditions = []
        params = []

        if passed_filter is not None:
            conditions.append("passed_filter = %s")
            params.append(passed_filter)

        if filters:
            if filters.get('start_date'):
                conditions.append("timestamp >= %s::timestamptz")
                start_date = f"{filters['start_date']} 00:00:00 America/Sao_Paulo"
                params.append(start_date)
            
            if filters.get('end_date'):
                conditions.append("timestamp <= %s::timestamptz")
                end_date = f"{filters['end_date']} 23:59:59 America/Sao_Paulo"
                params.append(end_date)
            
            if filters.get('product_id'):
                conditions.append("""
                    short_id IN (
                        SELECT short_id 
                        FROM links 
                        WHERE product_id = %s
                    )
                """)
                params.append(filters['product_id'])
            
            if filters.get('short_id'):
                conditions.append("short_id = %s")
                params.append(filters['short_id'])
            
            if filters.get('country'):
                conditions.append("country_code = %s")
                params.append(filters['country'])
            
            if filters.get('device'):
                conditions.append("device_type = %s")
                params.append(filters['device'])

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        cur.execute(query, params)
        return cur.fetchone()[0]
    except Exception as e:
        print(f"Error getting filtered accesses: {e}")
        return 0
    finally:
        cur.close()
        conn.close()

def get_hourly_accesses(filters=None):
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    try:
        query = """
            SELECT 
                date_trunc('hour', timestamp AT TIME ZONE 'America/Sao_Paulo') as hour,
                COUNT(*) as count
            FROM traffic_logs
        """
        conditions = []
        params = []

        if filters:
            if filters.get('start_date'):
                conditions.append("timestamp >= %s::timestamptz")
                start_date = f"{filters['start_date']} 00:00:00 America/Sao_Paulo"
                params.append(start_date)
            
            if filters.get('end_date'):
                conditions.append("timestamp <= %s::timestamptz")
                end_date = f"{filters['end_date']} 23:59:59 America/Sao_Paulo"
                params.append(end_date)
            
            if filters.get('product_id'):
                conditions.append("""
                    short_id IN (
                        SELECT short_id 
                        FROM links 
                        WHERE product_id = %s
                    )
                """)
                params.append(filters['product_id'])
            
            if filters.get('short_id'):
                conditions.append("short_id = %s")
                params.append(filters['short_id'])
            
            if filters.get('country'):
                conditions.append("country_code = %s")
                params.append(filters['country'])
            
            if filters.get('device'):
                conditions.append("device_type = %s")
                params.append(filters['device'])

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += """
            GROUP BY hour
            ORDER BY hour ASC
        """

        cur.execute(query, params)
        results = cur.fetchall()
        
        return [
            {
                'hour': result[0].strftime('%Y-%m-%d %H:00'),
                'count': result[1]
            }
            for result in results
        ]
    except Exception as e:
        print(f"Error getting hourly accesses: {e}")
        return []
    finally:
        cur.close()
        conn.close()


def update_link(short_id, offer_url, safe_url, device_filter, country_filter, product_id):
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute(
        "UPDATE links SET offer_url = %s, safe_url = %s, device_filter = %s, country_filter = %s, product_id = %s WHERE short_id = %s",
        (offer_url, safe_url, device_filter, country_filter, product_id if product_id else None, short_id)
    )
    success = cur.rowcount > 0
    conn.commit()
    cur.close()
    conn.close()
    return success

def delete_link(short_id):
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM links WHERE short_id = %s", (short_id,))
        success = cur.rowcount > 0
        conn.commit()
    except Exception as e:
        print(f"Error deleting link: {e}")
        conn.rollback()
        success = False
    finally:
        cur.close()
        conn.close()
    return success

def create_products_table():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL
        )
    """)
    conn.commit()
    cur.close()
    conn.close()

def add_product_id_to_links():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("""
        ALTER TABLE links
        ADD COLUMN IF NOT EXISTS product_id INTEGER REFERENCES products(id)
    """)
    conn.commit()
    cur.close()
    conn.close()

def add_product(name):
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("INSERT INTO products (name) VALUES (%s) RETURNING id", (name,))
    product_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return product_id

def get_all_products():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("SELECT * FROM products")
    products = cur.fetchall()
    cur.close()
    conn.close()
    return [{'id': p[0], 'name': p[1]} for p in products]

def get_product(product_id):
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("SELECT * FROM products WHERE id = %s", (product_id,))
    product = cur.fetchone()
    cur.close()
    conn.close()
    return {'id': product[0], 'name': product[1]} if product else None

def update_product(product_id, name):
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("UPDATE products SET name = %s WHERE id = %s", (name, product_id))
    success = cur.rowcount > 0
    conn.commit()
    cur.close()
    conn.close()
    return success

def delete_product(product_id):
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("DELETE FROM products WHERE id = %s", (product_id,))
    success = cur.rowcount > 0
    conn.commit()
    cur.close()
    conn.close()
    return success

def add_user(username, password):
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    try:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cur.execute("INSERT INTO login (username, password) VALUES (%s, %s)", (username, hashed_password))
        conn.commit()
        success = True
    except Exception as e:
        print(f"Error adding user: {e}")
        conn.rollback()
        success = False
    finally:
        cur.close()
        conn.close()
    return success

def get_user(username):
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("SELECT * FROM login WHERE username = %s", (username,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    return user

def update_user_password(user_id, new_password):
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    try:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cur.execute("UPDATE login SET password = %s WHERE id = %s", (hashed_password, user_id))
        conn.commit()
        success = cur.rowcount > 0
    except Exception as e:
        print(f"Error updating password: {e}")
        conn.rollback()
        success = False
    finally:
        cur.close()
        conn.close()
    return success

def get_all_users():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("SELECT id, username FROM login")
    users = cur.fetchall()
    cur.close()
    conn.close()
    return [{'id': user[0], 'username': user[1]} for user in users]

def delete_user(user_id):
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    try:
        cur.execute("SELECT username FROM login WHERE id = %s", (user_id,))
        username = cur.fetchone()
        if username and username[0] != 'admin':
            cur.execute("DELETE FROM login WHERE id = %s", (user_id,))
            conn.commit()
            success = True
        else:
            success = False
    except Exception as e:
        print(f"Error deleting user: {e}")
        conn.rollback()
        success = False
    finally:
        cur.close()
        conn.close()
    return success

def clear_old_logs():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    
    sp_timezone = timezone('America/Sao_Paulo')
    thirty_days_ago = datetime.now(sp_timezone) - timedelta(days=30)
    
    cur.execute("DELETE FROM traffic_logs WHERE timestamp < %s", (thirty_days_ago,))
    
    deleted_count = cur.rowcount
    conn.commit()
    cur.close()
    conn.close()
    
    return deleted_count

def get_unique_countries():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT DISTINCT country_code 
            FROM traffic_logs 
            WHERE country_code IS NOT NULL
            ORDER BY country_code
        """)
        countries = cur.fetchall()
        return [{'code': country[0], 'name': get_country_name(country[0])} for country in countries]
    except Exception as e:
        print(f"Error getting unique countries: {e}")
        return []
    finally:
        cur.close()
        conn.close()

def get_country_name(country_code):
    # Dicionário básico de códigos de país para nomes
    country_names = {
        'BR': 'Brasil',
        'US': 'Estados Unidos',
        'AR': 'Argentina',
        'UK': 'Reino Unido',
        # Adicione mais países conforme necessário
    }
    return country_names.get(country_code, country_code)

def get_links_by_product(product_id=None):
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    try:
        if product_id:
            cur.execute("""
                SELECT l.short_id, l.offer_url, p.name as product_name
                FROM links l
                LEFT JOIN products p ON l.product_id = p.id
                WHERE l.product_id = %s
            """, (product_id,))
        else:
            cur.execute("""
                SELECT l.short_id, l.offer_url, p.name as product_name
                FROM links l
                LEFT JOIN products p ON l.product_id = p.id
            """)
        
        links = cur.fetchall()
        return [
            {
                'short_id': link[0],
                'offer_url': link[1],
                'product_name': link[2]
            }
            for link in links
        ]
    except Exception as e:
        print(f"Error getting links: {e}")
        return []
    finally:
        cur.close()
        conn.close()

def create_ab_test(name, device_filter, country_filter, urls):
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    try:
        test_id = shortuuid.uuid()[:8]
        access_code = generate_access_code()
        
        # Criar o teste
        cur.execute("""
            INSERT INTO ab_tests (test_id, name, device_filter, country_filter, access_code)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING test_id
        """, (test_id, name, device_filter, country_filter, access_code))
        
        # Adicionar URLs
        for url in urls:
            if url.strip():  # Verificar se a URL não está vazia
                cur.execute("""
                    INSERT INTO ab_test_urls (test_id, url, visits)
                    VALUES (%s, %s, 0)
                """, (test_id, url))
        
        conn.commit()
        return test_id, access_code
    except Exception as e:
        conn.rollback()
        print(f"Error creating AB test: {e}")
        return None, None
    finally:
        cur.close()
        conn.close()

def get_ab_test(test_id):
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT test_id, name, device_filter, country_filter, access_code 
            FROM ab_tests 
            WHERE test_id = %s
        """, (test_id,))
        test = cur.fetchone()
        
        if test:
            cur.execute("""
                SELECT url, visits 
                FROM ab_test_urls 
                WHERE test_id = %s
                ORDER BY id
            """, (test_id,))
            urls = cur.fetchall()
            
            return {
                'test_id': test[0],
                'name': test[1],
                'device_filter': test[2],
                'country_filter': test[3],
                'access_code': test[4],
                'urls': [{'url': url[0], 'visits': url[1]} for url in urls]
            }
        return None
    finally:
        cur.close()
        conn.close()

def increment_ab_test_visit(test_id, url):
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE ab_test_urls 
            SET visits = visits + 1
            WHERE test_id = %s AND url = %s
        """, (test_id, url))
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"Error incrementing visit: {e}")
    finally:
        cur.close()
        conn.close()

def get_all_ab_tests():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT test_id, name, device_filter, country_filter, access_code 
            FROM ab_tests 
            ORDER BY created_at DESC
        """)
        tests = cur.fetchall()
        
        result = []
        for test in tests:
            cur.execute("""
                SELECT url, visits 
                FROM ab_test_urls 
                WHERE test_id = %s
                ORDER BY id
            """, (test[0],))
            urls = cur.fetchall()
            
            total_visits = sum(url[1] for url in urls)
            urls_with_stats = [
                {
                    'url': url[0],
                    'visits': url[1],
                    'percentage': round((url[1] / total_visits * 100) if total_visits > 0 else 0, 2)
                }
                for url in urls
            ]
            
            result.append({
                'test_id': test[0],
                'name': test[1],
                'device_filter': test[2],
                'country_filter': test[3],
                'access_code': test[4],
                'urls': urls_with_stats
            })
        
        return result
    finally:
        cur.close()
        conn.close()

def delete_ab_test(test_id):
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    try:
        # Primeiro deletar as URLs associadas
        cur.execute("DELETE FROM ab_test_urls WHERE test_id = %s", (test_id,))
        # Depois deletar o teste
        cur.execute("DELETE FROM ab_tests WHERE test_id = %s", (test_id,))
        
        success = cur.rowcount > 0
        conn.commit()
        return success
    except Exception as e:
        conn.rollback()
        print(f"Error deleting AB test: {e}")
        return False
    finally:
        cur.close()
        conn.close()