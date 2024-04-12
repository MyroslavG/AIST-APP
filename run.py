from flask import Flask, render_template, request, redirect, url_for, flash, session, Response
import requests
from functools import wraps
from datetime import timedelta
import stripe
from dotenv import load_dotenv
import os

app = Flask(__name__)

load_dotenv()

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print("Checking if user_id in session")  # Debug print
        if 'access_token' not in session:
            print(f"Redirecting to login from {request.url}")  # Debug print
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    session.permanent = True
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        response = requests.post('https://aist.amuservc.com/login', json={
            'email': email, 
            'password': password}
        )
        
        if response.ok:
            token = response.json().get('access_token')
            session['access_token'] = token
            # session['user_id'] = response.json().get('user_id')
            # print(token)
            return redirect(url_for('dashboard'))
        else:
            flash('Login Failed. Please check your credentials.')
            
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        response = requests.post('https://aist.amuservc.com/register', json={
            'username': username,
            'email': email,
            'password': password
        })

        if response.ok:
            flash('Registration successful. Please log in.')
            return redirect(url_for('login'))
        else:
            flash('Registration failed. ' + response.json().get('message', ''))

    return render_template('register.html')

@app.route('/create_checkout_session', methods=['GET', 'POST'])
@login_required
def create_checkout_session():
    if 'access_token' not in session:
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    access_token = session.get('access_token')

    quantity = request.form.get('quantity', type=int)
    if not quantity or quantity < 1:
        flash('Invalid quantity specified', 'error')
        return redirect(url_for('billing'))

    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    
    try:
        # Create the Stripe Checkout session
        response = requests.post('https://aist.amuservc.com/create_checkout_session', headers=headers, json={
            'quantity': quantity
        })

        # print(response.json())

        if response.ok:
            # print('here')
            checkout_session_url = response.json().get('checkout_session_url')
            return redirect(checkout_session_url)
    except Exception as e:
        print(e)  # Log the error
        flash('Failed to create a checkout session', 'error')
        return redirect(url_for('billing'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if 'access_token' not in session:
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    access_token = session.get('access_token')

    headers = {
        'Authorization': f'Bearer {access_token}'
    }

    api_url = 'https://aist.amuservc.com/dashboard'
    response = requests.get(api_url, headers=headers) #, json={'user_id': user_id})
    if response.status_code == 200:
        balance = response.json().get('balance', [])

    if request.method == 'POST':
        prompt = request.form.get('prompt')

        response = requests.post('https://aist.amuservc.com/video', headers=headers, json={
            'prompt': prompt,
        })  

        if response.status_code == 200:
            flash('Your video generation process has started')
        else:
            flash('You have no more generations left. Please purchase some on the "Billing" page!')
    
    return render_template('dashboard.html', balance=balance)#, user=session['user'])

@app.route('/payment_success')
@login_required
def payment_success():
    if 'access_token' not in session:
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    access_token = session.get('access_token')
    headers = {
        'Authorization': f'Bearer {access_token}'
    }

    api_url = 'https://aist.amuservc.com/payment_success'
    response = requests.get(api_url, headers=headers) #, json={'user_id': user_id})
    if response.status_code == 200:
        balance = response.json().get('balance', [])

    return render_template('payment_success.html', balance=balance)#, user=session['user'])

@app.route('/my_videos')
@login_required
def my_videos():
    if 'access_token' not in session:
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    access_token = session.get('access_token')
    
    if not access_token:
        return "Please log in first", 401

    headers = {
        'Authorization': f'Bearer {access_token}'
    }

    api_url = 'https://aist.amuservc.com/get_videos'
    response = requests.get(api_url, headers=headers) #, json={'user_id': user_id})

    if response.status_code == 200:
        videos = response.json().get('videos', [])
    else:
        videos = []

    return render_template('my_videos.html', videos=videos)

@app.route('/profile')
@login_required
def profile():
    if 'access_token' not in session:
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    access_token = session.get('access_token')
    
    if not access_token:
        return "Please log in first", 401

    headers = {
        'Authorization': f'Bearer {access_token}'
    }

    api_url = 'https://aist.amuservc.com/profile'
    response = requests.get(api_url, headers=headers) #, json={'user_id': user_id})

    if response.status_code == 200:
        username = response.json().get('username', [])
        email = response.json().get('email', [])

    return render_template('profile.html', username=username, email=email)

@app.route('/billing')
@login_required
def billing():
    if 'access_token' not in session:
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    access_token = session.get('access_token')
    
    if not access_token:
        return "Please log in first", 401

    headers = {
        'Authorization': f'Bearer {access_token}'
    }

    api_url = 'https://aist.amuservc.com/billing'
    response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        subscription_plan = response.json().get('subscription_plan', [])
        subscription_status = response.json().get('subscription_status', [])

    return render_template('billing.html', subscription_plan=subscription_plan, subscription_status=subscription_status)

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.pop('user', None)
    session.pop('access_token', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc')
