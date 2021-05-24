from celery import Celery
import subprocess

TIMEOUT = 15 * 60 # seconds

# Create the app and set the broker location (RabbitMQ)
app = Celery('DiAnE', backend='rpc://', broker='amqp://sherlock:mYr@bb1t@192.168.48.142')

@app.task(queue='DiAnE')
def run_lifting(apk):
    p = subprocess.Popen(['python', 'sanity_check.py', '--lift', '--celery', '--apk', apk])
    try:
    	p.wait(timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
    	p.kill()

@app.task(queue='DiAnE')
def run_analysis(apk):
    p = subprocess.Popen(['python', 'sanity_check.py', '--analyze', '--celery', '--apk', apk])
    try:
    	p.wait(timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
    	p.kill()
