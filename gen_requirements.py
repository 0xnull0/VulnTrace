"""
Generate requirements.txt file for VulnTrace
Run this script to generate the requirements file based on currently installed packages.
"""

with open('requirements.txt', 'w') as f:
    f.write("""beautifulsoup4==4.12.2
email-validator==2.1.0
flask==2.3.3
flask-sqlalchemy==3.1.1
gunicorn==21.2.0
psycopg2-binary==2.9.9
requests==2.31.0
""")