"""Typosquatting karşılaştırması için popüler paket adları (kısa, elle seçilmiş liste).

Sınırlama: Bu liste tam değildir; amaç 'requests' yerine 'reqeusts' gibi bariz
yazım tuzaklarını yakalamaktır. Yanlış alarm olasılığı yüksek olduğu için bulgu LOW/MEDIUM verilir.
"""
POPULAR_PYPI = frozenset("""requests numpy pandas scipy matplotlib flask django fastapi pytest setuptools wheel pip urllib3
boto3 botocore pyyaml cryptography pillow sqlalchemy beautifulsoup4 selenium tensorflow torch scikit-learn jinja2 click
certifi idna charset-normalizer six python-dateutil pytz packaging attrs aiohttp httpx pydantic openai anthropic
colorama tqdm rich typer black flake8 mypy pylint opencv-python lxml psycopg2 redis celery paramiko pyjwt""".split())

POPULAR_NPM = frozenset("""react react-dom lodash express axios moment chalk commander debug typescript webpack babel-core
vue angular jquery underscore request async bluebird uuid dotenv eslint prettier jest mocha next nuxt tailwindcss
rxjs socket.io mongoose mysql redis cors body-parser nodemon cross-env inquirer yargs glob rimraf minimist
openai anthropic zod""".split())
