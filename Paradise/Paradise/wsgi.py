import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'chiang_pinhuey_final_project.settings')

application = get_wsgi_application()
