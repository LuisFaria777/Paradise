import requests
from ninja import Router

users_router = Router()

@users_router.post('/', response={200: dict})
def create_user(request):
    return {'ok': 'ok'}



def get_access_token():
    url = "https://apigateway.conectagov.estaleiro.serpro.gov.br/oauth2/jwt-token"
    client_id = "your_client_id"  # Substitua pelo seu client ID
    client_secret = "your_client_secret"  # Substitua pelo seu client secret
    
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret
    }
    
    response = requests.post(url, headers=headers, data=data)
    if response.status_code == 200:
        return response.json().get('access_token')
    else:
        raise Exception("Failed to get access token")


