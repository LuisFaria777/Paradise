import pycountry
from operator import itemgetter

# Gera uma lista de tuplas com o nome dos países ordenados alfabeticamente
country_list = sorted(
    [(country.name, country.name) 
     for country in list(pycountry.countries)], key=itemgetter(0))

# Insere uma opção padrão no início da lista
country_list.insert(0, ("*Select Country", "*Select Country"))

# Define a lista como uma constante para uso em formulários ou modelos
COUNTRIES = country_list
