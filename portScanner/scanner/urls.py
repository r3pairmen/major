from django.urls import path
from . import views

app_name = 'scanner'

urlpatterns = [
    path('', views.scanner, name='scanner'),
    path('whois/', views.whois_lookup, name='whois_lookup'),
    path('crawler/', views.crawler, name='crawler'),
    path('subdomain/', views.subdomain_lookup, name='subdomain_lookup'),
    path('subdomain/results/', views.subdomain_results, name='subdomain_results'),
]
