from django.contrib import admin
from django.urls import path, include
from scanner import views
from crawler_module import crawl_website


urlpatterns = [
    path('admin/', admin.site.urls),
    path('scanner/', include('scanner.urls')),
    path('whois/', views.whois_lookup, name='whois_lookup'),
    path('crawler/', views.crawler, name='crawler'),
    path('subdomain/', views.subdomain_lookup, name='subdomain_lookup'),
    path('subdomain/results/', views.subdomain_results, name='subdomain_results'),
]
