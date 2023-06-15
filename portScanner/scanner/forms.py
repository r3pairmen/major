from django import forms
from django.core.validators import validate_ipv4_address

class PortScanForm(forms.Form):
    ip_address = forms.CharField(label='IP Address', validators=[validate_ipv4_address])

class CrawlerForm(forms.Form):
    domain = forms.CharField(label='Domain')


class SubdomainForm(forms.Form):
    domain = forms.CharField(label='Domain', max_length=100)
