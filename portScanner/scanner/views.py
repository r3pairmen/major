import socket
import whois
import nmap
from django.shortcuts import render
from .forms import CrawlerForm
from .forms import SubdomainForm
from crawler_module import crawl_website
from googlesearch import search
from crtsh import crtshAPI




def scan_ports(target):
    try:
        # Try to resolve the target as an IP address
        socket.inet_aton(target)
    except socket.error:
        # If target is not an IP address, resolve it to an IP address
        target = socket.gethostbyname(target)

    # Create a new nmap PortScanner object
    scanner = nmap.PortScanner()

    # Run a TCP scan on the target IP address
    scanner.scan(target, arguments='-F')

    # Extract the open ports and their services from the scan result
    open_ports = []
    for port in scanner[target]['tcp']:
        if scanner[target]['tcp'][port]['state'] == 'open':
            service = scanner[target]['tcp'][port]['name']
            open_ports.append((port, service))

    # Resolve the IP address of the target
    resolved_ip = socket.gethostbyname(target)

    return resolved_ip, open_ports

def scanner(request):
    # Check if the user has submitted an IP address
    if 'ip_address' in request.GET:
        # Get the user-provided IP address
        ip_address = request.GET.get('ip_address')

        # Perform a port scan on the IP address
        resolved_ip, open_ports = scan_ports(ip_address)

        # Render the results in a template
        context = {'ip_address': ip_address, 'resolved_ip': resolved_ip, 'open_ports': open_ports}
        return render(request, 'scanner/results.html', context)

    # Render the scanner form template if no IP address has been submitted yet
    return render(request, 'scanner/scanner.html')


def whois_lookup(request):
    if 'domain' in request.GET:
        domain = request.GET.get('domain')
        result = whois.whois(domain)
        context = {'domain': domain, 'result': result}
        return render(request, 'scanner/whois_result.html', context)
    return render(request, 'scanner/whois_lookup.html')

def crawler(request):
    if request.method == 'POST':
        form = CrawlerForm(request.POST)
        if form.is_valid():
            domain = form.cleaned_data['domain']
            urls = crawl_website(domain)
            context = {'domain': domain, 'urls': urls}
            return render(request, 'scanner/crawler_results.html', context)
    else:
        form = CrawlerForm()
    return render(request, 'scanner/crawler.html', {'form': form})


def google_subdomain_search(domain):
    subdomains = []

    query = f"site:{domain}"

    # Perform the Google search
    results = search(query, num_results=10)

    # Extract subdomains from the search results
    for result in results:
        subdomain = result.split("//")[-1].split("/")[0].split(":")[0]
        if subdomain not in subdomains:
            subdomains.append(subdomain)

    return subdomains

def ssl_certificate_transparency(domain):
    subdomains = []

    api = crtshAPI()

    # Search for certificates associated with the domain
    results = api.search(domain)

    # Extract subdomains from the certificate results
    for result in results:
        subdomain = result['common_name']
        if subdomain not in subdomains:
            subdomains.append(subdomain)

    return subdomains

def subdomain_lookup(request):
    if request.method == 'POST':
        form = SubdomainForm(request.POST)
        if form.is_valid():
            domain = form.cleaned_data['domain']

            # Perform subdomain enumeration using Google search
            google_subdomains = google_subdomain_search(domain)

            # Perform subdomain enumeration using SSL certificate transparency
            ssl_subdomains = ssl_certificate_transparency(domain)

            context = {
                'domain': domain,
                'google_subdomains': google_subdomains,
                'ssl_subdomains': ssl_subdomains
            }
            return render(request, 'scanner/subdomain_results.html', context)
    else:
        form = SubdomainForm()

    context = {'form': form}
    return render(request, 'scanner/subdomain_lookup.html', context)