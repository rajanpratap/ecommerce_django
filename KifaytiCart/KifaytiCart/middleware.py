from django.http import HttpResponseForbidden
from django.conf import settings

class BlockIPMiddleware:
    """
    Middleware to block requests coming from IP addresses listed in settings.BLOCKED_IPS.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        # Retrieve the list of blocked IPs from settings; defaults to an empty list if not defined.
        self.blocked_ips = getattr(settings, 'BLOCKED_IPS', [])

    def __call__(self, request):
        # Get the client's IP address.
        ip = self.get_client_ip(request)
        if ip in self.blocked_ips:
            return HttpResponseForbidden("Access Denied: Your IP has been blocked.")
        # Continue processing the request if the IP is not blocked.
        return self.get_response(request)

    def get_client_ip(self, request):
        """
        Retrieves the client's IP address from the request. If your app is behind a proxy,
        consider using the X-Forwarded-For header.
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # In case of multiple IPs, the first one is the original client IP.
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
