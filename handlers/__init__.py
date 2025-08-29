from handlers.dns_handler import DNSHandler

# from handlers.banner_handler import BannerHandler
from handlers.endpoint_handler import EndpointHandler
# from handlers.ldap_handler import LDAPHandler
# from handlers.smb_handler import SMBHandler

HANDLERS = {
    "dns": DNSHandler,
    # "banner": BannerHandler,
    "endpoint": EndpointHandler,
    # "ldap": LDAPHandler,
    # "smb": SMBHandler,
}
