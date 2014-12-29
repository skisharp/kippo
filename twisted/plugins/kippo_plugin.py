from zope.interface import implements

import os

from twisted.python import usage
from twisted.plugin import IPlugin
from twisted.application.service import IServiceMaker
from twisted.application import internet
import twisted.application.service
from twisted.cred import portal

if os.name == 'posix' and os.getuid() == 0:
    print 'ERROR: You must not run kippo as root!'
    sys.exit(1)

if not os.path.exists('kippo.cfg'):
    print 'ERROR: kippo.cfg is missing!'
    sys.exit(1)

from kippo import core
from kippo.core import ssh
from kippo.core.config import config

cfg = config()
if cfg.has_option('honeypot', 'ssh_addr'):
    DEFAULT_ADDRESS = cfg.get('honeypot', 'ssh_addr')
else:
    DEFAULT_ADDRESS = '0.0.0.0'

if cfg.has_option('honeypot', 'ssh_port'):
    DEFAULT_PORT = cfg.get('honeypot', 'ssh_port')
else:
    DEFAULT_PORT = '2222'

if cfg.has_option('honeypot', 'interact_port'):
    DEFAULT_INTERACT_PORT = cfg.get('honeypot', 'interact_port')
else:
    DEFAULT_INTERACT_PORT = '5123'

class Options(usage.Options):
    optParameters = [
        ["port", "p", DEFAULT_PORT, "The port number to listen on."],
        ["address", "a", DEFAULT_ADDRESS, "The port number to listen on."],
        ["interact_port", "i", DEFAULT_INTERACT_PORT, "The default interact port."]
    ]

class KippoServiceMaker(object):
    implements(IServiceMaker, IPlugin)
    tapname = "kippo"
    description = "Kippo SSH Honeypot"
    options = Options

    def makeService(self, options):
        """
        Construct a TCPServer from a factory defined in myproject.
        """

        """ multi service to hold both kippo and interact """
        multi = twisted.application.service.MultiService()

        """ set up kipposervice """
        realm = core.ssh.HoneyPotRealm()
        kportal = portal.Portal(realm)
        factory = core.ssh.HoneyPotSSHFactory()
        factory.portal = kportal
        factory.portal.registerChecker(core.auth.HoneypotPublicKeyChecker())
        factory.portal.registerChecker(core.auth.HoneypotPasswordChecker())

        for i in options["address"].split():
            service = internet.TCPServer(
                int(options["port"]), factory,
                interface=i)
            service.setServiceParent(multi)

        """ set up interact if required """
        if cfg.has_option('honeypot', 'interact_enabled') and \
                cfg.get('honeypot', 'interact_enabled').lower() in \
                ('yes', 'true', 'on'):
            from kippo.core import interact
            from twisted.internet import protocol
            service = internet.TCPServer(int(options["interact_port"]), interact.makeInteractFactory(factory))
            service.setServiceParent(multi)

        return multi

# Now construct an object which *provides* the relevant interfaces
# The name of this variable is irrelevant, as long as there is *some*
# name bound to a provider of IPlugin and IServiceMaker.

serviceMaker = KippoServiceMaker()
