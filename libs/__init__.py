
import logging
try:  
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass



LOG = logging.getLogger(__name__)
LOG.addHandler(NullHandler())
