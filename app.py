import logging
import socket
import time

from apps import App, action

logger = logging.getLogger("apps")


@action
def test():
    logger.debug("This is a another test from {}".format(socket.gethostname()))
    return {"message": "FN Agile FROM {}".format(socket.gethostname())}

class Test(App):
    """This app defines the same actions as above, but bound to an app instance. This instance will keep track fo how
    many total actions are called for this app's instance.
    """

    def __init__(self, name, device, context):
        App.__init__(self, name, device, context)
        # Functions and Variables that are designed to exist across functions go here
        self.introMessage = {"message": "HELLO WORLD FROM {}".format(socket.gethostname())}
        self.total_called_functions = 0


    def shutdown(self):
        return
