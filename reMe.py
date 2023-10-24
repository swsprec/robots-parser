import signal
import re

TIMEOUT = 5

# Credit to: https://www.saltycrane.com/blog/2010/04/using-python-timeout-decorator-uploading-s3/
class TimeoutError(Exception):
    def __init__(self, value = "Timed Out"):
        self.value = value
    def __str__(self):
        return repr(self.value)

def timeout(seconds_before_timeout):
    def decorate(f):
        def handler(signum, frame):
            raise TimeoutError()
        def new_f(*args, **kwargs):
            old = signal.signal(signal.SIGALRM, handler)
            signal.alarm(seconds_before_timeout)
            try:
                result = f(*args, **kwargs)
            finally:
                # reinstall the old signal handler
                signal.signal(signal.SIGALRM, old)
                # cancel the alarm
                # this line should be inside the "finally" block (per Sam Kortchmar)
                signal.alarm(0)
            return result
        new_f.__name__ = f.__name__
        return new_f
    return decorate

# End Credit

@timeout(TIMEOUT)
def _match(*args, **kwargs):
    return re.match(*args, **kwargs)


def match(*args, **kwargs):
    try:
        return _match(*args, **kwargs)
    except TimeoutError:
        return None


@timeout(TIMEOUT)
def _search(*args, **kwargs):
    return re.search(*args, **kwargs)

def search(*args, **kwargs):
    try:
        return _search(*args, **kwargs)
    except TimeoutError:
        return None


@timeout(TIMEOUT)
def _fullmatch(*args, **kwargs):
    return re.fullmatch(*args, **kwargs)

def fullmatch(*args, **kwargs):
    try:
        return _fullmatch(*args, **kwargs)
    except TimeoutError:
        return None

@timeout(TIMEOUT)
def _findall(*args, **kwargs):
    return re.findall(*args, **kwargs)
def findall(*args, **kwargs):
    try:
        return _findall(*args, **kwargs)
    except TimeoutError:
        return None


@timeout(TIMEOUT)
def _sub(*args, **kwargs):
    return re.sub(*args, **kwargs)
def sub(*args, **kwargs):
    try:
        return _sub(*args, **kwargs)
    except TimeoutError:
        return None
