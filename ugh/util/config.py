from .. import globals as G

from configparser import (ConfigParser, ExtendedInterpolation)
import os
import logging
import logging.config
from tempfile import NamedTemporaryFile

log = logging.getLogger(__name__)


def _expand_path(path):
    """Expand path string containing shell variables and ~ constructions
    into their values. Environment variables have to have their $ escaped by
    another $. For example: $$XDG_RUNTIME_DIR/foo.bar
    """
    return os.path.expanduser(os.path.expandvars(path))


def _extend_config(conf, fname):
    log.debug("Reading config file %s", fname)
    with open(fname, 'rt') as fd:
        conf.read_file(fd, source=fname)
    return conf


def _get_default_config():
    c = ConfigParser(
        interpolation=ExtendedInterpolation(),
        converters={"path": _expand_path})
    return _extend_config(c, G.DEFAULT_CONFIG_PATH)


def _get_default_logging_config(c):
    return _extend_config(c, G.DEFAULT_LOG_CONFIG_PATH)


def _get_user_config(c):
    try:
        return _extend_config(c, G.DEFAULT_USER_CONFIG_PATH)
    except FileNotFoundError:
        return c


def get_config(args):
    c = _get_default_config()
    c = _get_default_logging_config(c)
    c = _get_user_config(c)
    return c


def configure_logging(args, conf):
    LOGGER = 'logger_ugh'
    conf[LOGGER]['level'] = args.log_level.upper()
    with NamedTemporaryFile('w+t') as fd:
        conf.write(fd)
        fd.seek(0, 0)
        logging.config.fileConfig(fd.name)
