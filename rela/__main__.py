from .util import config
from .core import client
from .core import server
from rela import __version__

from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
import logging
import logging.config

log = logging.getLogger(__name__)


def create_arg_parser():
    p = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
    p.add_argument(
        '--log-level', type=str, default='info',
        choices=('debug', 'info', 'warn', 'error'),
        help='Set the log level')
    p.add_argument(
        '-v', '--version', action='version', version=__version__)
    sub = p.add_subparsers(dest='command', required=True)
    client.gen_parser(sub)
    server.gen_parser(sub)
    return p


def main():
    p = create_arg_parser()
    args = p.parse_args()
    conf = config.get_config(args)
    config.configure_logging(args, conf)
    def_args = [args, conf]
    def_kwargs = {}
    known_commands = {
        'client': {'f': client.main, 'a': def_args, 'kw': def_kwargs},
        'server': {'f': server.main, 'a': def_args, 'kw': def_kwargs},
    }
    if args.command not in known_commands:
        p.print_help()
        return
    c = known_commands[args.command]
    exit(c['f'](*c['a'], **c['kw']))
