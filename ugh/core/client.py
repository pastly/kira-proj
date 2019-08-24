from argparse import ArgumentDefaultsHelpFormatter
import logging

log = logging.getLogger(__name__)


def gen_parser(sub):
    d = ''
    _ = sub.add_parser(
        'client', description=d,
        formatter_class=ArgumentDefaultsHelpFormatter)


def main(args, conf):
    log.info('client')
    return 0
