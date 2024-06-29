"""
RulesList Parser AdGuard/Domain-List/uBlock/etc...
"""
import re
import ipaddress
import warnings
from typing import Iterable, NewType, Optional, TextIO, Union

from pyderive.extensions.serde import Serde

#** Variables **#
__all__ = [
    'Status',
    'Domain',
    'Regex',
    'Rule',
    'RuleDef',
    'RuleDefs',

    'parse_rule',
    'parse_rules',
]

#: wrapper around whitelist/blacklist determination
Status = NewType('Status', bool)

#: wrapper around domain string
class Domain(str): pass

#: wrapper around regex string
class Regex(str): pass

#: wrapper around wildcard string
class Wildcard(str): pass

#: Possible Rules (Domain/Wildcard/Regex)
Rule = Union[Domain, Regex, Wildcard]

class RuleDef(Serde, slots=True):
    rule:   Rule
    status: Status

#: generator of rule results
RuleDefs = Iterable[RuleDef]

#: raw regex expression to match valid web domains
re_expr = r'(?:[a-zA-Z0-9_](?:[a-zA-Z0-9-_]{0,61}' + \
    r'[A-Za-z0-9])?\.)+[A-Za-z0-9][A-Za-z0-9-_]{0,61}[A-Za-z]\.?'

#: compiled regex expression used to find domains in string
domain_find = re.compile(re_expr, re.IGNORECASE)

#: compiled regex expression to match domains as full-string only
domain_exact = re.compile(f'^{re_expr}$', re.IGNORECASE)

#: allowed (but not supported) adguard options
ALLOWED_OPTIONS = {'dnsrewrite', 'important'}

#** Functions **#

#NOTE: current implementation ignores existing adguard filter
# options which can effect how rules are applied.
# (https://adguard-dns.io/kb/general/dns-filtering-syntax)

def is_ipaddr(ip: str) -> bool:
    """
    attempt to parse string as an ip-address and return success

    :param ip: potential ip-address string
    :return:   true if string is ip-address
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_regex(rgx: str) -> bool:
    """
    attempt to parse string as regex expression and return success

    :param rgx: potential regex string
    :return:    true if string is valid regex
    """
    try:
        re.compile(rgx)
        return True
    except re.error:
        return False

def parse_rule(line: str) -> Optional[RuleDef]:
    """
    parse rule string into associated rule-type

    :param line: raw rule defintion on single-line
    :return:     parsed rule definition
    """
    # handle regex expr rule
    status = Status(not line.startswith('@@'))
    if line.startswith('/'):
        line = line.strip('/')
        if not is_regex(line):
            return
        return RuleDef(Regex(line), status)
    # parse adguard options from rule: ||example.com^$settings=1
    rule = line.strip('@')
    if rule.startswith('|') and '$' in rule:
        rule, options = rule.rsplit('$', 1)
        if not any(opt in options for opt in ALLOWED_OPTIONS):
            return
    # check if rule is in old `/etc/hosts` style format: `0.0.0.0 example.com`
    if ' ' in rule:
        start, end = rule.split(' ', 1)
        if is_ipaddr(start):
            rule = end.split('#', 1)[0].strip()
    # strip url extensions from rules
    for c in '/#?':
        if c in rule:
            rule = rule.split(c, 1)[0].strip()
    # handle traditional domain rules: ||www.google.com^
    # by adguard standards this is still a wildcard without ending with a `|`
    # but processing it like a flat domain comparison is better and faster
    # and acts exactly the same when its just a domain
    clean_rule = rule.strip('|^')
    if domain_exact.match(clean_rule):
       return RuleDef(Domain(clean_rule), status)
    # ignore ip-address rules since they won't apply to anything: ||1.2.3.4^
    if is_ipaddr(clean_rule):
        return
    # treat non-domains without a clear ending as a wildcard: ||abcdef.^
    if not any(rule.startswith(c) for c in '|*'):
        clean_rule = '*' + rule
    if not any(rule.endswith(c) for c in '^|*'):
        clean_rule += '*'
    # handle wildcard domain rules. anything with a `*` is safely a wildcard
    if '*' in clean_rule:
        return RuleDef(Wildcard(clean_rule), status)
    # error on failure to parse
    warnings.warn(f'Invalid Rule: {line!r}')

def parse_rules(f: TextIO) -> RuleDefs:
    """
    parse all available rules contained within a file

    :param f: file object to read rules from
    :return:  generator of parsed rule definitions
    """
    lines = (l.strip() for l in f.read().split('\n'))
    lines = (l for l in lines if l)
    for line in lines:
        if any(line.startswith(c) for c in ('!', '#', ':')):
            continue
        rule = parse_rule(line)
        if rule is not None:
            yield rule
