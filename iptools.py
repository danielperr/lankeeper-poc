
def ip2int(ip):
    """:returns the given IPv4 address in integer form"""
    if len(filter(lambda x: not x.isdigit() or int(x) > 255 or int(x) < 0, ip.split('.'))):
        raise ValueError('invalid IPv4 address')
    return sum([int(x) * 2 ** (8 * (3 - i)) for i, x in enumerate(ip.split('.'))])


def int2ip(num):
    """:returns the given IPv4 integer address in string form"""
    if num < 0 or num >= 2**32:
        raise ValueError('invalid IPv4 integer')
    return '.'.join([str(num / 2 ** (8 * i) % 2 ** 8) for i in range(4)][::-1])
