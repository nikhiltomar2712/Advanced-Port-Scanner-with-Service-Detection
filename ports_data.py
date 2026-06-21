"""
Static reference data used by the scanner:

  - TOP_100_PORTS / TOP_1000_PORTS: curated lists of the ports most
    frequently found open in the wild, used by --top-ports.
  - SERVICE_NAMES: a best-effort port -> service name lookup table,
    used when live banner grabbing doesn't return anything useful.

These lists are not pulled from any single proprietary source; they are
a curated superset of IANA well-known ports plus the high ports most
commonly seen running real services (databases, web alt-ports, etc).
They are intentionally "good enough for a fast triage scan" rather than
a byte-for-byte clone of any particular existing tool's database.
"""

from __future__ import annotations

# --- The 100 ports most worth checking first on a quick triage scan ---
TOP_100_PORTS = [
    7, 9, 13, 20, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 254, 255, 280, 311, 389, 427,
    443, 444, 445, 464, 465, 497, 513, 514, 515, 543, 544, 548, 554, 587,
    593, 625, 631, 636, 646, 787, 808, 873, 902, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
    2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6379, 6646,
    7070, 8000, 8008, 8080, 8443, 8888, 9100, 9999,
]

# --- A broader top-1000 set used for more thorough scans ---
# Built from: full well-known range 1-1023, plus the registered ports most
# commonly associated with real-world services (web alt ports, databases,
# remote access, message queues, container/orchestration tooling, etc).
_WELL_KNOWN_RANGE = list(range(1, 1024))

_EXTRA_HIGH_PORTS = [
    1080, 1099, 1158, 1234, 1311, 1337, 1414, 1433, 1434, 1521, 1604, 1645,
    1646, 1701, 1718, 1719, 1720, 1723, 1755, 1761, 1812, 1813, 1900, 1935,
    1962, 2000, 2001, 2049, 2065, 2068, 2121, 2161, 2181, 2375, 2376, 2379,
    2380, 2401, 2424, 2483, 2484, 2601, 2717, 2967, 3000, 3001, 3050, 3128,
    3260, 3268, 3269, 3283, 3306, 3307, 3389, 3690, 3702, 3986, 4000, 4040,
    4111, 4190, 4369, 4443, 4444, 4445, 4500, 4567, 4664, 4672, 4673, 4730,
    4786, 4840, 4848, 4899, 4949, 5000, 5001, 5005, 5009, 5050, 5051, 5060,
    5061, 5093, 5101, 5120, 5190, 5222, 5223, 5269, 5351, 5353, 5355, 5357,
    5400, 5431, 5432, 5555, 5560, 5631, 5632, 5666, 5672, 5683, 5800, 5900,
    5901, 5984, 5985, 5986, 6000, 6001, 6002, 6346, 6379, 6443, 6446, 6488,
    6500, 6514, 6543, 6566, 6588, 6646, 6660, 6661, 6662, 6663, 6664, 6665,
    6666, 6667, 6668, 6669, 6679, 6697, 6881, 6969, 7000, 7001, 7002, 7070,
    7077, 7080, 7170, 7199, 7233, 7400, 7401, 7402, 7426, 7474, 7547, 7548,
    7600, 7625, 7634, 7657, 7777, 7778, 7911, 8000, 8001, 8002, 8003, 8005,
    8006, 8008, 8009, 8010, 8014, 8020, 8022, 8025, 8030, 8042, 8060, 8069,
    8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091,
    8092, 8093, 8094, 8095, 8096, 8099, 8100, 8112, 8123, 8126, 8140, 8161,
    8181, 8200, 8222, 8243, 8280, 8281, 8333, 8384, 8443, 8500, 8501, 8502,
    8530, 8531, 8554, 8649, 8686, 8761, 8765, 8800, 8834, 8843, 8847, 8848,
    8880, 8883, 8888, 8889, 8899, 8983, 8989, 9000, 9001, 9002, 9009, 9010,
    9042, 9043, 9080, 9081, 9090, 9091, 9092, 9100, 9151, 9160, 9191, 9200,
    9201, 9229, 9300, 9389, 9418, 9443, 9444, 9445, 9600, 9700, 9711, 9869,
    9874, 9875, 9876, 9877, 9878, 9898, 9900, 9917, 9929, 9943, 9944, 9981,
    9990, 9999, 10000, 10001, 10002, 10010, 10050, 10051, 10080, 10101,
    10110, 10243, 10250, 10255, 10256, 10257, 10258, 10259, 10443, 10809,
    10990, 11001, 11211, 11300, 11371, 12000, 12174, 12222, 12345, 13000,
    13456, 13720, 13722, 14000, 14147, 15000, 15002, 15003, 15004, 15660,
    15672, 16000, 16012, 16016, 16018, 16080, 16113, 16992, 16993, 17877,
    17988, 18040, 18080, 18081, 18091, 18092, 18101, 18988, 19000, 19283,
    19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222,
    20828, 21571, 22939, 23023, 23424, 23791, 23901, 24444, 24800, 25000,
    25025, 25565, 25672, 26000, 26214, 27000, 27015, 27017, 27018, 27019,
    27345, 27888, 28017, 28201, 28784, 29999, 30000, 30005, 30564, 30704,
    30718, 30951, 31001, 31099, 31337, 32400, 32483, 32768, 32769, 32770,
    32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780,
    32781, 32782, 32783, 32784, 32785, 33060, 33389, 33899, 34571, 34572,
    34573, 35500, 38292, 40193, 40911, 41511, 42510, 44176, 44323, 44442,
    44443, 44501, 45100, 48080, 49152, 49153, 49154, 49155, 49156, 49157,
    49158, 49159, 49160, 49161, 49163, 49165, 49167, 49175, 49176, 49400,
    49999, 50000, 50001, 50002, 50003, 50006, 50300, 50389, 50500, 50636,
    50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055,
    55056, 55555, 55600, 56737, 56738, 57294, 57797, 58080, 60020, 60443,
    61532, 61900, 62078, 63331, 64623, 64680, 65000, 65129, 65389,
]

# Deduplicate while preserving the "well known first" ordering, then trim
# to a clean 1000 entries.
_seen = set()
TOP_1000_PORTS = []
for _port in _WELL_KNOWN_RANGE + _EXTRA_HIGH_PORTS:
    if _port not in _seen:
        _seen.add(_port)
        TOP_1000_PORTS.append(_port)
TOP_1000_PORTS = sorted(TOP_1000_PORTS)[:1000]
del _seen, _port

# --- port -> common service name (used as a fallback label) ---
SERVICE_NAMES = {
    7: "echo", 9: "discard", 13: "daytime", 20: "ftp-data", 21: "ftp",
    22: "ssh", 23: "telnet", 25: "smtp", 26: "rsftp", 37: "time",
    53: "dns", 79: "finger", 80: "http", 81: "http-alt", 88: "kerberos",
    106: "pop3pw", 110: "pop3", 111: "rpcbind", 113: "ident",
    119: "nntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
    139: "netbios-ssn", 143: "imap", 144: "news", 161: "snmp",
    162: "snmptrap", 179: "bgp", 194: "irc", 199: "smux", 264: "fw1-rdp",
    389: "ldap", 427: "svrloc", 443: "https", 444: "snpp", 445: "smb",
    464: "kpasswd5", 465: "smtps", 497: "retrospect", 500: "isakmp",
    513: "rlogin", 514: "syslog", 515: "printer", 543: "klogin",
    544: "kshell", 548: "afp", 554: "rtsp", 587: "submission",
    593: "http-rpc-epmap", 631: "ipp", 636: "ldaps", 646: "ldp",
    873: "rsync", 902: "vmware-auth", 989: "ftps-data", 990: "ftps",
    993: "imaps", 995: "pop3s", 1080: "socks", 1099: "rmiregistry",
    1194: "openvpn", 1433: "mssql", 1434: "mssql-monitor",
    1521: "oracle", 1701: "l2tp", 1723: "pptp", 1812: "radius",
    1883: "mqtt", 1900: "ssdp", 1935: "rtmp", 2049: "nfs",
    2082: "cpanel", 2083: "cpanel-ssl", 2086: "whm", 2087: "whm-ssl",
    2095: "webmail", 2096: "webmail-ssl", 2181: "zookeeper",
    2375: "docker", 2376: "docker-ssl", 2379: "etcd-client",
    2380: "etcd-peer", 2483: "oracle-tls-off", 2484: "oracle-tls-on",
    3000: "dev-http", 3128: "squid-proxy", 3268: "ldap-gc",
    3306: "mysql", 3389: "rdp", 3690: "svn", 4369: "epmd",
    4444: "metasploit-default", 4500: "ipsec-nat-t", 4848: "glassfish-admin",
    5000: "upnp/flask-dev", 5044: "logstash", 5060: "sip",
    5222: "xmpp-client", 5269: "xmpp-server", 5353: "mdns",
    5432: "postgresql", 5601: "kibana", 5631: "pcanywheredata",
    5672: "amqp", 5683: "coap", 5900: "vnc", 5984: "couchdb",
    5985: "winrm-http", 5986: "winrm-https", 6000: "x11",
    6379: "redis", 6443: "kubernetes-api", 6660: "irc", 6667: "irc",
    6881: "bittorrent", 7000: "cassandra", 7077: "spark",
    7199: "cassandra-jmx", 7474: "neo4j-http", 7547: "cwmp-tr069",
    8000: "http-alt", 8008: "http-alt", 8080: "http-proxy",
    8086: "influxdb", 8089: "splunkd", 8091: "couchbase",
    8200: "vault", 8443: "https-alt", 8500: "consul",
    8530: "wsus", 8531: "wsus-ssl", 8888: "http-alt",
    9000: "php-fpm/sonarqube", 9042: "cassandra-cql", 9092: "kafka",
    9100: "jetdirect/printer", 9200: "elasticsearch", 9300: "elasticsearch-transport",
    9389: "adws", 9418: "git", 9443: "https-alt", 10000: "webmin",
    11211: "memcached", 15672: "rabbitmq-mgmt", 25565: "minecraft",
    27017: "mongodb", 27018: "mongodb-shard", 28017: "mongodb-http",
    32400: "plex", 50000: "db2", 50070: "hadoop-namenode",
}


def get_service_name(port: int) -> str:
    """Return a best-effort service name for a port, or 'unknown'."""
    return SERVICE_NAMES.get(port, "unknown")
