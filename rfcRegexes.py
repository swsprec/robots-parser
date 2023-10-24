import re

ngroup_reg = '\\(\\?P<([a-zA-Z0-9_]*)>'
ngroup_comp_reg = re.compile(ngroup_reg)
def get_ngroups(s: str):
    return re.findall(ngroup_comp_reg,s)

scheme = '[a-zA-Z][a-zA-Z0-9+\\-.]*'
unreserved = '[a-zA-Z0-9\\-._~]'
pct_encoded = '%[0-9A-Fa-f][0-9A-Fa-f]'
sub_delims = "(?:[!$&]|\\\\'|[()*+,;=])"
userinfo = f'(?:{unreserved}|{pct_encoded}|{sub_delims}|:)*'
h16 = '[0-9A-Fa-f]{1,4}'
dec_octet = '(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])'
ipv4address = f'{dec_octet}\\.{dec_octet}\\.{dec_octet}\\.{dec_octet}'
ls32 = f'(?:{h16}:{h16}|{ipv4address})'
ipv6address = (
    f'(?:(?:{h16}:){{6}}{ls32}|::(?:{h16}:){{5}}{ls32}|(?:{h16})?::(?:{h16}:){{4}}'
    f'{ls32}|(?:(?:{h16}:)?{h16})?::(?:{h16}:){{3}}{ls32}|(?:(?:{h16}:){{2}}{h16})?::'
    f'(?:{h16}:){{2}}{ls32}|(?:(?:{h16}:){{3}}{h16})?::{h16}:{ls32}|(?:(?:{h16}:){{4}}'
    f'{h16})?::{ls32}|(?:(?:{h16}:){{5}}{h16})?::{h16}|(?:(?:{h16}:){{6}}{h16})?::)'
)
ipvfuture = f'[vV][0-9A-Fa-f]+\\.(?:{unreserved}|{sub_delims}|:)+'
ip_literal = f'\\[(?:{ipv6address}|{ipvfuture})\\]'
reg_name = f'(?:{unreserved}|{pct_encoded}|{sub_delims})*'
host = f'(?:{ip_literal}|{ipv4address}|{reg_name})'
port = '[0-9]*'
authority = f'(?:{userinfo}@)?{host}(?::{port})?'

force_authority = f'(?:{userinfo}@)?{host}(?::{port})'

pchar = f'(?:{unreserved}|{pct_encoded}|{sub_delims}|[:@])'
segment = f'(?:{pchar})*'
path_abempty = f'(?:/{segment})*'
segment_nz = f'(?:{pchar})+'
path_absolute = f'/(?:{segment_nz}(?:/{segment})*)?'
path_rootless = f'{segment_nz}(?:/{segment})*'
path_empty = f'(?:{pchar}){{0}}'
hier_part = (
    f'(?://{authority}{path_abempty}|{path_absolute}|{path_rootless}|'
    f'{path_empty})'
)
hier_part_no_leading = f'(?:{force_authority}{path_abempty})'

query = f'(?:{pchar}|[/?])*'

absuri = f'{scheme}:{hier_part}(?:\\?{query})?'
compiled_absuri = re.compile(absuri)

ws = '[ \t]'

# Custom domain finder regex
custom_domain = f'{ws}*(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z0-9-]+{ws}*'

no_scheme_uri = f'({scheme}:)?{hier_part_no_leading}(?:\\?{query})?'
compiled_no_scheme_uri = re.compile(custom_domain)

identifier = '[\\-A-Z_a-z]+'
product_token = f'(?:{identifier}|\\*)'
complied_product_token = re.compile(product_token)
utf8_1_noctl = '[!"$-\\x7f]'
utf8_tail = '[\\x80-\\xbf]'
utf8_2 = f'[\\xc2-\\xdf]{utf8_tail}'
utf8_3 = (
    f'(?:\\xe0[\\xa0-\\xbf]{utf8_tail}|[\\xe1-\\xec](?:{utf8_tail}){{2}}|\\xed'
    f'[\\x80-\\x9f]{utf8_tail}|[\\xee-\\xef](?:{utf8_tail}){{2}})'
)
utf8_4 = (
    f'(?:\\xf0[\\x90-\\xbf](?:{utf8_tail}){{2}}|[\\xf1-\\xf3](?:{utf8_tail}){{3}}|'
    f'\\xf4[\\x80-\\x8f](?:{utf8_tail}){{2}})'
)
utf8_char_noctl = f'(?:{utf8_1_noctl}|{utf8_2}|{utf8_3}|{utf8_4})'
path_pattern = f'/(?:{utf8_char_noctl})*'
complied_path_pattern = re.compile(path_pattern)
empty_pattern = f'(?:{ws})*'
comment = f'\\#(?:{utf8_char_noctl}|{ws}|\\#)*'
compiled_comment_val = re.compile(comment)
nl = '(?:[\r\n]|\\\r\\\n)'
eol = f'(?:{ws})*({comment})?{nl}'

commentline = f'(?P<comment>{comment})(?P<eolComment>{eol})'

acap_val = f'(?P<val>{product_token}|({path_pattern}|{empty_pattern}))'
compiled_acap_val = re.compile(acap_val)
acap = (
    f'(?:{ws})*(?P<directive>acap-[\\-a-zA-Z]*)(?:{ws})*:(?:{ws})*{acap_val}(?P<eolComment>{eol})'
)

rule = f'(?:{ws})*(allow|disallow)(?:{ws})*:(?:{ws})*({path_pattern}|{empty_pattern}){eol}'

allow = f'(?:{ws})*(?P<directive>allow)(?:{ws})*:(?:{ws})*(?P<path>{path_pattern}|{empty_pattern})(?P<eolComment>{eol})'


block = f'(?:{ws})*(?P<directive>block)(?:{ws})*:(?:{ws})*(?P<path>{path_pattern}|{empty_pattern})(?P<eolComment>{eol})'

param_vals = '[A-Za-z0-9./*_]*'
full_cparam_vals = f'(?P<param1>{param_vals})(?P<paramS>(?:\\&{param_vals})*)(?:{ws})*(?P<path>{path_pattern}|{empty_pattern})'
compiled_full_cparam_vals = re.compile(full_cparam_vals)

clean_param = (
    f'(?:{ws})*(?P<directive>clean-param)(?:{ws})*:(?:{ws})*{full_cparam_vals}(?P<eolComment>{eol})'
)

crawl_delay = f'(?:{ws})*(?P<directive>crawl-delay)(?:{ws})*:(?:{ws})*(?P<delay>[0-9]*)(?P<eolComment>{eol})'
compiled_crawl_delay_val = re.compile("[0-9]*")

disallow = f'(?:{ws})*(?P<directive>disallow)(?:{ws})*:(?:{ws})*(?P<path>{path_pattern}|{empty_pattern})(?P<eolComment>{eol})'

emptyline = f'{eol}'
gen_delims = '[:/?#\\[\\]@]'

startgroupline = f'(?:{ws})*(?P<directive>user-agent)(?:{ws})*:(?:{ws})*(?P<token>{product_token})(?P<eolComment>{eol})'
group = f'{startgroupline}(?:{startgroupline}|{emptyline})*(?:{rule}|{emptyline})*'

host_directive = f'(?:{ws})*(?P<directive>host)(?:{ws})*:(?:{ws})*(?P<uri>{absuri}|{host})(?P<eolComment>{eol})'
compiled_host_dir_val = re.compile(f'({absuri}|{host})')

host_loads_val = f'(?P<duration>[0-9]*)'
compiled_host_loads_val = re.compile(host_loads_val)
host_loads = f'(?:{ws})*(?P<directive>host-loads)(?:{ws})*:(?:{ws})*{host_loads_val}(?P<eolComment>{eol})'

ignore = f'(?:{ws})*(?P<directive>ignore)(?:{ws})*:(?:{ws})*(?P<path>{path_pattern}|{empty_pattern})(?P<eolComment>{eol})'

noarchive = f'(?:{ws})*(?P<directive>noarchive)(?:{ws})*:(?:{ws})*(?P<path>{path_pattern}|{empty_pattern})(?P<eolComment>{eol})'

nofollow = f'(?:{ws})*(?P<directive>nofollow)(?:{ws})*:(?:{ws})*(?P<path>{path_pattern}|{empty_pattern})(?P<eolComment>{eol})'


noindex = f'(?:{ws})*(?P<directive>noindex)(?:{ws})*:(?:{ws})*(?P<path>{path_pattern}|{empty_pattern})(?P<eolComment>{eol})'

nosnippet = f'(?:{ws})*(?P<directive>nosnippet)(?:{ws})*:(?:{ws})*(?P<path>{path_pattern}|{empty_pattern})(?P<eolComment>{eol})'

segment_nz_nc = f'(?:{unreserved}|{pct_encoded}|{sub_delims}|@)+'
path_noscheme = f'{segment_nz_nc}(?:/{segment})*'
path = (
    f'(?:{path_abempty}|{path_absolute}|{path_noscheme}|{path_rootless}|'
    f'{path_empty})'
)

rr_val = f'(?P<rate>[0-9]*)/(?P<time>[0-9]*)(?P<units>[sS]|[mM]|[hH]|[dD])(?:{ws})*(?P<time_day>[0-9]*-[0-9]*)?'
request_rate = (
    f'(?:{ws})*(?P<directive>request-rate)(?:{ws})*:(?:{ws})*{rr_val}(?P<eolComment>{eol})'
)
complied_request_rate_val = re.compile(rr_val)

reserved = f'(?:{gen_delims}|{sub_delims})'
robotstxt = f'(?:{group}|{emptyline})*'
sitejunk = f'(?:{utf8_char_noctl})*\\-sitemap'

sitemapExtra = f'(?:{ws})*(?P<directive>{sitejunk})(?:{ws})*:(?:{ws})*(?P<uri>{absuri})(?P<eolComment>{eol})'

sitemap = f'(?:{ws})*(?P<directive>sitemap)(?:{ws})*:(?:{ws})*(?P<uri>{absuri})(?P<eolComment>{eol})'

user_agent = f'{startgroupline}'

visit_time_val = f'(?P<time>[0-9]{{2}}:[0-9]{{2}}-[0-9]{{2}}:[0-9]{{2}})'
compiled_visit_time_val = re.compile(visit_time_val)
visit_time = (
    f'(?:{ws})*(?P<directive>visit-time)(?:{ws})*:(?:{ws})*{visit_time_val}(?P<eolComment>{eol})'
)

compiled_paths = re.compile(f'({path_pattern}|{empty_pattern})')


KNOWN_LINES = {'user-agent': (re.compile(user_agent, re.IGNORECASE), get_ngroups(user_agent), complied_product_token),
               'crawl-delay': (re.compile(crawl_delay, re.IGNORECASE), get_ngroups(crawl_delay), compiled_crawl_delay_val),
               'request-rate': (re.compile(request_rate, re.IGNORECASE), get_ngroups(request_rate), complied_request_rate_val ),
               'allow': (re.compile(allow, re.IGNORECASE), get_ngroups(allow), compiled_paths),
               'disallow': (re.compile(disallow, re.IGNORECASE), get_ngroups(disallow), compiled_paths),
               'block': (re.compile(block, re.IGNORECASE), get_ngroups(block), compiled_paths),
               'noindex': (re.compile(noindex, re.IGNORECASE), get_ngroups(noindex), compiled_paths),
               'nosnippet': (re.compile(nosnippet, re.IGNORECASE), get_ngroups(nosnippet), compiled_paths),
               'sitemap': (re.compile(sitemap, re.IGNORECASE), get_ngroups(sitemap), compiled_absuri),
               '-sitemap': (re.compile(sitemapExtra, re.IGNORECASE), get_ngroups(sitemapExtra), compiled_absuri),
               'host': (re.compile(host_directive, re.IGNORECASE), get_ngroups(host_directive), compiled_host_dir_val),
               'ignore': (re.compile(ignore, re.IGNORECASE), get_ngroups(ignore), compiled_paths),
               'clean-param': (re.compile(clean_param, re.IGNORECASE), get_ngroups(clean_param), compiled_full_cparam_vals),
               'host-load': (re.compile(host_loads, re.IGNORECASE), get_ngroups(host_loads), compiled_host_loads_val),
               'visit-time': (re.compile(visit_time, re.IGNORECASE), get_ngroups(visit_time), compiled_visit_time_val),
               'noarchive': (re.compile(noarchive, re.IGNORECASE), get_ngroups(noarchive), compiled_paths),
               'nofollow': (re.compile(nofollow, re.IGNORECASE), get_ngroups(nofollow), compiled_paths),
               'acap-': (re.compile(acap, re.IGNORECASE), get_ngroups(acap), compiled_acap_val),
               'comment': (re.compile(commentline, re.IGNORECASE), get_ngroups(commentline), compiled_comment_val)
               }
