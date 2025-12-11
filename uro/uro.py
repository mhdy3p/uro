import argparse
import io
import re
import sys
from urllib.parse import urlparse

from uro.utils import *
from uro.filters import *

try:
	from signal import signal, SIGPIPE, SIG_DFL
	signal(SIGPIPE, SIG_DFL)
except ImportError:
	pass

parser = argparse.ArgumentParser()
parser.add_argument('-i', help='file containing urls', dest='input_file')
parser.add_argument('-o', help='output file', dest='output_file')
parser.add_argument('-w', '--whitelist', help='only keep these extensions and extensionless urls', dest='whitelist', nargs='+')
parser.add_argument('-b', '--blacklist', help='remove these extensions', dest='blacklist', nargs='+')
parser.add_argument('-f', '--filters', help='additional filters, read docs', dest='filters', nargs='+')
args = parser.parse_args()

filter_map = {
	'hasext': has_ext,
	'noext': no_ext,
	'hasparams': has_params,
	'noparams': no_params,
	'removecontent': remove_content,
	'blacklist': blacklisted,
	'whitelist': whitelisted,
	'vuln': has_vuln_param,
}

filters = clean_nargs(args.filters)
active_filters = ['removecontent']

if 'allexts' in filters:
	filters.remove('allexts')
else:
	if args.whitelist:
		active_filters.append('whitelist')
	else:
		active_filters.append('blacklist')

for i in filters:
	if i in filter_map or i in ('keepcontent', 'keepslash'):
		active_filters.append(i)
	elif i + 's' in filter_map:
		active_filters.append(i + 's')
	elif i[:-1] in filter_map:
		active_filters.append(i[:-1])
	else:
		print('[ERROR] Invalid filter:', i, file=sys.stderr)
		exit(1)

if 'keepcontent' in active_filters:
	active_filters.remove('removecontent')
	active_filters.remove('keepcontent')

keepslash = True if 'keepslash' in active_filters else False
if keepslash:
	active_filters.remove('keepslash')

urlmap = {}
params_seen = set()
patterns_seen = set()

re_int = re.compile(r'/\d+([?/]|$)')

# Extensions that should NEVER be filtered out
whitelisted = tuple((
    # --- PHP (Already good, slight expansion) ---
    'php', 'php3', 'php4', 'php5', 'phtml', 'phps', 'php-s',

    # --- ASP / .NET / IIS Handlers ---
    'asp', 'aspx', 'axd', 'asmx', 'ashx', 'svc', 'config', 'asax',
    'master', 'browser', 'config', 'cdx', 'idc', # Configuration/handler files

    # --- Java / JSP / Spring / Servlet ---
    'jsp', 'jspx', 'jsw', 'jsv', 'jspf', 'do', 'action', 'seam', 'struts',

    # --- Python (Django / Flask / etc.) ---
    'py', 'wsgi', 'pyc', # While often configuration, they indicate Python backends

    # --- Ruby (Ruby on Rails) ---
    'rb', 'rhtml', 'rjs', 'erb',

    # --- ColdFusion ---
    'cfm', 'cfml', 'cfc',

    # --- Perl / CGI ---
    'pl', 'cgi', 'pm', 'shtm', 'shtml', 'stm', # Server-Side Includes

    # --- Node.js / Serverless / Modern JS ---
    'js', 'json', 'ts', 'jsx', 'tsx', # Although JS/JSON can be static, they are often API endpoints

    # --- Go / Golang ---
    'go',

    # --- Legacy / Others ---
    'dll', 'inc', 'asa', 'htr', # Handlers/includes
    'xml', 'wsdl', 'xsd', 'yaml', 'yml', 'toml', # Configuration/schema files, often tied to APIs/handlers
    'txt', # For robots.txt, sitemap.xml, or files that might contain sensitive info
    'git', 'svn', 'hg', # Source control artifacts
    'bak', 'old', 'tmp', 'copy', # Backup/temporary files
    'log', 'err', 'trace', # Log files
    'zip', 'tar', 'gz', 'rar', '7z' # Archives that might contain code/configs
))

ext_list = tuple(clean_nargs(args.blacklist)) if args.blacklist else tuple((
    # --- Images ---
    'css', 'png', 'jpg', 'jpeg', 'svg', 'ico', 'webp', 'bmp', 'tif', 'tiff', 'gif',
    'heic', 'avif', 'apng', 'xbm', 'cur',
    
    # --- Fonts ---
    'ttf', 'otf', 'woff', 'woff2', 'eot', 'fnt',
    
    # --- Audio & Video ---
    'mp3', 'mp4', 'avi', 'wav', 'mov', 'webm', 'mkv', 'flv', 'wmv', 'm4a', 
    'aac', 'ogg', 'wma', '3gp', 'flac',
    
    # --- Documents (Static) ---
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'rtf', 'txt', 'csv',
    
    # --- Web Assets & Maps ---
    'scss', 'sass', 'less', 'map', 'swf'
))

vuln_params = set([
    # --- SSRF & LFI & Open Redirect ---
    'file', 'document', 'folder', 'root', 'path', 'pg', 'style', 'pdf', 'template',
    'php_path', 'doc', 'page', 'name', 'cat', 'dir', 'action', 'board', 'date',
    'detail', 'download', 'prefix', 'include', 'inc', 'locate', 'show', 'site',
    'type', 'view', 'content', 'layout', 'mod', 'conf', 'daemon', 'upload',
    'log', 'ip', 'dest', 'redirect', 'uri', 'continue', 'url', 'window', 'to',
    'out', 'navigation', 'Open', 'val', 'validate', 'domain', 'callback',
    'return', 'page', 'feed', 'host', 'port', 'next', 'data', 'head', 'header',
    'headers', 'img', 'filename', 'img_url', 'image_url', 'file_url', 'load_url',
    'load_file', 'open', 'forward', 'forward_url', 'reference', 'site_url',
    'html', 'navigator', 'u', 't', 'link', 'ret', 'r', 'rb', 'src', 'source',
    'u', 'return_path', 'return_to', 'returnTo', 'return_url', 'rt', 'rurl',
    'target', 'checkout', 'checkout_url', 'goto', 'next_page', 'redirect_to',
    'redirect_uri', 'redirect_url', 'logout', 'login_url', 'page_url',
    'go', 'succUrl', 'returnUrl', 'return_path',
    
    # --- RCE (Command Injection) ---
    'cli', 'cmd', 'exec', 'command', 'execute', 'ping', 'query', 'jump', 'code',
    'reg', 'do', 'func', 'arg', 'option', 'load', 'process', 'step', 'read',
    'function', 'req', 'feature', 'exe', 'module', 'payload', 'run', 'print',
    'system', 'shell', 'filter', 'access', 'admin', 'dbg', 'debug', 'edit',
    'grant', 'test', 'alter', 'clone', 'create', 'disable', 'enable', 'make',
    'modify', 'rename', 'reset', 'toggle', 'adm', 'cfg', 'config', 'server',
    'message', 'email',
    
    # --- SQL Injection (SQLi) ---
    'id', 'select', 'report', 'role', 'update', 'user', 'sort', 'where', 'params',
    'row', 'table', 'from', 'sel', 'results', 'sleep', 'fetch', 'order', 'column',
    'field', 'delete', 'string', 'number', 'filter', 'group', 'class', 'matrix',
    'search', 'q', 's', 'keyword', 'keywords', 'query', 'ac', 'api', 'password',
    'token', 'username', 'csrf_token', 'unsubscribe_token', 'item', 'page_id',
    'month', 'immagine', 'list_type', 'terms', 'categoryid', 'key', 'l',
    'begindate', 'enddate', 'desc', 'asc', 'item_id', 'user_id', 'product_id',
    'station_id', 'msg_id', 'entry_id', 'cust_id', 'customer_id', 'client_id',
    'order_id', 'post_id', 'link_id', 'topic_id', 'note_id', 'cat_id', 'group_id',
    
    # --- XSS & Client Side ---
    'lang', 'year', 'emailto', 'p', 'jsonp', 'api_key', 'callback', 'c',
    'v', 'variant', 'context', 'subject', 'topic', 'body', 'headline', 'title',
    
    # --- IDOR & Business Logic ---
    'account', 'no', 'doc', 'key', 'email', 'profile', 'edit', 'report', 'money',
    'amount', 'quantity', 'qty', 'balance', 'credit', 'debit', 'limit', 'role',
    'admin', 'level', 'auth', 'authorized', 'authenticated', 'status', 'state',
    'oauth', 'oauth_token', 'invite', 'invitation'
])

if args.whitelist:
	ext_list = tuple(clean_nargs(args.whitelist))


def create_pattern(path):
	"""
	creates patterns for urls with integers in them
	"""
	new_parts = []
	last_index = 0
	for i, part in enumerate(re.escape(path).split('/')):
		if part.isdigit():
			last_index = i
			new_parts.append('\\d+')
		else:
			new_parts.append(part)
	return re.compile('/'.join(new_parts[:last_index + 1]))


def apply_filters(path, params):
	"""
	apply filters to a url
	returns True if the url should be kept
	"""
	meta = {
		'strict': True if ('hasext' or 'noext') in filters else False,
		'ext_list': ext_list,
		'vuln_params': vuln_params,
	}
	for filter in active_filters:
		if not filter_map[filter](path, params, meta):
			return False
	return True


def process_url(url):
	"""
	processes a url
	"""
	host = url.scheme + '://' + url.netloc
	if host not in urlmap:
		urlmap[host] = {}
	path, params = url.path, params_to_dict(url.query)
	new_params = [] if not params else [param for param in params.keys() if param not in params_seen]
	keep_url = apply_filters(path, params)
	if not keep_url:
		return
	params_seen.update(new_params)
	new_path = path not in urlmap[host]
	if new_path:
		if re_int.search(path):
			pattern = create_pattern(path)
			if pattern in patterns_seen:
				return
			patterns_seen.add(pattern)
		urlmap[host][path] = []
		if params:
			urlmap[host][path].append(params)
	else:
		if new_params:
			urlmap[host][path].append(params)
		elif compare_params(urlmap[host][path], params):
			urlmap[host][path].append(params)


def process_line(line):
	"""
	processes a single line from input
	"""
	cleanline = line.strip() if keepslash else line.strip().rstrip('/')
	try:
		parsed_url = urlparse(cleanline)
		if parsed_url.netloc:
			process_url(parsed_url)
	except ValueError:
		pass

def main():
	if args.input_file:
		with open(args.input_file, 'r', encoding='utf-8', errors='ignore') as input_file:
			for line in input_file:
				process_line(line)
	elif not sys.stdin.isatty():
		for line in io.TextIOWrapper(sys.stdin.buffer, encoding='utf-8', errors='ignore'):
			process_line(line)
	else:
		print('[ERROR] No input file or stdin.', file=sys.stderr)
		exit(1)

	og_stdout = sys.stdout
	sys.stdout = open(args.output_file, 'a+') if args.output_file else sys.stdout
	for host, value in urlmap.items():
		for path, params in value.items():
			if params:
				for param in params:
					print(host + path + dict_to_params(param))
			else:
				print(host + path)


