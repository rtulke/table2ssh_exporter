#!/usr/bin/env python3
"""
Table SSH Exporter (tssh)
Exports hostname, IP, port and user data from various table formats to TXT, CSV or SSH config.
"""

import argparse
import configparser
import csv
import os
import re
import ssl
import sys
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import urlopen
from urllib.error import URLError


def find_config_files():
    """
    Search for config files in predefined locations.
    
    Returns:
        list: List of found config file paths
    """
    home = Path.home()
    current_dir = Path.cwd()
    
    search_paths = [
        home / '.conf' / 'tssh.ssh',
        home / '.tssh.conf',
        home / 'tssh.conf',
        current_dir / 'tssh.conf',
        current_dir / '.tssh.conf'
    ]
    
    found_configs = [path for path in search_paths if path.exists()]
    return found_configs


def remove_duplicate_ssh_keys(global_section, host_defaults):
    """
    Remove duplicate SSH keys between global and host sections.
    
    Args:
        global_section (str): Global SSH settings text
        host_defaults (str): Host defaults text
        
    Returns:
        tuple: (global_section, cleaned_host_defaults)
    """
    if not global_section or not host_defaults:
        return global_section, host_defaults
    
    # Extract keys from global section
    global_keys = set()
    for line in global_section.splitlines():
        line = line.strip()
        if line and ' ' in line:
            key = line.split(' ', 1)[0].lower()
            global_keys.add(key)
    
    # Filter host defaults to remove duplicates
    cleaned_host_defaults = ""
    removed_keys = []
    
    for line in host_defaults.splitlines():
        line_stripped = line.strip()
        if line_stripped and ' ' in line_stripped:
            key = line_stripped.split(' ', 1)[0].lower()
            if key in global_keys:
                removed_keys.append(key)
                continue  # Skip duplicate key
        
        cleaned_host_defaults += line + "\n"
    
    # Report removed duplicates
    if removed_keys:
        print(f"Removed duplicate keys from host defaults: {', '.join(removed_keys)}")
    
    return global_section, cleaned_host_defaults


def load_ssh_template(template_file=None):
    """
    Load SSH template configuration as text sections.
    
    Args:
        template_file (str): Optional specific template file path
        
    Returns:
        tuple: (global_section_text, host_defaults_text)
    """
    template_content = ""
    
    if template_file:
        # Use specified template file
        if not Path(template_file).exists():
            print(f"Error: Template file '{template_file}' not found", file=sys.stderr)
            sys.exit(1)
        template_content = Path(template_file).read_text(encoding='utf-8')
    else:
        # Auto-discover config files
        found_configs = find_config_files()
        
        if len(found_configs) > 1:
            print("Error: Multiple config files found:", file=sys.stderr)
            for config_path in found_configs:
                print(f"  {config_path}", file=sys.stderr)
            print("Please specify which config to use with --ssh-template", file=sys.stderr)
            sys.exit(1)
        elif len(found_configs) == 1:
            template_content = found_configs[0].read_text(encoding='utf-8')
            print(f"Using config: {found_configs[0]}")
        else:
            print("No config file found, using built-in defaults")
            return get_builtin_defaults_text()
    
    # Parse sections manually
    global_section = ""
    host_defaults = ""
    current_section = None
    
    for line in template_content.splitlines():
        line_stripped = line.strip()
        
        # Skip comments and empty lines
        if not line_stripped or line_stripped.startswith('#'):
            continue
            
        # Check for section headers
        if line_stripped == '[global]':
            current_section = 'global'
            continue
        elif line_stripped == '[host_defaults]':
            current_section = 'host_defaults'
            continue
        elif line_stripped.startswith('['):
            current_section = None
            continue
        
        # Parse key-value pairs
        if '=' in line_stripped and current_section:
            key, value = line_stripped.split('=', 1)
            key = key.strip()
            value = value.strip()
            
            if current_section == 'global':
                global_section += f"    {key} {value}\n"
            elif current_section == 'host_defaults':
                host_defaults += f"    {key} {value}\n"
    
    # Remove duplicate keys between global and host sections
    global_section, host_defaults = remove_duplicate_ssh_keys(global_section, host_defaults)
    
    return global_section, host_defaults


def get_builtin_defaults_text():
    """
    Get built-in default SSH configuration as text sections.
    
    Returns:
        tuple: (global_section_text, host_defaults_text)
    """
    global_section = """    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h-%p
    ControlPersist 600
    ServerAliveInterval 60
    ServerAliveCountMax 3
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    ConnectTimeout 10
    Compression yes
"""
    
    host_defaults = """    IdentitiesOnly yes
    PasswordAuthentication no
    PubkeyAuthentication yes
"""
    
    return global_section, host_defaults


def read_input_source(source, insecure=False):
    """
    Read content from URL or file path.
    
    Args:
        source (str): URL or file path
        insecure (bool): Allow insecure SSL connections
        
    Returns:
        str: Content of the source
        
    Raises:
        SystemExit: If source cannot be read
    """
    try:
        # Check if source is URL
        parsed = urlparse(source)
        if parsed.scheme in ('http', 'https'):
            if insecure and parsed.scheme == 'https':
                # Create unverified SSL context for self-signed certificates
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                with urlopen(source, context=ssl_context) as response:
                    return response.read().decode('utf-8')
            else:
                with urlopen(source) as response:
                    return response.read().decode('utf-8')
        else:
            # Treat as file path
            file_path = Path(source)
            if not file_path.exists():
                print(f"Error: File '{source}' not found", file=sys.stderr)
                sys.exit(1)
            return file_path.read_text(encoding='utf-8')
            
    except URLError as e:
        error_msg = str(e)
        if 'CERTIFICATE_VERIFY_FAILED' in error_msg:
            print(f"Error: SSL certificate verification failed for '{source}'", file=sys.stderr)
            print("  Try using --insecure flag to ignore SSL certificate errors", file=sys.stderr)
        elif 'nodename nor servname provided' in error_msg or 'Name or service not known' in error_msg:
            print(f"Error: Cannot resolve hostname in URL '{source}'", file=sys.stderr)
            print("  This might be an internal/private server not accessible from your network", file=sys.stderr)
        else:
            print(f"Error reading URL '{source}': {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading source '{source}': {e}", file=sys.stderr)
        sys.exit(1)


def get_column_patterns():
    """
    Get column detection patterns.
    
    Returns:
        dict: Dictionary with pattern lists for each column type
    """
    return {
        'hostname': [
            'hostname', 'host', 'hostName', 'host_name', 'host-name',
            'server', 'servername', 'server_name', 'server-name',
            'machine', 'machinename', 'machine_name', 'machine-name',
            'node', 'nodename', 'node_name', 'node-name',
            'system', 'systemname', 'system_name', 'system-name',
            'fqdn', 'name', 'device', 'device_name', 'device-name',
            'computer', 'computername', 'computer_name', 'computer-name'
        ],
        'ip': [
            'ip', 'ip-address', 'ipadress', 'ipaddress', 'ip_address',
            'address', 'addr', 'ipv4', 'ipv6', 'network', 'net',
            'endpoint', 'target', 'destination', 'dest'
        ],
        'port': [
            'port', 'portno', 'port_no', 'port-no', 'portnumber', 
            'port_number', 'port-number', 'tcp_port', 'udp_port',
            'service_port', 'svc_port', 'ssh_port'
        ],
        'user': [
            'user', 'benutzer', 'username', 'user_name', 'user-name',
            'login', 'loginname', 'login_name', 'login-name',
            'account', 'accountname', 'account_name', 'account-name',
            'uid', 'userid', 'user_id', 'user-id',
            'admin', 'administrator', 'ssh_user', 'sshuser', 'ssh-user'
        ]
    }


def detect_input_format(content, source):
    """
    Detect input format (markdown, csv, or delimited text).
    
    Args:
        content (str): File content
        source (str): Source file path/URL
        
    Returns:
        str: Format type ('markdown', 'csv', 'text')
    """
    # Check file extension
    source_lower = source.lower()
    if source_lower.endswith('.md') or source_lower.endswith('.markdown'):
        return 'markdown'
    elif source_lower.endswith('.csv'):
        return 'csv'
    elif source_lower.endswith('.txt'):
        return 'text'
    
    # Analyze content
    lines = content.strip().split('\n')[:5]  # Check first 5 lines
    
    # Check for markdown table patterns
    markdown_indicators = 0
    for line in lines:
        if '|' in line and ('---' in line or '--' in line):
            markdown_indicators += 2
        elif '|' in line:
            markdown_indicators += 1
    
    if markdown_indicators >= 2:
        return 'markdown'
    
    # Check for CSV patterns (commas in multiple lines)
    comma_lines = sum(1 for line in lines if ',' in line)
    if comma_lines >= 2:
        return 'csv'
    
    # Default to text
    return 'text'


def find_column_index(cells, patterns):
    """
    Find column index based on pattern matching (case insensitive).
    
    Args:
        cells (list): List of header cells
        patterns (list): List of patterns to match
        
    Returns:
        int: Column index or -1 if not found
    """
    for i, cell in enumerate(cells):
        cell_clean = cell.lower().strip()
        for pattern in patterns:
            if pattern.lower() in cell_clean:
                return i
    return -1


def parse_csv_data(content):
    """
    Parse CSV data and extract columns.
    
    Args:
        content (str): CSV content
        
    Returns:
        tuple: (data, has_port, has_user) where data is list of dicts
    """
    import io
    
    # Try different delimiters - same as text parsing
    delimiters = [',', ';', ':', '\t', ' ']
    best_delimiter = ','
    max_fields = 0
    
    for delimiter in delimiters:
        csv_reader = csv.reader(io.StringIO(content), delimiter=delimiter)
        try:
            first_row = next(csv_reader)
            if len(first_row) > max_fields:
                max_fields = len(first_row)
                best_delimiter = delimiter
        except StopIteration:
            continue
    
    # Parse with best delimiter
    csv_reader = csv.reader(io.StringIO(content), delimiter=best_delimiter)
    rows = list(csv_reader)
    
    if not rows:
        return [], False, False
    
    return parse_tabular_data(rows)


def parse_text_data(content):
    """
    Parse delimited text data (comma, semicolon, colon separated).
    
    Args:
        content (str): Text content
        
    Returns:
        tuple: (data, has_port, has_user) where data is list of dicts
    """
    lines = [line.strip() for line in content.split('\n') if line.strip()]
    
    if not lines:
        return [], False, False
    
    # Try different delimiters - same as CSV parsing
    delimiters = [',', ';', ':', '\t', ' ']
    best_delimiter = ','
    max_fields = 0
    
    for delimiter in delimiters:
        fields = lines[0].split(delimiter)
        if len(fields) > max_fields:
            max_fields = len(fields)
            best_delimiter = delimiter
    
    # Parse lines with best delimiter
    rows = []
    for line in lines:
        fields = [field.strip() for field in line.split(best_delimiter)]
        if fields:
            rows.append(fields)
    
    return parse_tabular_data(rows)


def parse_tabular_data(rows):
    """
    Parse tabular data (list of rows) and extract columns.
    
    Args:
        rows (list): List of rows (each row is list of cells)
        
    Returns:
        tuple: (data, has_port, has_user) where data is list of dicts
    """
    if not rows:
        return [], False, False
    
    # Get column patterns
    patterns = get_column_patterns()
    
    # Find column indices from header row
    header_row = rows[0]
    hostname_col = find_column_index(header_row, patterns['hostname'])
    ip_col = find_column_index(header_row, patterns['ip'])
    port_col = find_column_index(header_row, patterns['port'])
    user_col = find_column_index(header_row, patterns['user'])
    
    if hostname_col == -1 or ip_col == -1:
        return [], False, False
    
    # Parse data rows
    data = []
    for row in rows[1:]:  # Skip header
        if len(row) <= max([col for col in [hostname_col, ip_col, port_col, user_col] if col >= 0]):
            continue
            
        hostname = row[hostname_col].strip() if hostname_col >= 0 else ''
        ip = row[ip_col].strip() if ip_col >= 0 else ''
        port = row[port_col].strip() if port_col >= 0 and port_col < len(row) else ''
        user = row[user_col].strip() if user_col >= 0 and user_col < len(row) else ''
        
        if hostname and ip:
            entry = {
                'hostname': hostname,
                'ip': ip,
                'port': port,
                'user': user
            }
            data.append(entry)
    
    has_port = port_col >= 0
    has_user = user_col >= 0
    
    return data, has_port, has_user


def parse_markdown_tables(content):
    """
    Parse markdown tables and extract hostname, IP, port and user data.
    
    Args:
        content (str): Markdown content
        
    Returns:
        tuple: (data, has_port, has_user) where data is list of dicts
    """
    data = []
    
    # Get column patterns
    patterns = get_column_patterns()
    
    lines = content.split('\n')
    
    in_table = False
    header_found = False
    hostname_col = -1
    ip_col = -1
    port_col = -1
    user_col = -1
    
    for line in lines:
        line = line.strip()
        
        # Skip empty lines
        if not line:
            in_table = False
            header_found = False
            continue
            
        # Check if line contains table separators
        if '|' in line and ('---' in line or '--' in line):
            continue
            
        # Check if this is a table row
        if '|' in line:
            cells = [cell.strip() for cell in line.split('|')]
            cells = [cell for cell in cells if cell]  # Remove empty cells
            
            if not cells:
                continue
                
            # Check if this is a header row
            if not header_found and len(cells) >= 2:
                hostname_col = find_column_index(cells, patterns['hostname'])
                ip_col = find_column_index(cells, patterns['ip'])
                port_col = find_column_index(cells, patterns['port'])
                user_col = find_column_index(cells, patterns['user'])
                
                if hostname_col >= 0 and ip_col >= 0:
                    header_found = True
                    in_table = True
                continue
            
            # Extract data from table rows
            if in_table and header_found and len(cells) > max([col for col in [hostname_col, ip_col, port_col, user_col] if col >= 0]):
                hostname = cells[hostname_col].strip() if hostname_col >= 0 else ''
                ip = cells[ip_col].strip() if ip_col >= 0 else ''
                port = cells[port_col].strip() if port_col >= 0 and port_col < len(cells) else ''
                user = cells[user_col].strip() if user_col >= 0 and user_col < len(cells) else ''
                
                # Skip empty entries and entries with only whitespace/formatting
                if hostname and ip and hostname != '---' and ip != '---':
                    # Clean up any markdown formatting
                    hostname = re.sub(r'[`*_]', '', hostname).strip()
                    ip = re.sub(r'[`*_]', '', ip).strip()
                    port = re.sub(r'[`*_]', '', port).strip() if port else ''
                    user = re.sub(r'[`*_]', '', user).strip() if user else ''
                    
                    # Skip if still empty or contains table separators
                    if hostname and ip and '---' not in hostname and '---' not in ip:
                        entry = {
                            'hostname': hostname,
                            'ip': ip,
                            'port': port,
                            'user': user
                        }
                        data.append(entry)
        else:
            # Not a table line, reset table state
            in_table = False
            header_found = False
    
    has_port = port_col >= 0
    has_user = user_col >= 0
    
    return data, has_port, has_user


def parse_input_data(content, source):
    """
    Parse input data based on detected format.
    
    Args:
        content (str): Input content
        source (str): Source path/URL
        
    Returns:
        tuple: (data, has_port, has_user) where data is list of dicts
    """
    input_format = detect_input_format(content, source)
    print(f"Detected format: {input_format}")
    
    if input_format == 'markdown':
        return parse_markdown_tables(content)
    elif input_format == 'csv':
        return parse_csv_data(content)
    else:  # text
        return parse_text_data(content)


def export_to_txt(data, output_file, has_port, has_user):
    """
    Export data to plain text format.
    
    Args:
        data (list): List of dicts with hostname, ip, port, user
        output_file (str): Output file path
        has_port (bool): Whether port column exists
        has_user (bool): Whether user column exists
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for entry in data:
                line_parts = [entry['hostname'], entry['ip']]
                
                if has_port:
                    line_parts.append(entry['port'] or '')
                
                if has_user:
                    line_parts.append(entry['user'] or '')
                
                f.write(' '.join(line_parts) + '\n')
        
        print(f"Exported {len(data)} entries to {output_file}")
    except Exception as e:
        print(f"Error writing to {output_file}: {e}", file=sys.stderr)
        sys.exit(1)


def export_to_csv(data, output_file, has_port, has_user):
    """
    Export data to CSV format.
    
    Args:
        data (list): List of dicts with hostname, ip, port, user
        output_file (str): Output file path
        has_port (bool): Whether port column exists
        has_user (bool): Whether user column exists
    """
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            # Build header
            header = ['hostname', 'ip']
            if has_port:
                header.append('port')
            if has_user:
                header.append('user')
            
            writer = csv.writer(f)
            writer.writerow(header)
            
            for entry in data:
                row = [entry['hostname'], entry['ip']]
                
                if has_port:
                    row.append(entry['port'] or '')
                
                if has_user:
                    row.append(entry['user'] or '')
                
                writer.writerow(row)
        
        print(f"Exported {len(data)} entries to {output_file}")
    except Exception as e:
        print(f"Error writing to {output_file}: {e}", file=sys.stderr)
        sys.exit(1)


def normalize_ssh_key(key):
    """
    Normalize SSH configuration key to proper case format.
    
    Args:
        key (str): SSH config key
        
    Returns:
        str: Properly formatted SSH key
    """
    # Common SSH keys with proper capitalization
    ssh_key_mapping = {
        'controlmaster': 'ControlMaster',
        'controlpath': 'ControlPath', 
        'controlpersist': 'ControlPersist',
        'serveraliveinterval': 'ServerAliveInterval',
        'serveralivecountmax': 'ServerAliveCountMax',
        'stricthostkeychecking': 'StrictHostKeyChecking',
        'userknownhostsfile': 'UserKnownHostsFile',
        'connecttimeout': 'ConnectTimeout',
        'compression': 'Compression',
        'identityfile': 'IdentityFile',
        'identitiesonly': 'IdentitiesOnly',
        'passwordauthentication': 'PasswordAuthentication',
        'pubkeyauthentication': 'PubkeyAuthentication',
        'hostname': 'Hostname',
        'user': 'User',
        'port': 'Port',
        'loglevel': 'LogLevel',
        'forwardagent': 'ForwardAgent',
        'forwardx11': 'ForwardX11'
    }
    
    return ssh_key_mapping.get(key.lower(), key)


def export_to_ssh_config(data, output_file, cli_user, cli_port, cli_identity, ssh_template):
    """
    Export data to SSH config format.
    
    Args:
        data (list): List of dicts with hostname, ip, port, user
        output_file (str): Output file path
        cli_user (str): CLI user parameter
        cli_port (str): CLI port parameter  
        cli_identity (str): CLI identity file parameter
        ssh_template (str): SSH template file path
    """
    try:
        # Load SSH template as text sections
        global_section, host_defaults = load_ssh_template(ssh_template)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            # Write global settings
            if global_section and global_section.strip():
                f.write("# Global SSH settings\n")
                f.write("Host *\n")
                f.write(global_section)
                f.write("\n")
            
            # Write host configurations
            f.write("# Host-specific configurations\n")
            for entry in data:
                hostname = entry['hostname']
                ip = entry['ip']
                
                # Extract short hostname (part before first dot)
                short_hostname = hostname.split('.')[0]
                
                f.write(f"Host {hostname} {short_hostname}\n")
                f.write(f"    Hostname {ip}\n")
                
                # CLI parameters override everything
                if cli_user:
                    f.write(f"    User {cli_user}\n")
                elif entry.get('user'):
                    f.write(f"    User {entry['user']}\n")
                
                if cli_port:
                    f.write(f"    Port {cli_port}\n")
                elif entry.get('port'):
                    f.write(f"    Port {entry['port']}\n")
                
                # Identity file: CLI > template default
                identity_file = cli_identity or '~/.ssh/id_rsa'
                f.write(f"    IdentityFile {identity_file}\n")
                
                # Add host defaults from template (preserve original formatting)
                if host_defaults and host_defaults.strip():
                    f.write(host_defaults)
                
                f.write("\n")
        
        print(f"Exported {len(data)} entries to {output_file}")
    except Exception as e:
        print(f"Error writing to {output_file}: {e}", file=sys.stderr)
        sys.exit(1)


def validate_args(args):
    """
    Validate command line arguments.
    
    Args:
        args: Parsed arguments object
    """
    export_count = sum([
        bool(args.txt),
        bool(args.csv), 
        bool(args.ssh)
    ])
    
    if export_count != 1:
        print("Error: Exactly one export option (--txt, --csv, --ssh) must be specified", 
              file=sys.stderr)
        sys.exit(1)


def main():
    """Main function to handle command line interface."""
    parser = argparse.ArgumentParser(
        description='Table SSH Exporter (tssh) - Extract hostname, IP, port and user data from tables',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -i servers.md --csv inventory.csv
  %(prog)s -i inventory.csv --ssh lab.conf --user admin
  %(prog)s -i "host1,10.1.1.1;host2,10.1.1.2" --txt hosts.txt
  %(prog)s -i https://internal.company.com/servers.md --csv hosts.csv --insecure
        """
    )
    
    parser.add_argument(
        '-i', '--input',
        required=True,
        help='Input source (URL, file path, or inline data)'
    )
    
    # Export options
    parser.add_argument(
        '--txt',
        metavar='OUTPUT.txt',
        help='Export to plain text format'
    )
    
    parser.add_argument(
        '--csv', 
        metavar='OUTPUT.csv',
        help='Export to CSV format'
    )
    
    parser.add_argument(
        '--ssh',
        metavar='OUTPUT.ssh',
        help='Export to SSH config format'
    )
    
    # SSH specific options
    parser.add_argument(
        '--user',
        help='SSH username (overrides user column)'
    )
    
    parser.add_argument(
        '--port',
        help='SSH port (overrides port column)'
    )
    
    parser.add_argument(
        '--id',
        help='SSH identity file path (overrides template default)'
    )
    
    parser.add_argument(
        '--ssh-template',
        help='SSH config template file (INI format)'
    )
    
    parser.add_argument(
        '--insecure',
        action='store_true',
        help='Allow insecure SSL connections (ignore certificate errors)'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    validate_args(args)
    
    # Read input source
    print(f"Reading from: {args.input}")
    if args.insecure:
        print("Warning: SSL certificate verification disabled")
    content = read_input_source(args.input, args.insecure)
    
    # Parse input data
    data, has_port, has_user = parse_input_data(content, args.input)
    
    if not data:
        print("Warning: No hostname/IP data found", file=sys.stderr)
        sys.exit(1)
    
    print(f"Found {len(data)} entries")
    if has_port:
        print("Port column detected")
    if has_user:
        print("User column detected")
    
    # Export based on selected format
    if args.txt:
        export_to_txt(data, args.txt, has_port, has_user)
    elif args.csv:
        export_to_csv(data, args.csv, has_port, has_user)
    elif args.ssh:
        export_to_ssh_config(data, args.ssh, args.user, args.port, args.id, args.ssh_template)


if __name__ == '__main__':
    main()
