# tssh - Table SSH Exporter

A Python tool to extract hostname, IP, port and user data from various table formats (Markdown, CSV, delimited text) and export to TXT, CSV, or SSH config files with flexible template support.

*Why?*
I had the problem that I didn't always want to write my SSH config by hand. So I decided to write this tool, which helps you generate an SSH client config file from a Markdown, CSV, or TXT file. Now I just have to maintain my server list in git and I can create an SSH config from it. That saves me some work. However, you could just as easily export your database and transfer it to this script to create an SSH configuration.


## Features

- **Multi-format input:** Markdown tables, CSV files, delimited text (comma, semicolon, colon, tab)
- **Flexible column detection:** Case-insensitive pattern matching for hostname, IP, port, user columns
- **Smart SSH config generation:** Template-based with global and per-host settings
- **Auto-config discovery:** Searches standard locations for SSH templates
- **CLI parameter override:** Command-line values override table data
- **URL and file support:** Read from web URLs or local files

## Installation

```bash
chmod +x tssh.py
```

**Requirements:** Python 3.6+ (no external dependencies)

## Quick Start

```bash
# Export markdown table to CSV
python3 tssh.py -i servers.md --csv inventory.csv

# Generate SSH config from CSV
python3 tssh.py -i inventory.csv --ssh ~/.ssh/config.d/lab --user admin

# Export from URL to text
python3 tssh.py -i https://gitlab.example.com/infra/-/raw/main/servers.md --txt hosts.txt
```

## Input Formats

### Markdown Tables

```markdown
| Hostname       | IP        | Port | User    |
|----------------|-----------|------|---------|
| web1.lab.com   | 10.1.1.10 | 80   | webadmin|
| db1.lab.com    | 10.1.1.20 | 3306 | dbadmin |
```

### CSV Files
```csv
hostname,ip,port,user
web1.lab.com,10.1.1.10,80,webadmin
db1.lab.com,10.1.1.20,3306,dbadmin
```

### Delimited Text
```
web1.lab.com,10.1.1.10,80,webadmin
db1.lab.com;10.1.1.20;3306;dbadmin
```

## Command Line Options

### Input
- `-i, --input <source>` - Input source (URL, file path) **[required]**

### Export Options (choose exactly one)
- `--txt <file.txt>` - Export to space-delimited text format
- `--csv <file.csv>` - Export to CSV format  
- `--ssh <file.conf>` - Export to SSH config format

### SSH Configuration Options
- `--user <username>` - SSH username (overrides user column)
- `--port <port>` - SSH port (overrides port column)
- `--id <path>` - SSH identity file path (overrides template default)
- `--ssh-template <file.ini>` - Specific SSH config template file

## Column Detection

The tool automatically detects columns using flexible, case-insensitive pattern matching:

**Hostname/Server columns:**
`hostname`, `host`, `server`, `servername`, `machine`, `node`, `system`, `fqdn`, `device`, `computer`, etc.

**IP Address columns:**
`ip`, `address`, `ipv4`, `ipv6`, `endpoint`, `target`, `destination`, `network`, etc.

**Port columns:**
`port`, `portno`, `portnumber`, `tcp_port`, `ssh_port`, `service_port`, etc.

**User columns:**
`user`, `username`, `login`, `account`, `admin`, `ssh_user`, `benutzer`, etc.

Here is a simple example of a Markdown table. However, the tool includes automatic header pattern detection where hostname can also be called "servername" or "server", and "user" can also be called "account". The spelling (upper/lower case) does not matter. If your patterns are missing, you can simply add them to the code in the patterns. For example, if you want to use a different language, currently only common English-language patterns are recognized.

## SSH Configuration Templates

### Auto-Discovery

The tool searches for config files in this order:
1. `~/.conf/tssh.ssh`
2. `~/.tssh.conf`  
3. `~/tssh.conf`
4. `tssh.conf` (current directory)
5. `.tssh.conf` (current directory)

However, you can also simply pass your config file as a parameter.

**Multiple configs found?** → Error message with instructions to use `--ssh-template`

### Template Format (INI)

```ini
# Example tssh.conf
[global]
# Applied to "Host *" block (once at top of SSH config)
ControlMaster = auto
ControlPath = ~/.ssh/sockets/%r@%h-%p
ControlPersist = 600
ServerAliveInterval = 60
StrictHostKeyChecking = no
ConnectTimeout = 10

[host_defaults]  
# Applied to each individual host block
IdentityFile = ~/.ssh/id_rsa
IdentitiesOnly = yes
PasswordAuthentication = no
PubkeyAuthentication = yes
```

### Parameter Precedence

**Priority order (highest to lowest):**
1. **CLI parameters** (`--user`, `--port`, `--id`)
2. **Table data** (user/port columns)
3. **Template values** (`[host_defaults]` section)
4. **Built-in defaults**

## Output Formats

### TXT Format
```
web1.lab.com 10.1.1.10 80 webadmin
db1.lab.com 10.1.1.20 3306 dbadmin
```

### CSV Format
```csv
hostname,ip,port,user
web1.lab.com,10.1.1.10,80,webadmin
db1.lab.com,10.1.1.20,3306,dbadmin
```

### SSH Config Format
```
# Global SSH settings
Host *
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h-%p
    ServerAliveInterval 60

# Host-specific configurations
Host web1.lab.com web1
    Hostname 10.1.1.10
    User webadmin
    Port 80
    IdentityFile ~/.ssh/id_rsa
    IdentitiesOnly yes

Host db1.lab.com db1
    Hostname 10.1.1.20
    User dbadmin
    Port 3306
    IdentityFile ~/.ssh/id_rsa
    IdentitiesOnly yes
```

## Examples

### Basic Usage
```bash
# Markdown to CSV
python3 tssh.py -i infrastructure.md --csv servers.csv

# CSV to SSH config with custom user
python3 tssh.py -i servers.csv --ssh lab.conf --user lab-admin

# URL input to text output
python3 tssh.py -i https://docs.company.com/servers.md --txt hostlist.txt
```

### Advanced SSH Configuration
```bash
# Use custom template and override port
python3 tssh.py -i inventory.csv --ssh production.conf \
  --ssh-template prod_template.ini --port 2222

# Generate config with custom identity file
python3 tssh.py -i servers.md --ssh ~/.ssh/config.d/lab \
  --user admin --id ~/.ssh/lab_ed25519
```

### Working with Different Input Formats
```bash
# Auto-detect CSV format
python3 tssh.py -i "server1,10.1.1.1;server2,10.1.1.2" --csv output.csv

# Semicolon-separated data
python3 tssh.py -i data.txt --ssh config --user root

# Tab-separated from URL
python3 tssh.py -i https://example.com/data.tsv --txt hosts.txt
```

## Template Customization

### Creating Custom Templates

Create your own SSH template for different environments:

**Lab Template (`lab_template.ini`):**
```ini
[global]
StrictHostKeyChecking = no
UserKnownHostsFile = /dev/null
ConnectTimeout = 5

[host_defaults]
User = lab-user
Port = 2222
IdentityFile = ~/.ssh/lab_rsa
```

**Production Template (`prod_template.ini`):**
```ini
[global]
StrictHostKeyChecking = yes
ServerAliveInterval = 30
ConnectTimeout = 10

[host_defaults]
IdentityFile = ~/.ssh/prod_ed25519
PasswordAuthentication = no
```

**Usage:**
```bash
python3 tssh.py -i servers.csv --ssh lab.conf --ssh-template lab_template.ini
python3 tssh.py -i servers.csv --ssh prod.conf --ssh-template prod_template.ini
```

### Adding Custom Column Patterns

To recognize additional column names, edit the pattern lists in the source code:

```python
# In parse_tabular_data() and parse_markdown_tables() functions
hostname_patterns = [
    'hostname', 'host', 'server', 
    'your_custom_pattern',  # Add custom patterns here
    # ... existing patterns
]

user_patterns = [
    'user', 'username', 'login',
    'serviceaccount', 'svc_user',  # Example additions
    # ... existing patterns  
]
```

## Error Handling

**Multiple config files found:**
```
Error: Multiple config files found:
  /home/user/.tssh.conf
  /home/user/tssh.conf
Please specify which config to use with --ssh-template
```

**No data found:**
```
Warning: No hostname/IP data found
```

**Invalid input source:**
```
Error: File 'missing.txt' not found
Error reading URL 'https://invalid.url': HTTP Error 404
```

## Tips & Best Practices

### Security
- Use different templates for lab vs production environments
- Disable `StrictHostKeyChecking` only for lab/dev environments
- Use specific identity files per environment (`--id` parameter)

### Performance  
- Enable connection multiplexing in templates for faster connections
- Set appropriate `ConnectTimeout` values
- Use `ServerAliveInterval` to prevent connection drops

### Organization
- Store templates in version control
- Use descriptive template names (`lab_template.ini`, `prod_template.ini`)
- Place generated SSH configs in `~/.ssh/config.d/` directory structure

## Troubleshooting

**Column not detected?** Check if your column name matches the built-in patterns or add custom patterns.

**SSH config not working?** Verify template syntax and ensure the SSH client supports your configuration options.

**Multiple formats in one file?** The tool auto-detects format based on content and file extension. Use explicit file extensions when possible.

## Version History

- **v2.0** - Complete rewrite as `tssh.py` with template system and multi-format support
- **v1.0** - Initial `md_table_exporter.py` with basic markdown support
