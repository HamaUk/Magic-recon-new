Usage

1. Make the scripts executable:

```bash
chmod +x magicrecon.sh functions.sh install.sh
```

1. Install dependencies:

```bash
./install.sh
```

1. Configure your API tokens in configuration.cfg
2. Run MagicRecon:

```bash
# Full scan on a domain
./magicrecon.sh -d example.com -a

# Passive recon on a list of domains
./magicrecon.sh -l domains.txt -p

# Massive recon on a wildcard
./magicrecon.sh -w example.com -m
```

This enhanced version includes better error handling, more organized code structure, additional features, and proper documentation. The tool is now more robust and easier to maintain
