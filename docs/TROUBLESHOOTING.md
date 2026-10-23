[← Back to README](../README.md)

# Troubleshooting

### Agent Not Connecting

1. Verify `ServerURL` in agent.go matches your server address
2. Check firewall allows traffic on the server port
3. Ensure server is running and accessible
4. Check agent console output for error messages

### YAML Not Found Errors

The agent handles sub-techniques (e.g., T1059.001) by searching multiple paths. If you see YAML errors:

1. Verify the atomics folder was correctly downloaded
2. Check the technique folder exists in `./atomics/`
3. Ensure the YAML file is present (e.g., `atomics/T1059/T1059.yaml`)

### Prerequisites Failing

1. Run agent as Administrator for full capability
2. Check PowerShell execution policy: `Set-ExecutionPolicy Bypass -Scope Process`
3. Verify PowerShell modules are downloaded to agent directory

### Detection Rules Not Loading

1. Verify `server/detection/` contains `attack_rule_map.json` and `elastic_rules.json`
2. Re-run `download-detection-rules.sh` from `server/detection/` to regenerate
3. Check server logs for JSON parsing errors
4. Validate JSON: `python3 -c "import json; json.load(open('server/detection/attack_rule_map.json'))"`
