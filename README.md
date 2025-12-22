# Canary-Console-Chat
Connect your Canary Console to Claude via MCP - Natural Language API interaction


The following MCP allows Thinkst Canary Customers to use model interaction to 

```
1. Create Canaryttokens
2. Configure Canary Personalities
3. Manage Console Flock and Canarytoken and Canary properties
```


This is an experiment by me, I am not affilated with Thinkst, just a fan of the product and tech.

Ensure proper testing before deploying to a prodcution Canary Console.


## Getting Started 

### Step One: Ensure you have enabled the API use for your console 

https://docs.canary.tools/guide/getting-started.html


### Step Two: Using Claude Desktop - Configure the MCP Settings 

`C:\Users\USERNAME\AppData\Roaming\Claude\claude_desktop_config.json`

Add the following JSON

```
{
  "preferences": {
    "legacyQuickEntryEnabled": false,
    "menuBarEnabled": true
  },
  "mcpServers": {
    
    "canary-console": {
      "command": "python",
      "args": [
        "C:\\Users\\Tester\\canary_mcp_server.py"
      ],
      "env": {
        "CANARY_DOMAIN": "DOMANHASH.canary.tools",
        "CANARY_AUTH_TOKEN": "AUTHTOKEN"
      }
    }
  
}
}
```

### Step Three: Start the MCP Server 

```
python .\canary_mcp_server.py
[2025-12-22 08:01:14] ============================================================
[2025-12-22 08:01:14] Starting Canary Console MCP Server (FULL VERSION)
[2025-12-22 08:01:14] ============================================================
[2025-12-22 08:01:14] Environment check:
[2025-12-22 08:01:14]   CANARY_DOMAIN: DOMAINHASH
[2025-12-22 08:01:14]   CANARY_AUTH_TOKEN: SET (length: 44)
[2025-12-22 08:01:14] ============================================================
[2025-12-22 08:01:14] Available Tools:
[2025-12-22 08:01:14]   DEVICES:
[2025-12-22 08:01:14]     - list_devices() - List all Canary devices
[2025-12-22 08:01:14]     - get_device_info() - Get detailed device information
[2025-12-22 08:01:14]     - configure_device_personality() - Set device personality
[2025-12-22 08:01:14]     - update_device_description() - Update device description
[2025-12-22 08:01:14]     - configure_device_from_prompt() - Natural language configuration
[2025-12-22 08:01:14]     - reboot_device() - Reboot a device
[2025-12-22 08:01:14]   FLOCKS:
[2025-12-22 08:01:14]     - list_flocks() - List all flocks (device groups)
[2025-12-22 08:01:14]   TOKENS:
[2025-12-22 08:01:14]     - list_canarytokens() - List all Canarytokens
[2025-12-22 08:01:14]     - get_canarytokens_summary() - Get token summary by type
[2025-12-22 08:01:15]     - create_token_from_prompt() - Create token from natural language
[2025-12-22 08:01:15]     - create_word_token() - Create Word document token
[2025-12-22 08:01:15]     - create_excel_token() - Create Excel spreadsheet token
[2025-12-22 08:01:15]     - create_pdf_token() - Create PDF document token
[2025-12-22 08:01:15]     - create_dns_token() - Create DNS token
[2025-12-22 08:01:15]     - create_web_token() - Create Web URL token
[2025-12-22 08:01:15]     - download_token_file() - Download token file
[2025-12-22 08:01:15]     - set_token_enabled() - Enable/disable a token
[2025-12-22 08:01:15]     - delete_canarytoken() - Delete a token
[2025-12-22 08:01:15]     - list_token_types() - List supported token types
[2025-12-22 08:01:15]   FACTORY:
[2025-12-22 08:01:15]     - list_factory_token_types() - List factory token types
[2025-12-22 08:01:15]     - create_token_factory() - Create token factory
[2025-12-22 08:01:15]     - list_token_factories() - List all factories
[2025-12-22 08:01:15]     - delete_token_factory() - Delete a factory
[2025-12-22 08:01:15]     - create_tokens_from_factory() - Create tokens from factory
[2025-12-22 08:01:15]     - download_factory_tokens() - Download factory tokens as ZIP
[2025-12-22 08:01:15]   INCIDENTS:
[2025-12-22 08:01:15]     - list_incidents() - List all incidents/alerts
[2025-12-22 08:01:15]     - get_incident_details() - Get detailed incident information
[2025-12-22 08:01:15]     - acknowledge_incident() - Acknowledge an incident
[2025-12-22 08:01:15]     - unacknowledge_incident() - Unacknowledge an incident
[2025-12-22 08:01:15] ============================================================
[2025-12-22 08:01:15] Server ready for connections
[2025-12-22 08:01:15] ============================================================
```

## Step Four: Launch Claude Desktop and Interact with your Console 

Sample Prompt

```
List Canaries in my default flock 
List available Microsoft Personalities and services 
Then configure the Canary with the latest IIS Personality
```



Experiment and see where we can improve the MCP or the API or both.

This is not an approved MCP by Thinkst. But I love the product and love to experiment with it.

💚

https://canary.tools/

