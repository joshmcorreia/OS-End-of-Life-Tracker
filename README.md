# OS End of Life Tracker
A simple tool for tracking the end of life of your operating systems.

Special thanks to https://endoflife.date for providing an excellent API. All data in the `raw_data` folder is provided by them.

---

# Prerequisites:
Currently this tool requires that you have a [Wazuh](https://wazuh.com/) server set up with a Wazuh agent on each machine that you wish to monitor.

---

# Currently supported Operating Systems:
This is a list of Operating Systems that I have confirmed work with this tool. Other OS may work, but they have not been confirmed yet. If you find an OS that works but hasn't been added to this list please make a pull request or open an issue so I can add it!
- xxx
- xxx

---

# How to use it

## Get your agent data
1. Open a browser and go to `https://{YOUR_WAZUH_IP}/app/wazuh#/wazuh-dev?tab=devTools`.
2. In the console type
   ```
   GET /agents/
   ```
3. Press the green arrow to send your request
4. Copy/paste the output into `agent_data.json` within this repository.
