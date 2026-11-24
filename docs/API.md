# HTTP API

The web interface uses this API; scripts can too. Log in with `POST /api/login`
(`{"password": "..."}`) and send the `signalbox_session` cookie with every request.
Requests that change something must be JSON (`content-type: application/json`) and come
from the same origin. Errors are `{"error": "<code>", "message": "<text>"}`.

Generated from the code by `tools/gen_api_doc.py`; a test keeps it current.

| Method | Path | What it does |
| --- | --- | --- |
| GET | `/api/health` | Liveness: version, number of devices, time of the last observation round. |
| GET | `/api/session` | Whether this browser is logged in. |
| POST | `/api/login` | Log in with the password; sets the session cookie. |
| POST | `/api/logout` | End the session. |
| POST | `/api/password` | Change the web interface password (ends all sessions). |
| GET | `/api/adapters` | Installed adapters with their settings form (JSON Schema). |
| GET | `/api/rules` | All rules with explanation, severity and whether they are enabled. |
| GET | `/api/sites` | List sites. |
| POST | `/api/sites` | Add a site. |
| PUT | `/api/sites/{site_id}` | Rename a site. |
| DELETE | `/api/sites/{site_id}` | Delete a site without devices. |
| GET | `/api/devices` | List devices with their last status and when they were first seen and last read. |
| POST | `/api/devices` | Add a device; secrets in `config` are stored encrypted. |
| POST | `/api/devices/test` | Read a device with the form's settings before saving; nothing is stored. |
| GET | `/api/devices/{device_id}` | One device. |
| PUT | `/api/devices/{device_id}` | Change a device; secret settings left empty keep their value. |
| DELETE | `/api/devices/{device_id}` | Remove a device and its last snapshot. |
| POST | `/api/devices/{device_id}/test` | Read the device now and report status, errors and what was found. |
| POST | `/api/devices/{device_id}/trust` | Trust the certificate the device presented (pending fingerprint). |
| GET | `/api/devices/{device_id}/port-tree` | The internal structure of a device's ports (#252): CPU port with its switch ports, |
| GET | `/api/network` | The merged network model without passphrase data; derived uplink and service values. |
| GET | `/api/fdb` | MAC address table entries (#160): of one device (``?device=``, also the switches a |
| GET | `/api/wifi-scan` | Access points the radios heard (#169): of one device (``?device=``, also the |
| GET | `/api/findings` | Current findings; `?resolved=true` includes resolved ones. |
| GET | `/api/history` | Observation history: first/last seen and changes of devices, clients and ports. |
| POST | `/api/observe` | Read all devices now. |
| GET | `/api/topology` | Devices, ports, links with the VLANs at each end, and clients per port. |
| GET | `/api/links` | Manually entered links (cables). |
| POST | `/api/links` | Add a link between two ports. |
| DELETE | `/api/links/{link_id}` | Delete a link. |
| GET | `/api/desired` | The desired state as YAML (empty when nothing is declared) and whether it is valid. |
| PUT | `/api/desired` | Validate and save the desired state (a git commit when the folder is a repository). |
| POST | `/api/desired/import/{site_id}` | The observed state of a site as desired-state YAML, to start from what exists. |
| POST | `/api/plan` | Plan the changes from the observed to the desired state (nothing is changed). |
| GET | `/api/secrets` | Names of stored secrets (values are never returned). |
| PUT | `/api/secrets/{name}` | Store a secret (encrypted), e.g. a Wi-Fi passphrase named in the desired state. |
| DELETE | `/api/secrets/{name}` | Delete a secret. |
| GET | `/api/notifications` | State |
| PUT | `/api/notifications/channels/{name}` | Put |
| DELETE | `/api/notifications/channels/{name}` | Delete |
| POST | `/api/notifications/channels/{name}/test` | Test |
| GET | `/api/notifications/browser` | Messages for the browser channels newer than ``after`` (the page polls this). |
| GET | `/api/annotations` | Annotations and acknowledgements in effect, declared and stored (with `source`). |
| GET | `/api/annotations/export` | The annotations and acknowledgements set in the UI as desired-state YAML. |
| PUT | `/api/annotations/{target}` | Set the label, purpose, owner, notes, tags and expectations of an object. |
| DELETE | `/api/annotations/{target}` | Remove the annotation of an object set in the UI. |
| POST | `/api/findings/{finding_id}/acknowledge` | Acknowledge a current finding (or every finding of its rule about one object). |
| DELETE | `/api/acknowledgements/{ack_id}` | Remove an acknowledgement set in the UI: the finding counts as a problem again. |
| GET | `/api/changes` | The change log, newest first, and whether deploying is enabled. |
| POST | `/api/changes` | Plan the desired state and record it as a change waiting for approval. |
| GET | `/api/changes/{change_id}` | One change with its plan, per-device results and event log. |
| POST | `/api/changes/{change_id}/approve` | Approve a planned change (an override reason is needed when it creates errors). |
| POST | `/api/changes/{change_id}/reject` | Reject a change that was not deployed. |
| POST | `/api/changes/{change_id}/deploy` | Deploy an approved change in the background; poll the change for its progress. |
| POST | `/api/changes/{change_id}/revert` | Plan a new change that undoes an applied one. |
| GET | `/api/backups` | Configuration backups taken before changes (contents stay on the server). |
| POST | `/api/backups/{backup_id}/restore` | Plan putting a backup back on its device (approve and deploy like any change). |
| GET | `/api/discovery` | Progress of the last search and the devices it found (marked when already added). |
| POST | `/api/discovery` | Search for devices now (known networks and the given ranges), without credentials. |
| POST | `/api/discovery/ignore` | Hide a found device from the list (or show it again with `ignored: false`). |
| GET | `/api/traces` | The last run's progress, the sources that can trace (with the permission each |
| POST | `/api/traces` | Trace now: all gateways to each other and to the internet target, or only from or |
| DELETE | `/api/traces` | Forget every stored trace. |
| GET | `/api/probes` | The last probe's state per interface and every DHCP server and router seen |
| POST | `/api/probes` | Probe now: one DHCPDISCOVER and one router solicitation per interface of |
| DELETE | `/api/probes` | Forget every stored probe answer (the devices' sightings stay). |
| POST | `/api/devices/setup` | What the automatic setup would do with this admin login; nothing is changed. |
| POST | `/api/devices/setup/apply` | Run the automatic setup (or its removal) and save the device with the new login. |
| POST | `/api/devices/setup/jobs` | Start the setup in the background and return a job to poll (#316). |
| GET | `/api/devices/setup/jobs/{job_id}` | The state of a setup job: the steps so far, the one running, and the outcome. |
| POST | `/api/devices/{device_id}/fix` | What *Fix it* would do on this device with the admin login; nothing is changed. |
| POST | `/api/devices/{device_id}/fix/apply` | Run the remedy, then read the device again (`reading`, as Test connection answers). |
| GET | `/api/fixes` | Every fix available across the stored devices (#376), from their last reading. |
| POST | `/api/fixes/jobs` | Run several fixes one after the other and return a job to poll (#376). |
| GET | `/api/fixes/jobs/{run_id}` | The state of a run of several fixes: per device `pending`, `running`, `done` or |
