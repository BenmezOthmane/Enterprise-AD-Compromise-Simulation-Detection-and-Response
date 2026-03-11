#!/bin/bash
# Deploy-wazuh-rules.sh
# Deploys custom Wazuh detection rules for AD attack scenarios

CONTAINER="single-node_wazuh.manager_1"
RULES_FILE="/var/ossec/etc/rules/local_rules.xml"

echo "[*] Deploying Wazuh custom rules..."

docker exec -i $CONTAINER bash -c "cat > $RULES_FILE" << 'EOF'
<group name="local,">

  <!-- LLMNR Poisoning — T1557.001 -->
  <rule id="100001" level="10">
    <if_group>windows</if_group>
    <field name="win.system.eventID">4648</field>
    <description>Explicit credential use — possible LLMNR poisoning (T1557.001)</description>
    <mitre><id>T1557.001</id></mitre>
  </rule>

  <!-- Kerberoasting — T1558.003 -->
  <rule id="100010" level="14">
    <if_group>windows</if_group>
    <field name="win.system.eventID">4769</field>
    <field name="win.eventdata.ticketEncryptionType">0x17</field>
    <description>Kerberos TGS RC4 — possible Kerberoasting (T1558.003)</description>
    <mitre><id>T1558.003</id></mitre>
  </rule>

  <!-- Pass-the-Hash — T1550.002 -->
  <rule id="100020" level="14">
    <if_group>windows</if_group>
    <field name="win.system.eventID">4624</field>
    <field name="win.eventdata.logonType">3</field>
    <field name="win.eventdata.authenticationPackageName">NTLM</field>
    <description>NTLM Network Logon — possible Pass-the-Hash (T1550.002)</description>
    <mitre><id>T1550.002</id></mitre>
  </rule>

  <!-- Pass-the-Hash CRITICAL -->
  <rule id="100021" level="15" frequency="3" timeframe="60">
    <if_matched_sid>100020</if_matched_sid>
    <description>CRITICAL: Repeated NTLM — Pass-the-Hash confirmed (T1550.002)</description>
    <mitre><id>T1550.002</id></mitre>
  </rule>

  <!-- Privilege Escalation — T1078.002 -->
  <rule id="100030" level="14">
    <if_group>windows</if_group>
    <field name="win.system.eventID">4728</field>
    <description>User added to privileged group (T1078.002)</description>
    <mitre><id>T1078.002</id></mitre>
  </rule>

  <!-- DCSync — T1003.006 -->
  <rule id="100031" level="15">
    <if_group>windows</if_group>
    <field name="win.system.eventID">4662</field>
    <field name="win.eventdata.properties">1131f6aa-9c07-11d1-f79f-00c04fc2dcd2</field>
    <description>DCSync replication detected — Domain compromise (T1003.006)</description>
    <mitre><id>T1003.006</id></mitre>
  </rule>

</group>
EOF

echo "[*] Restarting Wazuh..."
docker exec $CONTAINER /var/ossec/bin/wazuh-control restart

echo "[+] Rules deployed successfully!"