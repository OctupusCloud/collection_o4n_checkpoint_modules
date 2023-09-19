# Octupus Collection

Collection o4n_checkpoint_modules includes imperative Ansible modules for Checkpoint devices.  
By Randy Rozo

## Required

- Ansible >= 2.10  
- Python Library: 
  - requests
  - urllib3
  - json

## Python Version Notice  

Collection only supports python 3.6 and above  

## Modules

- o4n_cp_https_rule_debugging_disabled
  Its main function is the ability to remove (or "prune") https rules that have been disabled on Checkpoint  
- o4n_cp_nat_rule_debugging_disabled
  Its main function is the ability to remove (or "prune") nat rules that have been disabled on Checkpoint  
- o4n_cp_rule_debugging_disabled
  Its main function is the ability to remove (or "prune") access rules that have been disabled on Checkpoint  
- o4n_cp_rule_debugging_expired
  Its main function is the ability to remove (or "prune") access rules that have been expired on Checkpoint  
- o4n_cp_rule_debugging_for_name
  Its main function is the ability to remove (or "prune") access rules for name on Checkpoint  
- o4n_cp_threat_rule_debugging_disabled
  Its main function is the ability to remove (or "prune") threat rules that have been disabled on Checkpoint  
- o4n_cp_add_access_rules
  Manages access rule objects in Check Point devices, including creation and updating if the rule to be created matches another, it will add missing sources or destinations  
- o4n_cp_add_https_rules
  Manages https rule objects in Check Point devices, including creation and updating if the rule to be created matches another, it will add missing sources or destinations  
- o4n_cp_add_nat_rules
  Add NAT rules of the selected layer.  
- o4n_cp_add_threat_rules
  Manages https rule objects in Check Point devices, including creation and updating if the rule to be created matches another, it will add missing sources, protected scope or destinations  
- o4n_cp_delete_access_rules
  Delete access rules of the selected layer.  
- o4n_cp_delete_https_rules
  Delete https rules of the selected layer.  
- o4n_cp_delete_nat_rules
  Delete nat rules of the selected layer.  
- o4n_cp_delete_threat_rules
  Delete threat rules of the selected layer.  
- o4n_cp_set_access_rules
  Set access rules of the selected layer.  
- o4n_cp_set_https_rules
  Set https rules of the selected layer.  
- o4n_cp_set_nat_rules
  Set nat rules of the selected layer.  
- o4n_cp_set_threat_rules
  Set threat rules of the selected layer.  
- o4n_cp_verify_policy
  Verifies the policy of the selected package.  
