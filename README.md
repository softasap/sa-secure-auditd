sa-secure-auditd
================
[![Build Status](https://travis-ci.org/softasap/sa-secure-auditd.svg?branch=master)](https://travis-ci.org/softasap/sa-secure-auditd)


Example of use: check box-example

Simple:

```YAML
custom_auditd_props:
  - "-D"  # clean rules
  - "-b 320"  # no of bufs for messages
  - "-f 1" # on failure 0 nothing, 1 dmesg, 2 kernel panic
  - "-a exit,always -S unlink -S rmdir"  # notify unlink rmdir
  - "-w /etc/group -p wa" # group modification
  - "-w /etc/passwd -p wa" # passwords modification
  - "-w /etc/shadow -p wa"
  - "-w /etc/sudoers -p wa"  
  - "-e 2" # prevent further changes to config

```

```YAML


     - {
         role: "sa-secure-auditd"
       }

```


Advanced:

```YAML


     - {
         role: "sa-secure-auditd",
         auditd_conf_default_props: "{{custom_auditd_props}}"
       }


```

Copyright and license
---------------------

Code licensed under the [BSD 3 clause] (https://opensource.org/licenses/BSD-3-Clause) or the [MIT License] (http://opensource.org/licenses/MIT).

Subscribe for roles updates at [FB] (https://www.facebook.com/SoftAsap/)
