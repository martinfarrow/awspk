# awspk
A handy pocket knife of AWS commands

Will add information on usage here in a short while, for now use --help


## Config file format
Example config file to allow ssh file to be written and connections to hosts to be made to query running processes etc.

### Section Keys

_jump: defines the jumphost if you need one to ssh through.

_global: defines things that act everywhere unless overwritten

### Environent keys

Other keys should be named after filter values (for instance dev for your dev environment and so forth).
This assumes that you have sensibly named EC2 instances, if you haven't fix this first.

IdentityFile: the path to the ssh identitify file

ec2user: The user with which to login

ProxyMatch: If the EC2 hostname matches this value AND it has a public IP, this host is used as a proxy to get to hosts in private subnets.




```
{
  "_jump" : {
    "IdentityFile": "~/.ssh/id_rsa2048",
    "jumpuser": "jumphostusername",
    "jumphost": "1.2.3.4"
  },
  "_global": {
    "ec2user": "centos"
  },
  "stage": {
    "IdentityFile": "~/.ssh/stage.pem",
    "ProxyMatch": "utilityserver",
    "ec2user": "ec2-user"
  },
  "prod": {
    "IdentityFile": "~/.ssh/production.pem",
    "ProxyMatch": "utilityserver",
    "ec2user": "ec2-user"
  }
}
```