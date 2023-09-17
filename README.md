# usrwtchchange

Watch /etc/passwd for changes and report to admin

## Usage

usrwtchchange user@email smtp.hostname

## Unique features

### runtime secret key

The secret key is generated at runtime and is not stored on disk. This makes tampering with audit daemon harder, as the attacker would need to patch the binary in memory.
Usual attacker might kill audit program, change hashes and restart it. This is not possible with usrwtchchange, as admin will notice runtime secret key change.

## Simplicity

The program is very simple and has no dependencies. It is written in golang and can be compiled for any platform.
Code is kept simple and easy to audit.

## TODO

* Watch for user info change (uid, shell, etc), for now program watch only for username add/remove
* Watch for shadow changes (password update), will require root privileges
* Store file hashes for restart and send to admin as well?
