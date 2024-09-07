# Linux Basics

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents. You accept full responsibility for your actions by applying any knowledge gained here.‌
{% endhint %}

## Preseeding

You can pressed any installer question with boot parameters which are accessible through /proc/cmdline.

> You can directly use the full identifier of the debconf questions, such as `debian-installer/language=en`, `language=en`, or `hostname=kali`

### Preseed Config

File presence locations

* Media
  * `/cdrom/preseed.cfg`
  * `/hdmedia/preseed.cfg`
* Network
  * `preseed/url=http://server/preseed.cfg`

### Overcoming limitations

To overcome the limitation of not being able to preseed the language, country, and keyboard questions, you can add the boot parameter `auto-install/enable=true` (or `auto=true`)

### Creating a Preseed File

The simplest way to write a preseed file is to install a system by hand. Then the `debconf-get-selections --installer` command will provide the answers you provided. You can get answers directed to other packages with `debconf-get-selections`. The cleaner solution is to write the preseed file by hand, starting from an example and then going through the documentation. This way only questions where the default answer needs to be overwritten can be preseeded. Provide the `priority=critical` boot parameter to instruct Debconf to only ask critical questions, and to use default answers for others. Examples:

* `d-i mirror/suite string kali-rolling`

## Services

### Postgresql

This service listens on port **5432** and on file-based socket `/var/run/postgresql/.s.PGSQL.5432`, additional clusters get assigned next available port number (usually **5433** for the second cluster). Configuration files are found in `/etc/postgresql/version/cluster-name/`.\
The `postgres` user is special and has full administrative privileges over all databases.

#### Creating Users and Databases

**Each command acts on the default cluster, but you can pass `--port=port` to modify users/databases on an alternate cluster.** `createuser` - adds a new user `dropuser` - removes a user `createdb` - adds a new database `dropdb` - removes a database

Example 1: creating a new user and database, then assigning the new user as the owner of the new database.

```
# su - postgres
postgres@kali:~$ creatuser -P king_phisher
postgres@kali:~$ createdb -T template0 -E UTF-8 -O king_phisher king_phisher
postgres@kali:~$ exit
```

Example 2: Test connecting to the database over the socket as king\_phisher.

```
# psql -h localhost -U king_phisher king_phisher
king_phisher=>
```
