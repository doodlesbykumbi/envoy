# Envoy + Secretless

Follow the steps below to go through a working example of Envoy brokering the authentication of a MySQL connection.
The credential injection is carried out via the Secretless C shared library.

**Requires** Docker and Envoy build dependencies

Build Envoy:
```
pushd ..
    bazel build //source/exe:envoy --verbose_failures
popd
```

Start envoy:
+ Set file secret provider and provide configure to speak to mysql:3306 on 9903
+ Specify dynamic linking path for secretlesslib
```
LD_LIBRARY_PATH=$PWD/../source/extensions/filters/network/mysql_proxy
  DYLD_LIBRARY_PATH=$LD_LIBRARY_PATH \
  SECRET_PROVIDER=file \
  ../bazel-bin/source/exe/envoy-static --config-yaml "$(cat config-mysql.yml)"
```

Start MySQL and expose it to your host on 3306:
```bash
docker run --name mysql-test --rm -e MYSQL_ROOT_PASSWORD=securerootpass -p 3306:3306 -d mysql/mysql-server:5.7
```

Wait for MySQL:
```bash
docker exec -it mysql-test  bash -c "
echo 'Waiting for MySQL to start'
while ! mysqladmin -psecurerootpass status > /dev/null 2>&1;
do
  >&2 printf '. '
  sleep 1
done

echo ''
>&2 echo 'MySQL is up - continuing'
"
```

Create a user that can login using password from any host
```bash
docker exec -it mysql-test mysql -uroot -psecurerootpass -e "
CREATE USER 'kumbi'@'%' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON * . * TO 'kumbi'@'%';
"
```

Access MySQL via Envoy(+ Secretless). Notice that the client is configure with gibberish credentials. Envoy will inject the correct credentials.
```bash
docker exec -it mysql-test mysql -h host.docker.internal -P 9903 --ssl=FALSE -u xxxx -pxxxx -e "status"
```
Output:
```
WARNING: --ssl is deprecated and will be removed in a future version. Use --ssl-mode instead.
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
mysql  Ver 14.14 Distrib 5.7.24, for Linux (x86_64) using  EditLine wrapper

Connection id:          4
Current database:       
Current user:           kumbi@172.17.0.1
SSL:                    Not in use
Current pager:          stdout
Using outfile:          ''
Using delimiter:        ;
Server version:         5.7.24 MySQL Community Server (GPL)
Protocol version:       10
Connection:             host.docker.internal via TCP/IP
Server characterset:    latin1
Db     characterset:    latin1
Client characterset:    latin1
Conn.  characterset:    latin1
TCP port:               9903
Uptime:                 17 sec

Threads: 1  Questions: 11  Slow queries: 0  Opens: 111  Flush tables: 1  Open tables: 104  Queries per second avg: 0.647
--------------
```

Notice the line `Current user: kumbi`!

Inspect the Envoy logs and observe that Secretless logs are in the mix:
```
# [2019-02-12 01:51:03.516][1295323][info][filter] [source/extensions/filters/network/mysql_proxy/mysql_filter.cc:38] requestingAuth
# 2019/02/12 01:51:03 Instantiating provider 'file'
# 2019/02/12 01:51:03 Instantiating provider 'file'
#
```

In this demo the Secretless configuration is hardcoded in the Envoy binary.
It uses the file provider and read the contents from a file of same name as the secret in the folder where Envoy was run.
The 2 secrets used are named `db-username` and `db-password`.
Modify either of them and notice that you're get failed access:
```
printf "wrong-password" > db-password
docker exec -it mysql-test mysql -h host.docker.internal -P 9903 --ssl=FALSE -u kxmbi -ppxssword -e "status"
```
