# build envoy
bazel build //source/exe:envoy --verbose_failures

# symlink shared library in anticipation for dynamic linking
ln -s $PWD/source/extensions/filters/network/mysql_proxy/secretless.a secretless.a

# start envoy. set file secret provider and provide configure to speak to mysql:3306 on 9903
SECRET_PROVIDER=file ../bazel-bin/source/exe/envoy-static --config-yaml "$(cat config-mysql.yml)"

# start mysql
docker run --name mysql-test --rm -e MYSQL_ROOT_PASSWORD=securerootpass -p 3306:3306 -d mysql/mysql-server:5.7

# create a user that can login using password from any host
docker exec -it mysql-test mysql -uroot -psecurerootpass -e "CREATE USER 'kumbi'@'%' IDENTIFIED BY 'password'; GRANT ALL PRIVILEGES ON * . * TO 'kumbi'@'%';"

# access mysql via envoy using secret provider (notice client is given gibberish credentials)
docker exec -it mysql-test mysql -h host.docker.internal -P 9903 --ssl=FALSE -u kxmbi -ppxssword -e "status"

# modify db-username or db-password
printf "wrong-password" > db-password

# failed access
docker exec -it mysql-test mysql -h host.docker.internal -P 9903 --ssl=FALSE -u kxmbi -ppxssword -e "status"
